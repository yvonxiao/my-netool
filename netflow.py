#!/usr/bin/env python3
"""
NetFlow - Linux Network Process Traffic Monitor
Real-time network traffic monitoring with process information.
Combines iftop-style flow view with nethogs-style process view.

Unlike nethogs, this tool properly tracks UDP traffic.
"""

import curses
import time
import os
import sys
import signal
import argparse
import subprocess
import socket
import struct
from collections import defaultdict
from datetime import datetime

PROC_NET_PATH = "/proc/net"
REFRESH_INTERVAL = 1.0


class ProcessTracker:
    """Track process information for network connections."""

    def __init__(self):
        self.inode_map = {}  # inode -> {pid, name, uid, exe}
        self.pid_info = {}
        self.refresh()

    def refresh(self):
        """Rebuild the inode to process mapping."""
        self.inode_map.clear()
        self.pid_info.clear()

        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue

                pid_path = f"/proc/{pid}"
                fd_path = f"{pid_path}/fd"

                try:
                    with open(f"{pid_path}/comm", 'r') as f:
                        comm = f.read().strip()

                    uid = 0
                    try:
                        with open(f"{pid_path}/status", 'r') as f:
                            for line in f:
                                if line.startswith("Uid:"):
                                    uid = int(line.split()[1])
                                    break
                    except:
                        pass

                    exe = ""
                    try:
                        exe = os.readlink(f"{pid_path}/exe")
                    except:
                        pass

                    self.pid_info[int(pid)] = {"name": comm, "uid": uid, "exe": exe}

                    for fd in os.listdir(fd_path):
                        try:
                            target = os.readlink(f"{fd_path}/{fd}")
                            if target.startswith("socket:["):
                                inode = int(target[8:-1])
                                self.inode_map[inode] = {
                                    "pid": int(pid),
                                    "name": comm,
                                    "uid": uid,
                                    "exe": exe
                                }
                        except (OSError, PermissionError, ValueError, FileNotFoundError):
                            continue
                except (OSError, PermissionError, ProcessLookupError, FileNotFoundError):
                    continue
        except OSError:
            pass

    def get_user(self, uid):
        """Get username from UID."""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except (ImportError, KeyError):
            return str(uid)

    def lookup(self, inode):
        """Look up process info for an inode."""
        return self.inode_map.get(inode, {"pid": 0, "name": "unknown", "uid": 0, "exe": ""})


class ProcNetParser:
    """Parse /proc/net/tcp, tcp6, udp, udp6 files with inode mapping."""

    TCP_STATES = {
        '01': 'ESTABLISHED',
        '02': 'SYN_SENT',
        '03': 'SYN_RECV',
        '04': 'FIN_WAIT1',
        '05': 'FIN_WAIT2',
        '06': 'TIME_WAIT',
        '07': 'CLOSE',
        '08': 'CLOSE_WAIT',
        '09': 'LAST_ACK',
        '0A': 'LISTEN',
        '0B': 'CLOSING'
    }

    def __init__(self):
        self.connections = {}  # (laddr, lport, raddr, rport, proto) -> {inode, state}
        self.inode_index = {}  # inode -> (laddr, lport, raddr, rport, proto)

    def hex_to_ip(self, hex_ip):
        """Convert hex IP to string (handles little-endian format)."""
        if len(hex_ip) == 8:  # IPv4
            # Convert little-endian hex to dotted notation
            ip_int = int(hex_ip, 16)
            return '.'.join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))
        elif len(hex_ip) == 32:  # IPv6
            parts = [hex_ip[i:i+4] for i in range(0, 32, 4)]
            # Reverse each group for little-endian
            return ':'.join(p for p in parts)
        return hex_ip

    def ip_to_hex(self, ip_str):
        """Convert IP string to hex format for /proc/net matching."""
        if ':' not in ip_str:  # IPv4
            parts = [int(x) for x in ip_str.split('.')]
            # Convert to little-endian hex
            ip_int = sum(p << (8 * i) for i, p in enumerate(parts))
            return f"{ip_int:08X}"
        else:  # IPv6
            # Handle IPv6
            return ip_str

    def parse_file(self, filepath, proto):
        """Parse a /proc/net/{tcp,tcp6,udp,udp6} file."""
        connections = {}

        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue

                try:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3] if proto in ('tcp', 'tcp6') else '00'
                    inode = int(parts[9])

                    local_ip, local_port = local_addr.split(':')
                    remote_ip, remote_port = remote_addr.split(':')

                    local_ip = self.hex_to_ip(local_ip)
                    local_port = int(local_port, 16)
                    remote_ip = self.hex_to_ip(remote_ip)
                    remote_port = int(remote_port, 16)

                    key = (local_ip, local_port, remote_ip, remote_port, proto.upper())

                    connections[key] = {
                        "inode": inode,
                        "state": self.TCP_STATES.get(state, state),
                        "proto": proto.upper()
                    }
                except (ValueError, IndexError):
                    continue

        except IOError:
            pass

        return connections

    def refresh(self):
        """Refresh all connection data."""
        self.connections.clear()
        self.inode_index.clear()

        for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
            filepath = f"/proc/net/{proto}"
            if os.path.exists(filepath):
                conns = self.parse_file(filepath, proto)
                self.connections.update(conns)

                for key, info in conns.items():
                    self.inode_index[info["inode"]] = key

    def find_by_addr(self, local_ip, local_port, remote_ip, remote_port):
        """Find connection by address tuple."""
        # Normalize IP format for matching
        local_ip_norm = local_ip.strip()
        remote_ip_norm = remote_ip.strip()

        # Convert ports to int
        try:
            local_port = int(local_port)
            remote_port = int(remote_port)
        except (ValueError, TypeError):
            return None

        for key, info in self.connections.items():
            k_local_ip, k_local_port, k_remote_ip, k_remote_port, proto = key

            # Compare addresses (strip any interface markers like %eth0)
            if (k_local_ip.split('%')[0] == local_ip_norm.split('%')[0] and
                k_local_port == local_port and
                k_remote_ip.split('%')[0] == remote_ip_norm.split('%')[0] and
                k_remote_port == remote_port):
                return info

        return None

    def get_inode(self, local_ip, local_port, remote_ip, remote_port):
        """Get inode for a connection."""
        info = self.find_by_addr(local_ip, local_port, remote_ip, remote_port)
        return info["inode"] if info else 0


class PacketCounter:
    """Packet counter using multiple data sources."""

    def __init__(self):
        self.prev_iface = {}
        self.prev_tcp = {}
        self.prev_udp = {}

    def get_interface_stats(self):
        """Get per-interface statistics."""
        stats = {}
        net_path = "/sys/class/net"
        if os.path.exists(net_path):
            for iface in os.listdir(net_path):
                rx_bytes = tx_bytes = 0
                rx_pkts = tx_pkts = 0
                try:
                    base = f"{net_path}/{iface}/statistics"
                    with open(f"{base}/rx_bytes", 'r') as f:
                        rx_bytes = int(f.read().strip())
                    with open(f"{base}/tx_bytes", 'r') as f:
                        tx_bytes = int(f.read().strip())
                    with open(f"{base}/rx_packets", 'r') as f:
                        rx_pkts = int(f.read().strip())
                    with open(f"{base}/tx_packets", 'r') as f:
                        tx_pkts = int(f.read().strip())
                except (IOError, ValueError):
                    pass
                stats[iface] = {
                    "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
                    "rx_pkts": rx_pkts, "tx_pkts": tx_pkts
                }
        return stats

    def get_snmp_stats(self):
        """Get SNMP statistics."""
        tcp_stats = {}
        udp_stats = {}

        try:
            with open("/proc/net/snmp", 'r') as f:
                lines = f.readlines()
                if len(lines) >= 2:
                    headers = lines[0].split()
                    values = lines[1].split()
                    for i, h in enumerate(headers):
                        if i < len(values):
                            try:
                                tcp_stats[h.strip()] = int(values[i])
                            except ValueError:
                                pass
        except IOError:
            pass

        try:
            with open("/proc/net/snmp6", 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            udp_stats[parts[0].strip(':')] = int(parts[1])
                        except ValueError:
                            pass
        except IOError:
            pass

        return tcp_stats, udp_stats

    def get_connections_ss(self, proto='all'):
        """Get connections using ss command with process info."""
        connections = []
        proto_filter = "-t" if proto == 'tcp' else "-u" if proto == 'udp' else ""

        # Get process info from ss -p (requires checking different outputs)
        proc_map = self._get_ss_process_map()

        try:
            cmd = ["ss", "-tn", proto_filter, "-p"] if proto_filter else ["ss", "-tnp"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue

                    try:
                        # ss output format varies, try multiple patterns
                        # Format 1: State Recv-Q Send-Q Local:Port Peer:Port Process
                        # Format 2: State Local:Port Peer:Port Process (no queues)

                        state = parts[0]  # Always first

                        # Find local and peer addresses - they contain ':'
                        addr_parts = [p for p in parts if ':' in p]
                        if len(addr_parts) >= 2:
                            local = addr_parts[0]
                            peer = addr_parts[1]
                        else:
                            local = parts[3] if len(parts) > 3 else ""
                            peer = parts[4] if len(parts) > 4 else ""

                        local_ip, local_port = self.parse_addr(local)
                        peer_ip, peer_port = self.parse_addr(peer)

                        protocol = "TCP" if proto_filter == "-t" or (not proto_filter and state not in ("", "0")) else "UDP"

                        # Extract process info from the connection line
                        pid, name = self._extract_process_from_line(line, proc_map)

                        connections.append({
                            "proto": protocol,
                            "local_ip": local_ip, "local_port": local_port,
                            "remote_ip": peer_ip, "remote_port": peer_port,
                            "state": state,
                            "pid": pid,
                            "name": name,
                            "raw": line
                        })
                    except (ValueError, IndexError):
                        continue
        except:
            pass

        return connections

    def _get_ss_process_map(self):
        """Get process map from ss -p output with full info."""
        proc_map = {}
        try:
            result = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                import re
                # Extract: users:((\"name\",pid=123,fd=4))
                # or: users:((\"name\",pid=123,fd=4)),ino:12345
                for line in result.stdout.strip().split("\n")[1:]:
                    # Try to find process name and pid
                    match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                    if match:
                        name = match.group(1)
                        pid = match.group(2)
                        proc_map[pid] = name
        except:
            pass
        return proc_map

    def _extract_process_from_line(self, line, proc_map):
        """Extract PID and process name from ss line."""
        import re
        pid = 0
        name = "unknown"

        # Try to extract from line: users:(("name",pid=123,fd=4))
        match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if match:
            name = match.group(1)
            pid = int(match.group(2))

        return pid, name

    def parse_addr(self, addr):
        """Parse address:port from ss output."""
        if not addr:
            return "", ""
        if addr.startswith('['):
            end = addr.find(']')
            if end > 0:
                ip = addr[1:end]
                port = addr[end+2:] if len(addr) > end+2 else ""
                return ip, port
        if ':' in addr:
            parts = addr.rsplit(':', 1)
            if len(parts) == 2:
                return parts[0], parts[1]
        return addr, ""

    def calculate_rates(self, current, prev, dt):
        """Calculate rates from byte counters."""
        rates = {}
        for iface, stats in current.items():
            if iface in prev:
                p = prev[iface]
                rates[iface] = {
                    "rx": max(0, (stats["rx_bytes"] - p["rx_bytes"]) / dt),
                    "tx": max(0, (stats["tx_bytes"] - p["tx_bytes"]) / dt),
                    "rx_pkts": max(0, (stats["rx_pkts"] - p["rx_pkts"]) / dt),
                    "tx_pkts": max(0, (stats["tx_pkts"] - p["tx_pkts"]) / dt)
                }
        return rates


class NetFlowApp:
    def __init__(self, stdscr, interface=None, nethogs_mode=False):
        self.stdscr = stdscr
        self.interface = interface
        self.nethogs_mode = nethogs_mode
        self.running = True
        self.sort_by = "total"
        self.reverse = True
        self.last_refresh = time.time()
        self.start_time = time.time()

        self.counter = PacketCounter()
        self.proc_net = ProcNetParser()
        self.process_tracker = ProcessTracker()

        self.flows = {}
        self.iface_rates = {}
        self.known_flows = {}  # Track flows over time

        self.setup_curses()

    def setup_curses(self):
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_CYAN, -1)
        curses.init_pair(3, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        self.stdscr.nodelay(True)
        self.stdscr.timeout(100)

    def get_interfaces(self):
        """Get available network interfaces."""
        try:
            net_path = "/sys/class/net"
            if os.path.exists(net_path):
                return [i for i in os.listdir(net_path) if i != "lo"]
        except:
            pass
        return []

    def get_interface_ips(self, iface):
        """Get all IP addresses assigned to an interface."""
        ips = set()
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=1
            )
            if result.returncode == 0:
                import re
                # Match IPv4 addresses like "inet 192.168.1.100/24"
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    ips.add(match.group(1))
        except:
            pass
        return ips

    def get_all_interface_ips(self):
        """Get IP addresses for all interfaces."""
        all_ips = set()
        for iface in self.get_interfaces():
            all_ips.update(self.get_interface_ips(iface))
        return all_ips

    def filter_connections_by_interface(self, tcp_conns, udp_conns):
        """Filter connections to only those on the specified interface."""
        if not self.interface:
            return tcp_conns, udp_conns

        iface_ips = self.get_interface_ips(self.interface)
        if not iface_ips:
            # Interface has no IP address assigned
            return [], []

        def is_on_interface(conn):
            return conn.get("local_ip") in iface_ips

        filtered_tcp = [c for c in tcp_conns if is_on_interface(c)]
        filtered_udp = [c for c in udp_conns if is_on_interface(c)]
        return filtered_tcp, filtered_udp

    def update(self):
        """Update all network statistics."""
        now = time.time()
        dt = max(0.1, now - self.last_refresh)
        self.last_refresh = now

        # Refresh all data sources
        self.process_tracker.refresh()
        self.proc_net.refresh()

        # Get interface stats and rates
        current_iface = self.counter.get_interface_stats()
        self.iface_rates = self.counter.calculate_rates(
            current_iface,
            getattr(self, '_prev_iface', {}),
            dt
        )
        self._prev_iface = current_iface

        # Get connections
        tcp_conns = self.counter.get_connections_ss('tcp')
        udp_conns = self.counter.get_connections_ss('udp')

        # Filter connections by interface if specified
        tcp_conns, udp_conns = self.filter_connections_by_interface(tcp_conns, udp_conns)

        # Update flows with process info
        self.update_flows(tcp_conns, udp_conns, dt)

    def update_flows(self, tcp_conns, udp_conns, dt):
        """Update flow tracking with accurate process mapping."""
        # Use specified interface or all interfaces for bandwidth
        if self.interface:
            rate_ifaces = {self.interface: self.iface_rates.get(self.interface, {"rx": 0, "tx": 0})}
        else:
            rate_ifaces = self.iface_rates

        total_rx = sum(r.get("rx", 0) for r in rate_ifaces.values())
        total_tx = sum(r.get("tx", 0) for r in rate_ifaces.values())

        # Count active connections
        active_tcp = len([c for c in tcp_conns if c.get("state") == "ESTABLISHED"])
        active_udp = len(udp_conns)
        total_active = max(1, active_tcp + active_udp)

        new_flows = {}

        for conn in tcp_conns + udp_conns:
            key = (
                conn["local_ip"], conn["local_port"],
                conn["remote_ip"], conn["remote_port"],
                conn["proto"]
            )

            # First try to get process info from ss (if available)
            pid = conn.get("pid", 0)
            name = conn.get("name", "unknown")
            uid = 0
            inode = 0

            if pid > 0:
                # Get UID from process tracker if we have PID
                proc_info = self.process_tracker.pid_info.get(pid, {})
                name = proc_info.get("name", name)
                uid = proc_info.get("uid", 0)
            else:
                # Fall back to inode-based lookup
                inode = self.proc_net.get_inode(
                    conn["local_ip"], conn["local_port"],
                    conn["remote_ip"], conn["remote_port"]
                )
                proc_info = self.process_tracker.lookup(inode)
                pid = proc_info.get("pid", 0)
                name = proc_info.get("name", "unknown")
                uid = proc_info.get("uid", 0)

            # Calculate bandwidth estimate
            state = conn.get("state", "")
            is_established = state == "ESTABLISHED" or (conn["proto"] == "UDP" and conn["remote_port"])

            if is_established and total_active > 0:
                if conn["proto"] == "TCP":
                    recv_rate = total_rx / active_tcp if active_tcp > 0 else 0
                    sent_rate = total_tx / active_tcp if active_tcp > 0 else 0
                else:  # UDP
                    recv_rate = total_rx / active_udp if active_udp > 0 else 0
                    sent_rate = total_tx / active_udp if active_udp > 0 else 0
            else:
                recv_rate = 0
                sent_rate = 0

            # Update or create flow
            if key in self.flows:
                flow = self.flows[key]
                # Smooth the rates
                flow["sent_rate"] = flow["sent_rate"] * 0.7 + sent_rate * 0.3
                flow["recv_rate"] = flow["recv_rate"] * 0.7 + recv_rate * 0.3
                flow["total_sent"] += sent_rate * dt
                flow["total_recv"] += recv_rate * dt
            else:
                self.flows[key] = {
                    "sent": 0, "recv": 0,
                    "sent_rate": sent_rate, "recv_rate": recv_rate,
                    "total_sent": sent_rate * dt, "total_recv": recv_rate * dt,
                    "local_ip": conn["local_ip"],
                    "local_port": conn["local_port"],
                    "remote_ip": conn["remote_ip"],
                    "remote_port": conn["remote_port"],
                    "proto": conn["proto"],
                    "state": state,
                    "pid": pid,
                    "name": name,
                    "uid": uid,
                    "inode": inode
                }

            new_flows[key] = self.flows[key]

        # Decay old flows
        for key in list(self.flows.keys()):
            if key not in new_flows:
                self.flows[key]["sent_rate"] *= 0.5
                self.flows[key]["recv_rate"] *= 0.5
                if self.flows[key]["sent_rate"] < 1 and self.flows[key]["recv_rate"] < 1:
                    del self.flows[key]

    def format_rate(self, rate):
        """Format bytes/sec rate."""
        rate = max(0, rate)
        for unit in ['B', 'K', 'M', 'G']:
            if rate < 1024:
                return f"{rate:6.1f}{unit}/s"
            rate /= 1024
        return f"{rate:6.1f}T/s"

    def format_bytes(self, val):
        """Format bytes."""
        val = max(0, val)
        for unit in ['B', 'K', 'M', 'G']:
            if val < 1024:
                return f"{val:6.0f}{unit}"
            val /= 1024
        return f"{val:6.0f}T"

    def get_sorted_flows(self):
        """Get flows sorted by criteria."""
        flows_list = list(self.flows.items())
        key_func = lambda x: (
            x[1].get(self.sort_by, 0),
            x[1].get("sent_rate", 0) + x[1].get("recv_rate", 0)
        )
        return sorted(flows_list, key=key_func, reverse=self.reverse)

    def render(self):
        """Render the UI."""
        try:
            max_y, max_x = self.stdscr.getmaxyx()
            self.stdscr.clear()

            if self.nethogs_mode:
                self.render_nethogs(max_y, max_x)
            else:
                self.render_iftop(max_y, max_x)

            self.render_footer(max_y, max_x)
        except curses.error:
            pass

    def render_iftop(self, max_y, max_x):
        """Render iftop-style view."""
        iface = self.interface or "|".join(self.get_interfaces()[:2]) or "?"

        self.stdscr.addstr(0, 0, f" NetFlow [IFTOP]  Interface: {iface}", curses.color_pair(4) | curses.A_BOLD)

        if self.interface:
            rate_ifaces = [self.interface]
        else:
            rate_ifaces = self.get_interfaces()
        total_rx = sum(self.iface_rates.get(i, {}).get("rx", 0) for i in rate_ifaces)
        total_tx = sum(self.iface_rates.get(i, {}).get("tx", 0) for i in rate_ifaces)

        self.stdscr.addstr(1, 0, f" RX: {self.format_rate(total_rx)}  TX: {self.format_rate(total_tx)}")

        # Check if specified interface has no IP
        if self.interface and not self.get_interface_ips(self.interface):
            self.stdscr.addstr(2, 0, f" [Warning: {self.interface} has no IP address assigned]", curses.color_pair(5))
            y = 4
        else:
            y = 3

        self.stdscr.addstr(y, 0, "  Local Address              Remote Address           PR  PID     Program          Sent        Received", curses.A_BOLD)
        self.stdscr.addstr(y+1, 0, "─" * (max_x-1))

        flows = self.get_sorted_flows()
        for i, (key, flow) in enumerate(flows):
            if i + y + 2 >= max_y - 3:
                break

            ly = y + 2 + i

            local = f"{flow['local_ip']}:{flow['local_port']}"
            remote = f"{flow['remote_ip']}:{flow['remote_port']}"
            proto = flow.get('proto', '??')[:2]
            pid = f"{flow['pid']}" if flow['pid'] else "-"
            name = flow.get('name', '?')[:14]
            sent = self.format_rate(flow['sent_rate'])
            recv = self.format_rate(flow['recv_rate'])

            color = curses.color_pair(1) if flow.get('state') == 'ESTABLISHED' else curses.color_pair(3)

            line = f"  {local:<24} {remote:<24} {proto:<2} {pid:>5}  {name:<14} {sent:>11} {recv:>11}"
            self.stdscr.addstr(ly, 0, line[:max_x-1], color)

        if not flows:
            self.stdscr.addstr(y+2, 0, "  No active connections")

    def render_nethogs(self, max_y, max_x):
        """Render nethogs-style view."""
        iface = self.interface or "|".join(self.get_interfaces()[:2]) or "?"

        self.stdscr.addstr(0, 0, f" NetFlow [NETHOGS]  Interface: {iface}", curses.color_pair(4) | curses.A_BOLD)

        if self.interface:
            rate_ifaces = [self.interface]
        else:
            rate_ifaces = self.get_interfaces()
        total_rx = sum(self.iface_rates.get(i, {}).get("rx", 0) for i in rate_ifaces)
        total_tx = sum(self.iface_rates.get(i, {}).get("tx", 0) for i in rate_ifaces)

        self.stdscr.addstr(1, 0, f" RX: {self.format_rate(total_rx)}  TX: {self.format_rate(total_tx)}")

        # Check if specified interface has no IP
        if self.interface and not self.get_interface_ips(self.interface):
            self.stdscr.addstr(2, 0, f" [Warning: {self.interface} has no IP address assigned]", curses.color_pair(5))
            y = 4
        else:
            y = 3

        proc_data = defaultdict(lambda: {"sent": 0, "recv": 0, "pid": 0, "name": "unknown", "uid": 0, "proto": set()})

        for key, flow in self.flows.items():
            pid = flow["pid"]
            name = flow["name"]
            proc_data[(pid, name)]["sent"] += flow["sent_rate"]
            proc_data[(pid, name)]["recv"] += flow["recv_rate"]
            proc_data[(pid, name)]["pid"] = pid
            proc_data[(pid, name)]["name"] = name
            proc_data[(pid, name)]["uid"] = flow["uid"]
            proc_data[(pid, name)]["proto"].add(flow["proto"])

        sorted_procs = sorted(
            proc_data.items(),
            key=lambda x: x[1]["sent"] + x[1]["recv"],
            reverse=self.reverse
        )

        y = 3
        self.stdscr.addstr(y, 0, "  PID     USER         PROGRAM                 PROTO     SENT        RECEIVED", curses.A_BOLD)
        self.stdscr.addstr(y+1, 0, "─" * (max_x-1))

        for i, ((pid, name), stats) in enumerate(sorted_procs):
            if i + y + 2 >= max_y - 3:
                break

            ly = y + 2 + i

            user = self.process_tracker.get_user(stats["uid"])[:10]
            proto = ",".join(sorted(stats["proto"]))[:6]
            pid_str = f"{pid}" if pid else "-"
            sent = self.format_rate(stats["sent"])
            recv = self.format_rate(stats["recv"])

            line = f"  {pid_str:>6}  {user:<10}  {name:<20} {proto:<6} {sent:>11} {recv:>11}"
            self.stdscr.addstr(ly, 0, line[:max_x-1])

        if not sorted_procs:
            self.stdscr.addstr(y+2, 0, "  No active connections")

    def render_footer(self, max_y, max_x):
        """Render footer."""
        y = max_y - 2
        sort_label = {"total": "Total", "sent": "Sent", "recv": "Recv"}.get(self.sort_by, "Total")
        mode_label = "NETHOGS" if self.nethogs_mode else "IFTOP"
        rev = "▼" if self.reverse else "▲"

        footer = f" [q]Quit  [s]Sort({sort_label})  [r]Reverse{rev}  [m]Mode({mode_label})"
        self.stdscr.addstr(y, 0, footer[:max_x-1])

        ts = datetime.now().strftime("%H:%M:%S")
        self.stdscr.addstr(y, max_x - 9, f" {ts}")

    def handle_input(self):
        """Handle keyboard input."""
        try:
            key = self.stdscr.getch()

            if key in (ord('q'), ord('Q'), 27, 3):
                self.running = False
            elif key in (ord('s'), ord('S')):
                self.sort_by = {"total": "sent", "sent": "recv", "recv": "total"}.get(self.sort_by, "total")
            elif key in (ord('r'), ord('R')):
                self.reverse = not self.reverse
            elif key in (ord('m'), ord('M')):
                self.nethogs_mode = not self.nethogs_mode
        except curses.error:
            pass

    def run(self):
        """Main loop."""
        self.last_refresh = time.time()
        while self.running:
            self.handle_input()
            self.update()
            self.render()
            time.sleep(0.1)


def main(stdscr):
    parser = argparse.ArgumentParser(
        description="NetFlow - Linux Network Process Traffic Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s              # Run with auto-detected interface
  %(prog)s -i eth0      # Monitor eth0 interface
  %(prog)s --nethogs    # Use nethogs-style view

Keys:  q/Q/ESC  Quit | s/S  Cycle sort | r/R  Reverse | m/M  Toggle mode
"""
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (default: auto-detect)")
    parser.add_argument("--nethogs", action="store_true",
                        help="Start in nethogs-style mode")
    args = parser.parse_args()

    if args.interface:
        available = []
        try:
            if os.path.exists("/sys/class/net"):
                available = os.listdir("/sys/class/net")
        except OSError:
            pass

        if args.interface not in available:
            print(f"Error: Interface '{args.interface}' not found.")
            print(f"Available: {', '.join(available) if available else 'none'}")
            sys.exit(1)

    try:
        app = NetFlowApp(stdscr, args.interface, args.nethogs)
        app.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if not sys.stdout.isatty():
        print("NetFlow requires a terminal. Please run from a terminal.")
        print("\nUsage: python3 netflow.py [--nethogs] [-i INTERFACE]")
        print("       python3 netflow.py --help")
        sys.exit(1)

    curses.wrapper(main)

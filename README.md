# my-netool

personal tool collection,backed up here.

## netflow.py

Linux only. Tested on local environment: Ubuntu 24.04.4 LTS, Linux 6.17.0-35-generic.Only for basic traffic display. For more specific details, please use other tools.

combines the approaches of iftop and nethogs, allowing me to see which process is handling each request.

0.1s refresh interval, live network bandwidth display,accurate network-to-process matching via socket inode.

### Usage

| Option | Description |
| -------- | ------------- |
| `-i INTERFACE` | Specify network interface, e.g. `-i wlan0` |
| `--nethogs` | Start in nethogs mode |
| `-h, --help` | Show help message |

```bash
# Normal user: only sees own processes
python3 ./netflow.py

# Root user: sees all processes
sudo python3 ./netflow.py
```

### Keyboard Shortcuts

| Key | Action |
| ----- | -------- |
| `q` / `Q` / `ESC` | Quit |
| `s` / `S` | Cycle sort: total → sent → received |
| `r` / `R` | Toggle reverse sort order |
| `m` / `M` | Toggle iftop / nethogs mode |

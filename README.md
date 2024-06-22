# docker-dbg

Python package to effortlessly debug any<sup>1</sup> process running in a docker container

<sup>1</sup> Only x86_64 containers running Linux are supported.  


## Demo


## Dependencies

### On the host
- Python with `pwntools`
- gdb
- Docker (current user should be added to the `docker` group)

### In the container
- `root` user
- Commands: `cat`, `cp`, `chmod`, `ps`, `rm`
- Optional: `killall`, `kill`, `ip`, `awk`
- A functional `/proc` filesystem
- `/` must be writable by `root`

These requirements shouldn't be a problem for most Linux docker containers.


## Packaged binaries
- Statically compiled `gdbserver` (13.2, compiled with `./configure CXXFLAGS="-fPIC -static"  --disable-inprocess-agent `)
- Statically compiled `frps` and `frpc` (v0.58.1, from https://github.com/fatedier/frp/releases/tag/v0.58.1)
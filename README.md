# docker-dbg

Python package to effortlessly debug any<sup>1</sup> process running in a docker container

<sup>1</sup> Only x86_64 containers running Linux are supported.  


## Demo


## Installation
```shell
pip install git+https://github.com/junron/docker-dbg
```

## Usage

Docker-dbg mirrors the `pwntools` [GDB module](https://docs.pwntools.com/en/stable/gdb.html)'s `debug` and `attach`:

```python
from docker_dbg import *

# Execute and debug the `/demo` binary in `container`:
p, docker_process = docker_debug("/demo", container="container")

# Attach to an existing process `demo` in `container`:
docker_process = docker_attach(proc="demo", container="container")
```

`docker_process.gdb` provides access to the `pwntools` GDB module. The `docker_process.libc` provides access to the libc executing in the container.

Checkout [`ubuntu/demo.py`](./demo/ubuntu/demo.py) for an example of `docker_debug` and [`redpwn_jail/demo.py`](./demo/redpwn_jail/demo.py) for `docker_attach`.


## How it works
Docker-dbg copies `gdbserver` into the docker container, then uses [fast reverse proxy](https://github.com/fatedier/frp/) to proxy the `gdbserver` port out of the docker container.

## Dependencies

### On the host
- Python 3 with `pwntools`
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
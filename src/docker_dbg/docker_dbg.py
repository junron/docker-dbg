import os
import random
import six
import pwnlib.gdb as pgdb
from pwnlib.tubes.process import process
import pwnlib
import atexit
import tempfile
from typing import Tuple
import functools

def ps_grep(proc, container):
    results = os.popen(f"docker exec --user root '{container}' ps aux").read().splitlines()
    pid_index = results[0].split().index("PID")
    out = []
    for line in results[1:]:
        if proc in line:
            pid = int(line.split()[pid_index])
            out.append(pid)
    return out
    
def exec_in_container(container, cmd, check_output=True):
    p = os.popen(f"docker exec --user root '{container}' {cmd}")
    if check_output:
        res = p.read()
        if "permission denied" in res:
            print("Please add this user to the docker group")
            exit(1)
        return res
        

def setup_docker(args, container, exe=None) -> Tuple[int, str]:

    def killall(proc):
        if "executable file not found" in exec_in_container(container, f"killall {proc} 2>&1"):
            pids = ps_grep(proc, container)
            for p in pids:
                exec_in_container(container, f"kill {p}")


    def copy_to_container(f):
        return os.popen(f"docker cp {f} '{container}:/'").read()

    def random_port():
        return random.randint(1024, 65535)
    
    def get_dir():
        return os.path.join(os.path.dirname(__file__), "binaries")
    
    def cleanup():
        killall("gdbserver")
        killall("frpc")
    atexit.register(cleanup)

    if isinstance(args, (bytes, six.text_type)):
        args = [args]
    
    parts = args[0].split("/")
    if parts[0] != "":
        print("Executable path must be absolute")
        return
    
    if os.path.exists("./frps.toml") and exec_in_container(container, "ls /frpc 2>/dev/null").strip():
        frpc = exec_in_container(container, "cat /frpc.toml")
        gdbserver_port = int(frpc.split("localPort = ")[1].split("\n")[0])
        frps_port = int(frpc.split("serverPort = ")[1].split("\n")[0])
    else:
        host_ip = exec_in_container(container, "ip route|awk '/default/ { print $3 }'").strip()
        if not host_ip:
            host_ip = "172.17.0.1"

        frps_port = random_port()

        gdbserver_port = random_port()
        
        f = tempfile.NamedTemporaryFile(mode="w")
        f.write(f"serverAddr = \"{host_ip}\"\n")
        f.write(f"serverPort = {frps_port}\n")
        f.write(f"[[proxies]]\n")
        f.write(f"name = \"gdbserver\"\n")
        f.write(f"type = \"tcp\"\n")
        f.write(f"localIP = \"127.0.0.1\"\n")
        f.write(f"localPort = {gdbserver_port}\n")
        f.write(f"remotePort = {gdbserver_port}\n")
        f.flush()

        copy_to_container(f.name)
        f.close()
        exec_in_container(container, f"cp /{f.name.split('/')[-1]} /frpc.toml")
        copy_to_container(f"{get_dir()}/frpc")
        copy_to_container(f"{get_dir()}/gdbserver")
        exec_in_container(container, "chmod +x /frpc")

    f = tempfile.NamedTemporaryFile(mode="w")
    f.write(f"bindPort = {frps_port}\n")
    f.flush()
    
    frps = process([f"{get_dir()}/frps", "-c", f.name], level='error')
    frps.recvuntil(b"started successfully")
    
    exec_in_container(container, "/frpc -c /frpc.toml", check_output=False)
    if exe is None:
        temp = tempfile.NamedTemporaryFile(delete=False)
        os.popen(f"docker cp '{container}:{args[0]}' {temp.name}").read()
        exe = temp.name
        atexit.register(lambda: os.unlink(temp.name))
    
    return gdbserver_port, exe
    
class DockerProcess:
    pid: int
    gdb: pgdb.Gdb
    executable: str
    container: str

    def libs(self):
        maps_raw = exec_in_container(self.container, f"cat /proc/{self.pid}/maps")
        if not maps_raw.strip():
            return {}
        maps = {}
        for line in maps_raw.splitlines():
            if '/' not in line: continue
            path = line[line.index('/'):]
            if path not in maps:
                maps[path]=0

        for lib in maps:
            for line in maps_raw.splitlines():
                if line.endswith(lib):
                    address = line.split('-')[0]
                    maps[lib] = int(address, 16)
                    break
        return maps
    
    @functools.lru_cache()
    def download_lib(self, path):
        temp = tempfile.NamedTemporaryFile(delete=False)
        container_exe_name = random.randbytes(8).hex()
        container_path = f"/proc/{self.pid}/root{path}"
        exec_in_container(self.container, f"cp {container_path} /{container_exe_name}")
        os.popen(f"docker cp '{self.container}:/{container_exe_name}' {temp.name}").read()
        exec_in_container(self.container, f"rm /{container_exe_name}")
        atexit.register(lambda: os.unlink(temp.name))
        return temp.name
    
    @property
    def libc_path(self) -> str:
        for lib, address in self.libs().items():
            if 'libc.so' in lib or 'libc-' in lib:
                return lib
    
    @property
    def libc(self) -> pwnlib.elf.ELF:
        from pwnlib.elf import ELF
        lib = self.libc_path
        e = ELF(self.download_lib(lib))
        e.address = self.libs()[self.libc_path]
        return e
            
    def download_libc(self):
        path = self.libc.path
        os.system(f"cp {path} ./libc.so.6")
    
    @property
    def address(self) -> int:
        libs = self.libs()
        cmdline = exec_in_container(self.container, f"cat /proc/{self.pid}/cmdline")
        exe_name = cmdline.split()[0]
        if exe_name in libs:
            return libs[exe_name]
        for lib, address in libs.items():
            if "lib" not in lib and ".so" not in lib:
                return address
    
    @property
    def elf(self):
        import pwnlib.elf.elf
        e = pwnlib.elf.elf.ELF(self.executable)
        e.address = self.address
        return e
    

    def breakpoint(self, address: int, block=False):
        # probably PIE
        if address < 0x10000:
            pie_base = self.address
            # Almost definitely PIE
            if pie_base > address:
                address += pie_base
        self.gdb.Breakpoint(f"*{hex(address)}")
        if block:
            self.gdb.continue_and_wait()
        else:
            self.gdb.continue_nowait()

    def brpt(self: pwnlib.tubes.process, address: int, block=False) -> pwnlib.gdb.Gdb:
        return self.breakpoint(address, block)

def docker_debug(args, container, gdbscript=None, exe=None, api=False) -> process:
    gdbserver_port, exe = setup_docker(args, container, exe)

    gdbserver_args = ["docker", "exec", "-i", "--user", "root", container]

    gdbserver = process(gdbserver_args + ["/gdbserver", "--no-disable-randomization", f"localhost:{gdbserver_port}", *args], level="error")

    gdbserver.executable = exe
    tmp = pgdb.attach(("127.0.0.1", gdbserver_port), exe=exe, gdbscript=gdbscript, api=api)

    if api:
        _, gdb = tmp
        gdbserver.gdb = gdb
    garbage = gdbserver.recvline(timeout=1)

    # Some versions of gdbserver output an additional message
    garbage2 = gdbserver.recvline_startswith(b"Remote debugging from host ", timeout=2)

    return gdbserver


def docker_attach(proc, container, gdbscript=None) -> DockerProcess:
    pids = ps_grep(proc, container)
    if not pids:
        print("Process not found!")
        return None
    pid = max(pids)
    exe_path = f"/proc/{pid}/exe"
    container_exe_name = random.randbytes(8).hex()
    os.popen(f"docker exec --user root '{container}' cp {exe_path} /{container_exe_name}").read()
    gdbserver_port, exe = setup_docker(f"/{container_exe_name}", container)
    os.popen(f"docker exec --user root '{container}' rm /{container_exe_name}")

    gdbserver_args = ["docker", "exec", "-i", "--user", "root", container]

    process(gdbserver_args + ["/gdbserver", "--no-disable-randomization", "--attach", f"localhost:{gdbserver_port}", str(pid)], level="error")

    _, gdb = pgdb.attach(("127.0.0.1", gdbserver_port), exe=exe, gdbscript=gdbscript, api=True)

    dp = DockerProcess()
    dp.pid = pid
    dp.gdb = gdb
    dp.executable = exe
    dp.container = container
    return dp




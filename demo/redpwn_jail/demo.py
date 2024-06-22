from docker_dbg import *
from pwn import *

p = remote("localhost", 34569)
dp = docker_attach(container="demo-jail", proc="run")

libc = dp.libc
dp.brpt(libc.sym.printf)

p.sendlineafter(b">", b"World")
dp.gdb.wait()

res = dp.gdb.execute("x/s $rsi", to_string=True)
assert "World" in res, res
dp.gdb.continue_nowait()

print(p.recvall().decode())
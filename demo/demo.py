from docker_dbg import *
from pwn import *

p = remote("localhost", 34569)
dp = docker_attach(container="demo-container", proc="run")

libc = dp.libc
dp.brpt(libc.sym.printf)

p.sendlineafter(b">", b"World")
p.interactive()
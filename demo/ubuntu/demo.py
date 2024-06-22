from docker_dbg import *
from pwn import *

p, dp = docker_debug("/demo", container="demo-ubuntu", gdbscript="catch load libc.so\nc\n")

dp.gdb.wait()

libc = dp.libc
dp.brpt(libc.sym.printf)

dp.gdb.wait()
res = dp.gdb.execute("x/s $rdi", to_string=True)
assert "What's your name?" in res, res
dp.gdb.continue_nowait()

p.sendlineafter(b">", b"World")
dp.gdb.wait()

res = dp.gdb.execute("x/s $rsi", to_string=True)
assert "World" in res, res
dp.gdb.continue_nowait()

print(p.recvall().decode())
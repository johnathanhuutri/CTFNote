#!/usr/bin/env python

import os
import re
from pwn import *
import argparse

x64 = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
x32 = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'esp', 'ebp']
x16 = ['ax', 'bx', 'cx', 'dx', 'sp', 'bp']
x8 = ['al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'dil', 'sil']

class COLOR:
	YELLOW = '\033[0;33m'
	CYAN = '\033[0;36m'
	RESET = '\033[0m'

def color_byte(byte_str):
	if args.nocolor:
		return byte_str
	try:
		val = int(byte_str, 16)
		color = COLOR.YELLOW if val % 2 == 0 else COLOR.CYAN
		return f"{color}{byte_str}{COLOR.RESET}"
	except:
		return byte_str  # fallback

def parse_line(line):
	# Remove offset of shellcode, which will cause problem if find for bytes
	line = re.sub(r'^.*:\s*', '', line)

	if all([ int(b, 16)%2==0 for b in re.findall(r'\b[0-9a-fA-F]{2}\b', line) ]):
		mode = 'e'
	elif all([ int(b, 16)%2!=0 for b in re.findall(r'\b[0-9a-fA-F]{2}\b', line) ]):
		mode = 'o'
	else:
		mode = 'a'

		b = re.findall(r'\b[0-9a-fA-F]{2}\b', line)
		tmp_mode_prev = 'e' if int(b[0], 16)%2==0 else 'o'
		for i in range(1, len(b)):
			tmp_mode = 'e' if int(b[i], 16)%2==0 else 'o'
			if tmp_mode_prev==tmp_mode:
				mode = 'x'
				break
			tmp_mode_prev = tmp_mode

	line = re.sub(r'\s{2,}', ' - ', line, count=1)
	line = re.sub(r'\s{2,}', ' ', line, count=1)
	line = re.sub(r'\b[0-9a-fA-F]{2}\b', lambda m: color_byte(m.group()), line)

	return line, mode

def parse_shellcode(sc):
	sc = asm(sc, arch='amd64')
	sc = disasm(sc, arch='amd64')
	output = ''
	for line in sc.split('\n'):
		line, mode = parse_line(line)
		if args.mode:
			if args.mode == mode:
				output += line + '\n'
		else:
			output += line + '\n'
	return output

def gen_add_sub(ins):
	print(f'[*] Generating "{ins}"...')
	sc = ''

	# Register only
	for rtype in x64, x32, x16, x8:
		for r1 in rtype:
			for r2 in rtype:
				if (r1 in ['dil', 'sil'] and r2 in ['ah', 'bh', 'ch', 'dh']) or (r1 in ['ah', 'bh', 'ch', 'dh'] and r2 in ['dil', 'sil']):
					continue
				sc += f'{ins} {r1}, {r2}\n'

	# With immediate value
	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}, 0x7e\n'

	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}, 0x7f\n'

	# With pointer
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'{ins} [{r1}], {r2}\n'
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'{ins} {r2}, [{r1}]\n'
	return parse_shellcode(sc)

def gen_mov():
	print(f'[*] Generating "mov"...')
	sc = ''

	# Register only
	for rtype in x64, x32, x16, x8:
		for r1 in rtype:
			for r2 in rtype:
				if (r1 in ['dil', 'sil'] and r2 in ['ah', 'bh', 'ch', 'dh']) or (r1 in ['ah', 'bh', 'ch', 'dh'] and r2 in ['dil', 'sil']):
					continue
				sc += f'mov {r1}, {r2}\n'

	# With immediate value
	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'mov {r}, 0x7e\n'

	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'mov {r}, 0x7f\n'

	# With pointer
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'mov [{r1}], {r2}\n'
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'mov {r2}, [{r1}]\n'

	return parse_shellcode(sc)

def gen_lea():
	print(f'[*] Generating "lea"...')
	sc = ''

	# Register only
	for r1 in x64:
		for r2 in x64:
			sc += f'lea {r1}, [{r2}]\n'

	for r1 in x64:
		for r2 in x64:
			sc += f'lea {r1}, [{r2}+0x7e]\n'

	for r1 in x64:
		for r2 in x64:
			sc += f'lea {r1}, [{r2}+0x7f]\n'

	return parse_shellcode(sc)

def gen_xchg():
	print(f'[*] Generating "xchg"...')
	sc = ''

	# Register only
	for rtype in x64, x32, x16, x8:
		for i1 in range(len(rtype)):
			for i2 in range(i1, len(rtype)):
				if (rtype[i1] in ['dil', 'sil'] and rtype[i2] in ['ah', 'bh', 'ch', 'dh']) or (rtype[i1] in ['ah', 'bh', 'ch', 'dh'] and rtype[i2] in ['dil', 'sil']):
					continue
				sc += f'xchg {rtype[i1]}, {rtype[i2]}\n'

	# With pointer
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'xchg [{r1}], {r2}\n'
	return parse_shellcode(sc)

def gen_or_xor_and(ins):
	print(f'[*] Generating "{ins}"...')
	sc = ''

	# Register only
	for rtype in x64, x32, x16, x8:
		for r1 in rtype:
			for r2 in rtype:
				if (r1 in ['dil', 'sil'] and r2 in ['ah', 'bh', 'ch', 'dh']) or (r1 in ['ah', 'bh', 'ch', 'dh'] and r2 in ['dil', 'sil']):
					continue
				sc += f'{ins} {r1}, {r2}\n'

	# With immediate value
	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}, 0x7e\n'

	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}, 0x7f\n'

	# With pointer
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'{ins} [{r1}], {r2}\n'
	for r1 in x64:
		for rtype in x64, x32, x16, x8:
			for r2 in rtype:
				if r1 in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'] and r2 in ['ah', 'bh', 'ch', 'dh']:
					continue
				sc += f'{ins} {r2}, [{r1}]\n'
	return parse_shellcode(sc)

def gen_shift_rotate(ins):
	print(f'[*] Generating "{ins}"...')
	sc = ''

	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}, cl\n'		# shl, shr only works with cl

	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}, 0xff\n'		# shl, shr only works with 1 bytes
	return parse_shellcode(sc)

def gen_push_pop(ins):
	print(f'[*] Generating "{ins}"...')
	sc = ''

	for r in x64:
		sc += f'{ins} {r}\n'		# shl, shr only works with cl

	for r in x64:
		sc += f'{ins} {r}\n'		# shl, shr only works with 1 bytes

	if ins=='push':
		sc += 'push 0x80\n'
		sc += 'push 0x8081\n'
		sc += 'push 0x808180\n'
		sc += 'push 0x8081808\n'
	return parse_shellcode(sc)

def gen_inc_dec(ins):
	print(f'[*] Generating "{ins}"...')
	sc = ''

	for rtype in x64, x32, x16, x8:
		for r in rtype:
			sc += f'{ins} {r}\n'		# shl, shr only works with cl
	return parse_shellcode(sc)

if __name__=='__main__':
	# Create parser
	parser = argparse.ArgumentParser(description="Simple argparse demo", formatter_class=argparse.RawTextHelpFormatter)

	# Add arguments
	parser.add_argument('-i', '--ins', nargs='+', type=str, help='One or more available instruction:\n  all (select all instruction)\n  add\n  sub\n  mov\n  lea\n  xchg\n  or\n  xor\n  and\n  shl\n  shr\n  ror\n  rol\n  push\n  pop\n  inc\n  dec')
	parser.add_argument('-a', '--asm', type=str, help='Compile assembly code')
	parser.add_argument('-m', '--mode', type=str, help='Check opcode if even or odd (default: x)\n"x" to skip\n"e" to check if even\n"o" to check if odd, "a" to check if even and odd alternating')
	parser.add_argument('-o', '--output', type=str, help='Save selected instruction to file OUTPUT')
	parser.add_argument('--nocolor', action='store_true', help='Don\'t print with color')

	# Parse arguments
	args = parser.parse_args()

	if not (args.asm or args.ins):
		parser.print_help()
		exit(0)

	if args.asm and args.ins:
		print("[-] Cannot use --ins and --asm at the same time!")
		exit(0)

	if args.asm:
		sc = args.asm.replace('\\n', '\n')
		print(f'[*] Generating shellcode for assembly:\n{sc}')
		print(parse_shellcode(sc))
		exit(0)

	sc = ''
	for ins in args.ins:
		match ins:
			case 'all':
				sc += gen_add_sub('add')
				sc += gen_add_sub('sub')
				sc += gen_mov()
				sc += gen_lea()
				sc += gen_xchg()
				sc += gen_or_xor_and('or')
				sc += gen_or_xor_and('xor')
				sc += gen_or_xor_and('and')
				sc += gen_shift_rotate('shl')
				sc += gen_shift_rotate('shr')
				sc += gen_shift_rotate('ror')
				sc += gen_shift_rotate('rol')
				sc += gen_push_pop('push')
				sc += gen_push_pop('pop')
				sc += gen_inc_dec('inc')
				sc += gen_inc_dec('dec')
			case 'add':
				sc += gen_add_sub(ins)
			case 'sub':
				sc += gen_add_sub(ins)
			case 'mov':
				sc += gen_mov()
			case 'lea':
				sc += gen_lea()
			case 'xchg':
				sc += gen_xchg()
			case 'or':
				sc += gen_or_xor_and(ins)
			case 'xor':
				sc += gen_or_xor_and(ins)
			case 'and':
				sc += gen_or_xor_and(ins)
			case 'shl':
				sc += gen_shift_rotate(ins)
			case 'shr':
				sc += gen_shift_rotate(ins)
			case 'ror':
				sc += gen_shift_rotate(ins)
			case 'rol':
				sc += gen_shift_rotate(ins)
			case 'push':
				sc += gen_push_pop(ins)
			case 'pop':
				sc += gen_push_pop(ins)
			case 'inc':
				sc += gen_inc_dec(ins)
			case 'dec':
				sc += gen_inc_dec(ins)
	if args.output:
		open(args.output, 'w').write(sc)
		print(f'[+] Saved to file "{args.output}"!')
	else:
		print(sc)

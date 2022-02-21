# Writeup

**https://mocsctf2022.mocsctf.com/challenges**

| Name | Type | File Type | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [C@ge](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-Cage) | pwn | c++ (64 bit) | `Heap Buffer Overflow` `Tcache Attack` `Ret2libc` | Use environ to leak stack address |


**https://pwnable.tw/**

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Start](https://github.com/nhtri2003gmail/writeup-pwnable.tw-Start) | pwn | c (32 bit) | `Buffer Overflow` `ROP`|

**https://cnsc.uit.edu.vn/ctf/** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [Feedback](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback) | pwn | c (64 bit) | `Least Significant Byte` |
| [note](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-note) | pwn | c (64 bit) | `Heap Attack` `Unsorted Bin Attack` |

**https://pwn.tn/**

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [f_one](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [f_two](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two) | pwn | c (32 bit) | `Buffer Overflow` `Integer Overflow` `Format String` |

**https://www.kcscctf.site/** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [ArrayUnderFl0w](https://github.com/nhtri2003gmail/writeup-kcscctf.site-ArrayUnderFl0w) | pwn | c | `Unchecked Index` |
| [guessMe](https://github.com/nhtri2003gmail/writeup-kcscctf.site-guessMe) | pwn | c | `Specific Seed Rand` |
| [Make Me Crash](https://github.com/nhtri2003gmail/writeup-kcscctf.site-Make_Me_Crash) | pwn | c | `Buffer Overflow` |
| [Chall](https://github.com/nhtri2003gmail/writeup-kcscctf.site-Chall) | pwn | c | `Format String` |
| [ret2win](https://github.com/nhtri2003gmail/writeup-kcscctf.site-ret2win) | pwn | c | `Buffer Overflow` |
| [get OVER InT](https://github.com/nhtri2003gmail/writeup-kcscctf.site-get_OVER_InT) | pwn | c | `Integer Overflow` |
| [bof1](https://github.com/nhtri2003gmail/writeup-kcscctf.site-bof1) | pwn | c | `Buffer Overflow` |

**ISITDTU 2019** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [tokenizer](https://github.com/nhtri2003gmail/writeup-ISITDTU2019-tokenizer) | pwn | cpp (64 bit) | `Least Significant Byte` |
| [iz_heap_lv1](https://github.com/nhtri2003gmail/writeup-ISITDTU2019-iz_heap_lv1) | pwn | c (64 bit) | `Heap Attack` `Tcache attack` |

**https://ctf.dicega.ng/**
| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [baby-rop](https://github.com/nhtri2003gmail/writeup-ctf.dicega.ng-baby-rop) | pwn | c (64 bit) | `Heap Attack` `ROP chaining` |
| [dataeater](https://github.com/nhtri2003gmail/writeup-ctf.dicega.ng-dataeater) | pwn | c (64 bit) | `ret2dlresolve` `Fake link_map` |

**https://dctf21.cyberedu.ro/**
| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [cache]() | pwn | c (64 bit) | `Use After Free` `Double Free` `Tcache Attack` `Overwrite GOT` |
| [blindsight](https://github.com/nhtri2003gmail/writeup-dctf21.cyberedu.ro-blindsight) | pwn | c (64 bit) | `Blind ROP` `Buffer Overflow` |


# Technique

| Name | When |
| :---: | :--- |
| [ret2dlresolve (64 bit)](https://github.com/nhtri2003gmail/ret2dlresolve-64bit) | Just input, no output and no output function |

# Note

#### Execute @plt on stack (BOF):
```
payload = <padding> + <@plt> + <return address> + <arg1> + <arg2>...
```

#### Another version for gdb.attach()

Using [x-terminal-emulator](https://www.systutorials.com/docs/linux/man/1-x-terminal-emulator/) to create popup shell and pass command in a file:

```
import subprocess

with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', '<child pid here>', '-x', '/tmp/command.gdb'])
input()         # input() to make program wait with gdb
```

#### pwntools  

- Get child pid (way 1): 
```
import os
from pwn import *

p = process(<Some Program>)
child_pid = pwnlib.util.proc.children(os.getpid())[0]
print(child_pid)
```

- Get child pid (way 2):
```
from pwn import *

p = process(<Some Program>)
print(pidof(p))
```

- Get child pid (way 3):
```
from pwn import *

p = process(<Some Program>)
print(p.pid)
```

- ARGS:

run.py:

```
from pwn import *

# print(args.<ANY NAME IN CAPITAL>)
print(args.MYNAME)
print(args.MYAGE)
```

Command:

```
python run.py MYNAME=Johnathan MYAGE=20
```

- [Core File:](https://docs.pwntools.com/en/stable/elf/corefile.html)

```
from pwn import *

p = process('<File>')

p.sendline(b'A'*500)
p.wait()     # Wait until it crash. Core file will be made after crash.
             # If it doesn't crash, check manually to make sure it crash

core = Coredump('./core')

# Read number of data from the specified address
print(core.read(<some address>, <number of byte read>))     # Return byte

# Read until null byte
print(core.string(<some address>))
```

#### Get shellcode from binary

Reference Source: https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump

```
objdump -d <Name of program>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

#### gdb

- `r < <()` can pass null byte, `r <<<$()` cannot.

- `flag +/-ZERO` to set or remove flag.

#### movaps xmm0,... 

- rsp (esp) address must end with byte 0x00, 0x10, 0x20, 0x30... or it will cause error.</br>
Ex: if rsp address end with 0xe8 --> segfault.

#### format string 

- `%p%p%p%n` will write and access easily.

- `%4$n` will write but cannot access.

- Payload should have `%c` instead `%x` to make sure it write a byte, **not** a random byte on stack.

- Enter `.` to `scanf()` with number format (`%d`, `%u`, `%ld`...) won't enter new value to var. 

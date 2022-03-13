### Table of content
- [Writeup](#writeup-table-of-content)
- [Technique](#technique-table-of-content)
- [Note](#note-table-of-content)

# Writeup ([Table of content](#table-of-content))

[FooBar CTF 2022](https://ctftime.org/event/1579)
| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Death-note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/FooBar-CTF-2022/Death-note) | pwn | c (64 bit) | `Use After Free` | `Tcache Attack` `House of Botcake` | Tcache forward pointer changed in libc 2.32 ([source](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2928)) |

[Pragyan CTF 2022](https://ctftime.org/event/1591)
| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Poly-Flow](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/PolyFlow) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [Portal](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/Portal) | pwn | c (64 bit) | `Format String` |  |  |
| [Database](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/database) | pwn | c (64 bit) | `Heap Overflow` | `Tcache Attack` |  |
| [Comeback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/comeback) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [TBBT](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/TBBT) | pwn | c (32 bit) | `Format String` | `Overwrite GOT` |  |

[TSJ CTF 2022](https://ctftime.org/event/1547)
| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [bacteria](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/TSJ-CTF-2022/bacteria) | pwn | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` | r_offset can be any writable and controllable place, don't need to be @got |


**https://mocsctf2022.mocsctf.com/challenges**

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [C@ge](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-Cage) | pwn | c++ (64 bit) | `Heap Overflow` | `Tcache Attack` `Ret2libc` | Use libc environ() to leak stack address |
| [calc](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-calc) | pwn | c (64 bit) | `Buffer Overflow` `Unchecked Index` | `ret2win` |  |
| [orange](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-orange) | pwn | c (64 bit) | `Heap Overflow` | `House of Orange` `Tcache Attack` `Unsorted Bin Attack` | Overwrite malloc hook with realloc and realloc hook with one gadget |

**https://pwnable.tw/**

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Start](https://github.com/nhtri2003gmail/writeup-pwnable.tw-Start) | pwn | c (32 bit) | `Buffer Overflow` `ROP`|

**https://cnsc.uit.edu.vn/ctf/** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/letwarnup) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [Feedback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/feedback) | pwn | c (64 bit) | `Least Significant Byte` |
| [note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/note) | pwn | c (64 bit) | `Heap Attack` `Unsorted Bin Attack` |

**https://pwn.tn/**

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [f_one](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [f_two](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two) | pwn | c (32 bit) | `Buffer Overflow` `Integer Overflow` `Format String` |

**https://www.kcscctf.site/** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [ArrayUnderFl0w](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/ArrayUnderFl0w) | pwn | c | `Unchecked Index` |
| [guessMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/guessMe) | pwn | c | `Specific Seed Rand` |
| [Make Me Crash](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/Make-Me-Crash) | pwn | c | `Buffer Overflow` |
| [Chall](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/Chall) | pwn | c | `Format String` |
| [ret2win](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/ret2win) | pwn | c | `Buffer Overflow` |
| [get OVER InT](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/GET_OVER_InT) | pwn | c | `Integer Overflow` |
| [bof1](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/bof1) | pwn | c | `Buffer Overflow` |

**ISITDTU 2019** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [tokenizer](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/ISITDTU/tokenizer) | pwn | cpp (64 bit) | `Least Significant Byte` |
| [iz_heap_lv1](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/ISITDTU/iz_heap_lv1) | pwn | c (64 bit) | `Heap Attack` `Tcache attack` |

**https://ctf.dicega.ng/**
| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [baby-rop](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DiceCTF-2022/baby-rop) | pwn | c (64 bit) | `Heap Attack` `ROP chaining` |
| [dataeater](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DiceCTF-2022/dataeater) | pwn | c (64 bit) | `ret2dlresolve` `Fake link_map` |

**https://dctf21.cyberedu.ro/**
| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [cache](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DefCamp-CTF-2022/cache) | pwn | c (64 bit) | `Use After Free` `Double Free` `Tcache Attack` `Overwrite GOT` |
| [blindsight](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DefCamp-CTF-2022/blindsight) | pwn | c (64 bit) | `Blind ROP` `Buffer Overflow` |

# Technique ([Table of content](#table-of-content))

| Name | Note |
| :---: | :--- |
| [ret2dlresolve (64 bit)](https://github.com/nhtri2003gmail/CTFNote/tree/master/technique/ret2dlresolve-64bit) | Just input, no output and no output function |
| Heap Exploit | :--- |

# Note ([Table of content](#table-of-content))

#### Execute @plt on stack (BOF):
```
payload = <padding> + <@plt> + <return address> + <arg1> + <arg2>...
```

#### Docker outline

- [Install docker on parrot](https://stackoverflow.com/questions/57025264/installing-docker-on-parrot-os):

```
sudo apt install docker.io
```

- Install [docker-compose](https://docs.docker.com/compose/install/) for convinient command

- Commands:

```
docker-compose build    # Build dockerfile to images
docker-compose up       # Run container
```

#### Attach GDB to running process in docker

To debug a process from docker, add this YAML code to docker-compose.yml, the same wilth `expose` ([source](https://stackoverflow.com/questions/42029834/gdb-in-docker-container-returns-ptrace-operation-not-permitted)):

```
cap_add:
- SYS_PTRACE
```

Because my computer doesn't show pid when running container so I use the following way to debug:

```
import subprocess
from pwn import *

def GDB():
    proc = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
    ps = proc.stdout.read().split(b'\n')
    pid = ''
    for i in ps:
        # Change the recognization here
        if b'/home/bacteria/bacteria' in i and b'timeout' not in i:
            pid = i.split(b'  ')[1].decode()

    # Change command here
    command = '''
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)

    # Need sudo permission
    subprocess.Popen(['sudo', '/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', pid, '-x', '/tmp/command.gdb'])
    input()     # input() to make program wait with gdb

p = connect('127.0.0.1', 9487)
GDB()
```

#### Another version for gdb.attach()

Using [x-terminal-emulator](https://www.systutorials.com/docs/linux/man/1-x-terminal-emulator/) to create popup shell and pass command in a file:

```
import subprocess

def GDB():
    command = '''
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
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

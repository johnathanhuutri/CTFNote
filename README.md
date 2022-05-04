### Table of content
- [Writeup](#writeup-table-of-content)
- [Technique](#technique-table-of-content)
- [Note](#note-table-of-content)

# Writeup ([Table of content](#table-of-content))

<!-- <details>
<summary>By type</summary>
<p>

</p>
</details> -->

<details>
<summary>By event</summary>
<p>

<details>
<summary><h3>KCSC CTF 2022</h3></summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [readOnly](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/readOnly) | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` |  |
| [start](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/start) | c (64 bit) | `Buffer Overflow` | `SROP` |  |
| [feedback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/feedback) | c (64 bit) | `Integer Overflow` `Buffer Overflow` | `SROP` |  |
| [guess2pwn](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/guess2pwn) | c++ (64 bit) |  |  | First byte from `urandom` may be null |
| [pwnMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/pwnMe) | c (64 bit) | `Format String` | `Ret2libc` |  |
| [babyheap](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/babyheap) | c (64 bit) | `Use After Free` `Heap Overflow` |  |  |
| [5ecretN0te](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/5ecretN0te) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

</p>
</details>

[Wolverine Security Conference/CTF](https://ctftime.org/event/1612)
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Us3_th3_F0rc3](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Wolverine-Security-Conference-CTF/Us3_th3_F0rc3) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

[zer0pts CTF 2022](https://ctftime.org/event/1555)
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Modern Rome](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/zer0pts-CTF-2022/Modern-Rome) | c++ (64 bit) | `Integer Overflow` |  |  |
| [accountant](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/zer0pts-CTF-2022/accountant) | c (64 bit) | `Integer Overflow` | `ret2libc` | If register (rax, rbx, rcx...) contain `0x10000000000000000` (9 bytes in total), the most significant byte will be remove (the 0x1 will be remove) and make register to null again |

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
| [Start](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/pwnable.tw/Start) | pwn | c (32 bit) | `Buffer Overflow` `ROP`|

**https://cnsc.uit.edu.vn/ctf/** (Connection closed)

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/letwarnup) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [Feedback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/feedback) | pwn | c (64 bit) | `Least Significant Byte` |
| [note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/note) | pwn | c (64 bit) | `Heap Attack` `Unsorted Bin Attack` |

**https://pwn.tn/**

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [f_one](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwn.tn/f_one) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [f_two](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwn.tn/f_two) | pwn | c (32 bit) | `Buffer Overflow` `Integer Overflow` `Format String` |

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

</p>
</details>

# Technique ([Table of content](#table-of-content))

| Name | Note |
| :---: | :--- |
| [Ret2dlresolve (64 bit)](https://github.com/nhtri2003gmail/CTFNote/tree/master/technique/Ret2dlresolve-64bit) | Just input, no output and no output function |
| [Heap Exploit](https://github.com/nhtri2003gmail/CTFNote/tree/master/technique/Heap-Exploitation) | Just notes. For a full technique, please visit [this page](https://github.com/shellphish/how2heap) |

# Note ([Table of content](#table-of-content))

### Execute @plt on stack (BOF):

- 32 bit:
```
payload = b'A'*<x>        # Padding
payload += p32(<@plt> / libc.sym['<function name>'])
payload += p32(<return address>)
payload += p32(<arg1>)
payload += p32(<arg2>)
...
```

- 64 bit:
```
payload = b'A'*<x>             # Padding
payload += p64(pop_rdi)
payload += p64(<arg1>)
payload += p64(pop_rsi_r15)
payload += p64(<arg2>)
payload += p64(<any byte>)
payload += p64(@plt / libc.sym['<function name>'])
payload += p32(<return address>)
```

---

### Docker outline

Install [docker](https://stackoverflow.com/questions/57025264/installing-docker-on-parrot-os) on parrot:

```
sudo apt install docker.io
```

Install [docker-compose](https://docs.docker.com/compose/install/) for convinient command

---

### Attach GDB to running process in docker

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

---

### Another version for gdb.attach()

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

---

### Load libc in python

```python
from ctypes import*

# Load glibc chạy chung với chương trình
glibc = cdll.LoadLibrary('./libc6_2.27-3ubuntu1.4_amd64.so')

# Tạo seed rand với seed bằng time(null)
glibc.srand(glibc.time(None))

# Lấy giá trị random
val = glibc.rand()

print(hex(val))
```

---

### pwntools  

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

```
from pwn import *

# print(args.<ANY NAME IN CAPITAL>)
print(args.MYNAME)
print(args.MYAGE)
```
--> `python run.py MYNAME=Johnathan MYAGE=20`

- [Core](https://docs.pwntools.com/en/stable/elf/corefile.html) file:

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

---

### Get [opcode](https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump) from binary

```
objdump -d <Name of program>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

---

### gdb

- `r < <()` can pass null byte, `r <<<$()` cannot.

- `flag +/-ZERO` to set or remove flag.

---

### movaps xmm0,... 

- rsp (esp) address must end with byte 0x00, 0x10, 0x20, 0x30... or it will cause error.</br>
Ex: if rsp address end with 0xe8 --> segfault.

---

### format string 

- `%p%p%p%n` will write and access easily.
- `%4$n` will write but cannot access.
- Payload should have `%c` instead `%x` to make sure it write a byte, **not** a random byte on stack.
- Enter `.` to `scanf()` with number format (`%d`, `%u`, `%ld`...) won't enter new value to var.
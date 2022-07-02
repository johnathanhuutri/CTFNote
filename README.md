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
<summary><h3>By event</h3></summary>
<p>

<details>
<summary>WhiteHat Play 11</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [pwn06-Ez_fmt](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/WhiteHat-Play-11/pwn06-Ez_fmt) | c (64 bit) | `Format String` |  | `%n` and `%p` (or `%s`) can be used at the same time just in case `%n` in clear form and `%p` (or `%s`) can be in short form. Ex: `%c%c%n%3$p` |
| [pwn07-Silence](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/WhiteHat-Play-11/pwn07-Silence) | c (64 bit) | `Buffer Overflow` |  | Due to the close of stdout and stderr, we can send data via stdin so we will use `getdents` syscall to get file name and print the flag through stdin </br> Or we can `dup2()` to reopen stdout and stderr, and get shell </br> Or just get the shell as normal but without anything to be printed. And when we get the shell, type `exec 1>&0` and everything from stdout will be redirected to stdin. Hence, we get a normal shell. |
| [pwn08-Ruby](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/WhiteHat-Play-11/pwn08-Ruby) | c (64 bit) | `Integer Overflow` |  | Attacking tcache_perthread_struct by freeing fake chunk which has size of `0x10000` and this size is inside tcache_perthread_struct |


</p>
</details>

<details>
<summary>KMACTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Duet](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KMACTF-2022/Duet) | c (64 bit) | `Buffer Overflow` | `Ret2Shellcode` | Shellcode (32 bit) can be executed on 64 bit binary and argument when execute `int 0x80` will be eax, ebx, ecx, edx... |
| [Two Shot](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KMACTF-2022/TwoShot) | c (64 bit) | `Buffer Overflow` `Format String` | `Ret2libc` |  |


</p>
</details>

<details>
<summary>HCMUS CTF 2022</summary>
<p>

### Quals
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [PrintMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Quals/PrintMe) |  |  |  |  |
| [Timehash - rev](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Quals/Timehash) | c (64 bit) |  |  | Patch file |
| [WWW](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Quals/WWW) | c (64 bit) | `Format String` | `Overwrite GOT` |  |

### Final
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [calert](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Final/calert) | c (64 bit) | `Integer Overflow` `Buffer Overflow` | `Ret2libc` | We can change original canary if we know its address which is not in range of libc nor ld |

</p>
</details>

<details>
<summary><a href="http://kcscctf.site/">KCSC CTF 2022</a></summary>
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

<details>
<summary><a href="https://ctftime.org/event/1612">Wolverine Security Conference/CTF</a></summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Us3_th3_F0rc3](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Wolverine-Security-Conference-CTF/Us3_th3_F0rc3) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1555">zer0pts CTF 2022</a></summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Modern Rome](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/zer0pts-CTF-2022/Modern-Rome) | c++ (64 bit) | `Integer Overflow` |  |  |
| [accountant](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/zer0pts-CTF-2022/accountant) | c (64 bit) | `Integer Overflow` | `ret2libc` | If register (rax, rbx, rcx...) contain `0x10000000000000000` (9 bytes in total), the most significant byte will be remove (the 0x1 will be remove) and make register to null again |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1579">FooBar CTF 2022</a></summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Death-note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/FooBar-CTF-2022/Death-note) | pwn | c (64 bit) | `Use After Free` | `Tcache Attack` `House of Botcake` | Tcache forward pointer changed in libc 2.32 ([source](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2928)) |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1591">Pragyan CTF 2022</a></summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Poly-Flow](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/PolyFlow) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [Portal](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/Portal) | pwn | c (64 bit) | `Format String` |  |  |
| [Database](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/database) | pwn | c (64 bit) | `Heap Overflow` | `Tcache Attack` |  |
| [Comeback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/comeback) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [TBBT](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/TBBT) | pwn | c (32 bit) | `Format String` | `Overwrite GOT` |  |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1547">TSJ CTF 2022</a></summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [bacteria](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/TSJ-CTF-2022/bacteria) | pwn | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` | r_offset can be any writable and controllable place, don't need to be @got |

</p>
</details>

<details>
<summary><a href="#">MOCSCTF 2022</a></summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [C@ge](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-Cage) | pwn | c++ (64 bit) | `Heap Overflow` | `Tcache Attack` `Ret2libc` | Use libc environ() to leak stack address |
| [calc](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-calc) | pwn | c (64 bit) | `Buffer Overflow` `Unchecked Index` | `ret2win` |  |
| [orange](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-orange) | pwn | c (64 bit) | `Heap Overflow` | `House of Orange` `Tcache Attack` `Unsorted Bin Attack` | Overwrite malloc hook with realloc and realloc hook with one gadget |

</p>
</details>

<details>
<summary><a href="https://pwnable.tw/">pwnable.tw</a></summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Start](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/Start) | c (32 bit) | `Buffer Overflow` | `ROPchain` `Shellcode` |  |
| [orw](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/orw) | c (32 bit) |  | `Shellcode` |  |
| [calc](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/calc) | c (32 bit) |  | `ROPchain` |  |
| [3x17](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/3x17) | c (64 bit) |  | `ROPchain` | Attack by overwriting `.fini_array` |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1591">Wanna Game 2022</a></summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/letwarnup) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [Feedback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/feedback) | pwn | c (64 bit) | `Least Significant Byte` |
| [note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/note) | pwn | c (64 bit) | `Heap Attack` `Unsorted Bin Attack` |

</p>
</details>

<details>
<summary><a href="https://pwn.tn/">pwn.tn</a></summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [f_one](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwn.tn/f_one) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [f_two](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwn.tn/f_two) | pwn | c (32 bit) | `Buffer Overflow` `Integer Overflow` `Format String` |

</p>
</details>

<details>
<summary><a href="http://kcscctf.site/">KCSC - Entrance exam</a></summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [ArrayUnderFl0w](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/ArrayUnderFl0w) | pwn | c | `Unchecked Index` |
| [guessMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/guessMe) | pwn | c | `Specific Seed Rand` |
| [Make Me Crash](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/Make-Me-Crash) | pwn | c | `Buffer Overflow` |
| [Chall](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/Chall) | pwn | c | `Format String` |
| [ret2win](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/ret2win) | pwn | c | `Buffer Overflow` |
| [get OVER InT](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/GET_OVER_InT) | pwn | c | `Integer Overflow` |
| [bof1](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/bof1) | pwn | c | `Buffer Overflow` |

</p>
</details>

<details>
<summary><a href="#">ISITDTU 2019</a></summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [tokenizer](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/ISITDTU/tokenizer) | pwn | cpp (64 bit) | `Least Significant Byte` |
| [iz_heap_lv1](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/ISITDTU/iz_heap_lv1) | pwn | c (64 bit) | `Heap Attack` `Tcache attack` |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1541">DiceCTF 2022</a></summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [baby-rop](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DiceCTF-2022/baby-rop) | pwn | c (64 bit) | `Heap Attack` `ROP chaining` |
| [dataeater](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DiceCTF-2022/dataeater) | pwn | c (64 bit) | `ret2dlresolve` `Fake link_map` |

</p>
</details>

<details>
<summary><a href="https://ctftime.org/event/1560">DefCamp CTF 21-22 Online</a></summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [cache](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DefCamp-CTF-2022/cache) | pwn | c (64 bit) | `Use After Free` `Double Free` `Tcache Attack` `Overwrite GOT` |
| [blindsight](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DefCamp-CTF-2022/blindsight) | pwn | c (64 bit) | `Blind ROP` `Buffer Overflow` |

</p>
</details>

<details id="svattt-2019">
<summary><a href="#user-content-svattt-2019">SVATTT 2019</a></summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [three_o_three](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/SVATTT2019/three_o_three) | c (64 bit) | `Unlimited malloc size` | `FILE structure attack` | Malloc with size larger than heap size make the chunk near libc ; `Scanf` flow: `__uflow` -> `_IO_file_underflow` -> `read` 1 byte until meet `\n` |

</p>
</details>

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
# Intel debug
import subprocess

def GDB(command=''):
    if not command:
        command = '''
        '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    # subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+0+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb
```



```
# Arm debug
def GDB(filename, port):
    q = process(f"/usr/bin/x-terminal-emulator --geometry 960x1080+960+0 -x gdb-multiarch -q --nh -ex 'source ~/.gef-283690ae9bfcecbb3deb80cd275d327c46b276b5.py' -ex 'set architecture arm64' -ex 'file {filename}' -ex 'target remote localhost:{port}'", shell=True)

port = 1234
filename = ''

p = process(f'qemu-aarch64 -L /usr/aarch64-linux-gnu -g {port} {filename}}'.split())
GDB('cli', port)
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
- `%*` works as `%d` and will print first 4 bytes
- `%*<k>$` works as `%<k>$d`
- `%*<k>$c` will be the pad of ` ` with the size that `%<k>c` point to
- `%.*<k>$c` will be the pad of `0` with the size that `%<k>$c` point to
- Format string can be use to modify and read data at the same time just in case you don't use the short format (`%<k>$c`), use the plain format instead (`%p`, `%n`, `%s`, `%c`).
    - Example: `%c%c%c%c%1234c%hn%6$s` to change address and read from that changed address
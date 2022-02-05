# Writeup

**https://cnsc.uit.edu.vn/ctf/** (Connection closed)

1. Letwarnu: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup]()

2. Feedback: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback]()

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup) | pwn | c | `Format String` `Overwrite GOT` |
| [Feedback](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback) | pwn | c | `Least Significant Byte` |
| [note](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-note) | pwn | c | `Heap Attack` `Unsorted Bin Attack` |

**https://pwn.tn/**

1. f_one: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one)

2. f_two: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two)

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
| [tokenizer](https://github.com/nhtri2003gmail/writeup-ISITDTU2019-tokenizer) | pwn | cpp | `Least Significant Byte` |
| [iz_heap_lv1](https://github.com/nhtri2003gmail/writeup-ISITDTU2019-iz_heap_lv1) | pwn | c | `Heap Attack` `Tcache attack` |
|  |  |  |  |
|  |  |  |  |


# Modules

#### Execute @plt on stack (BOF):
```
payload = <padding> + <@plt> + <return address> + <arg1> + <arg2>...
```

# Note

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

#### assembly opcode

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

# Writeup

**https://cnsc.uit.edu.vn/ctf/** (Connection closed)

1. Letwarnme: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup)

2. Feedback: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback)

**https://pwn.tn/**

1. f_one: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one)

2. f_two: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two)

**https://www.kcscctf.site/** (Connection closed)

| Name | Type | Module |
| :---: | :---: | :---: |
| [ArrayUnderFl0w](https://github.com/nhtri2003gmail/writeup-kcscctf.site-ArrayUnderFl0w) | pwn | Unknow |
| [guessMe](https://github.com/nhtri2003gmail/writeup-kcscctf.site-guessMe) | pwn |  |
| [Make Me Crash](https://github.com/nhtri2003gmail/writeup-kcscctf.site-Make_Me_Crash) | pwn ||
| [Chall](https://github.com/nhtri2003gmail/writeup-kcscctf.site-Chall) | pwn |  |
| [ret2win](https://github.com/nhtri2003gmail/writeup-kcscctf.site-ret2win) | pwn |  |
| [get OVER InT](https://github.com/nhtri2003gmail/writeup-kcscctf.site-get_OVER_InT) | pwn |  |
| [bof1](https://github.com/nhtri2003gmail/writeup-kcscctf.site-bof1) | pwn |  |
# Modules

#### Execute @plt on stack (BOF):
```
payload = <padding> + <@plt> + <return address> + <arg1> + <arg2>...
```

# Note

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

# Writeup

**https://cnsc.uit.edu.vn/ctf/** (Connection closed, cannot connect)

1. Letwarnme: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup)

2. Feedback: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback)

**https://pwn.tn/**

1. f_one: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one)

2. f_two: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two)

# Modules

### Execute @plt on stack (BOF):
```
payload = <padding> + <@plt> + <return address> + <arg1> + <arg2>...
```

# Note

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

### assembly opcode
```
objdump -d <Name of program>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

### gdb
- `r < <()` can pass null byte, `r <<<$()` cannot.
- `flag +/-ZERO` to set or remove flag.

### movaps xmm0,... 
- rsp (esp) address must end with byte 0x00, 0x10, 0x20, 0x30... or it will cause error.</br>
Ex: if rsp address end with 0xe8 --> segfault.

### format string 
- `%p%p%p%n` will write and access easily.
- `%4$n` will write but cannot access.
- Payload should have `%c` instead `%x` to make sure it write a byte, **not** a random byte on stack.
- Enter `.` to skip input of `scanf("%lf", &var)`

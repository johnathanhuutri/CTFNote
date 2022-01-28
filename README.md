# Writeup

**https://cnsc.uit.edu.vn/ctf/** (Connection closed, cannot connect)

1. Letwarnme: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-letwarnup)

2. Feedback: [https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback](https://github.com/nhtri2003gmail/writeup-cnsc.uit.edu.vn-feedback)

**https://pwn.tn/**

1. f_one: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_one)

2. f_two: [https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two](https://github.com/nhtri2003gmail/writeup-pwn.tn-f_two)

# Note

# 

--- pwntools --- 
- Get child pid: 
import os
from pwn import *

pwnlib.util.proc.children(os.getpid())

##### assembly opcode #####
objdump -d "$1"|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

### gdb  ###########################################
- "r < <()" can pass null byte, "r <<<$()" cannot
- "flag +/-ZERO" to set or remove flag
 
### movaps xmm0,... #####################################
- rsp (esp) address must end with byte 0x00, 0x10, 0x20, 0x30...
- ex: if rsp address end with 0xe8 --> segfault

### format string #######################################
- %p%p%p%n will write and access easily
- %4$n will write but cannot access

- %c instead %x to make sure it write a byte, not a random byte

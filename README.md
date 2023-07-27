# Technique ([Table of content](#table-of-content))

| Name | Note |
| :---: | :--- |
| [Ret2dlresolve (64 bit)](Ret2dlresolve-64bit) | Just input, no output and no output function |
| [Heap Exploit](Heap-Exploitation) | Just notes. For a full technique, please visit [this page](https://github.com/shellphish/how2heap) |

# Note ([Table of content](#table-of-content))

<details>
<summary><h3>Execute @plt on stack (BOF)</h3></summary>
<p>

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
payload += p64(<any byte>)     # Padding
payload += p64(@plt / libc.sym['<function name>'])
payload += p32(<return address>)
```

</p>
</details>

<details>
<summary><h3>Docker installation</h3></summary>
<p>

Install [docker](https://stackoverflow.com/questions/57025264/installing-docker-on-parrot-os) on parrot:

```
sudo apt install docker.io
```

Install [docker-compose](https://docs.docker.com/compose/install/linux/) for convinient command. If you get errot `Unable to locate package docker-compose-plugin`, please read [this blog](https://dothanhlong.org/cai-docker-compose-tren-ubuntu-linux/) to install another way

</p>
</details>

<details>
<summary><h3>GDB Attach</h3></summary>
<p>

Using [x-terminal-emulator](https://www.systutorials.com/docs/linux/man/1-x-terminal-emulator/) to create popup shell and pass command in a file.

### Intel debug

```python
def GDB():     # *NIX machine
    command = '''
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()
```

```python
def GDB():     # Wsl2
    import os
    script = '''
    #!/bin/sh

    cd <Path_to_folder_contain_running_binary>
    '''
    script += f'gdb -p {p.pid} -x /tmp/command.gdb'
    with open('/tmp/script.sh', 'w') as f: f.write(script)
    os.system("chmod +x /tmp/script.sh")

    command = '''
    '''
    with open('/tmp/command.gdb', 'w') as f: f.write(command)
    q = process(f'cmd.exe /c start C:\\Windows\\system32\\wsl.exe /tmp/script.sh'.split())
    input()
```

### Arm debug

```python
def GDB(filename, port):
    q = process(f"/usr/bin/x-terminal-emulator --geometry 960x1080+960+0 -x gdb-multiarch -q --nh -ex 'source ~/.gef-283690ae9bfcecbb3deb80cd275d327c46b276b5.py' -ex 'set architecture arm64' -ex 'file {filename}' -ex 'target remote localhost:{port}'", shell=True)


port = 1234
filename = ''
p = process(f'qemu-aarch64 -L /usr/aarch64-linux-gnu -g {port} {filename}'.split())
GDB(filename, port)
```

### Kernel debug (add before qemu command, add `-s` to qemu, using wsl2 ubuntu 20.04)

```bash
command="-nx"
command="${command} -ex 'set disassembly-flavor intel'"
command="${command} -ex 'set pagination off'"
command="${command} -ex 'set confirm off'"
command="${command} -ex 'target remote localhost:1234'"
command="${command} -ex 'display/x \$rax'"
command="${command} -ex 'display/x \$rbx'"
command="${command} -ex 'display/x \$rcx'"
command="${command} -ex 'display/x \$rdx'"
command="${command} -ex 'display/x \$rdi'"
command="${command} -ex 'display/x \$rsi'"
command="${command} -ex 'display/x \$rbp'"
command="${command} -ex 'display/x \$rsp'"
command="${command} -ex 'display/x \$r8'"
command="${command} -ex 'display/x \$r9'"
command="${command} -ex 'display/x \$r10'"
command="${command} -ex 'display/x \$r11'"
command="${command} -ex 'display/x \$r12'"
command="${command} -ex 'display/x \$r13'"
command="${command} -ex 'display/x \$r14'"
command="${command} -ex 'display/x \$r15'"
command="${command} -ex 'display/10i \$rip'"
command="${command} -ex '<addcommandhere>'"
cmd.exe /c "start <wsl2filename> run gdb $command" &
```

### Debug docker process

To debug a process from docker, add this YAML code to docker-compose.yml, the same wilth `expose` ([source](https://stackoverflow.com/questions/42029834/gdb-in-docker-container-returns-ptrace-operation-not-permitted)):

```
cap_add:
- SYS_PTRACE
```

Because my computer doesn't show pid when running container so I use the following way to debug:

```python
import subprocess
from pwn import *

def GDB():
    proc = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
    ps = proc.stdout.read().split(b'\n')
    pid = ''
    for i in ps:
        # Change the recognization here
        if b'/home/bacteria/bacteria' in i and b'timeout' not in i:
            pid = i.split()[1].decode()

    # Change command here
    command = '''
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)

    # Need sudo permission
    subprocess.Popen(['sudo', '/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', pid, '-x', '/tmp/command.gdb'])
    input()     # input() to make program wait with gdb
```

</p>
</details>

<details>
<summary><h3>GDB tips</h3></summary>
<p>

### Show data when stop

You can read [this blog](https://www.cse.unsw.edu.au/~learn/debugging/modules/gdb_watch_display/) for example.

- watch

```gdb
(gdb) watch <variable_name>
(gdb) info breakpoints    # Viewing both breakpoint and watchpoint
(gdb) disable <watchpoint_number>
```

- display

```gdb
# display <expression/variable_name>
(gdb) display $rax

# display/fmt <expression/variable_name>
(gdb) display/x $rax    # display as hex format

# info display
# delete display <display_number>
(gdb) delete display 1
```

### Disable "Type return to continue..."

I got it from https://stackoverflow.com/questions/28815621/how-to-disable-type-return-to-continue-or-q-return-to-quit-in-gdb

```
(gdb) set pagination off
```

### Disable "Quit anyway?..."

I got it from https://stackoverflow.com/questions/4355978/get-rid-of-quit-anyway-prompt-using-gdb-just-kill-the-process-and-quit

```
(gdb) set confirm off
```

### Other tips

- `r < <()` can input null byte, `r <<<$()` cannot.

- `flag +/-ZERO` to set or remove flag.

</p>
</details>

<details>
<summary><h3>Load libc in python</h3></summary>
<p>

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

</p>
</details>

<details>
<summary><h3>Core dump</h3></summary>
<p>

To check if core dump is enable or not, run `ulimit -a` and check the line `-c: core file size`

![](images/ulimit-show.png)

String `unlimited` is what we want. If it's not that string, you will want to change back to unlimited with this command:

```bash
ulimit -c unlimited
```

But that is just ulimit soft, which means ulimit just affect current session, current terminal, not the next time. If you want to set it hard, you would like to edit the file `/etc/security/limits.conf` by adding the following line with chosen user:

```
<user>      hard    core        ulimited
```

Now the core dump will be generated when a program get segfault. If you want to know where the core file is saved, run this command to show the default core place:

```bash
cat /proc/sys/kernel/core_pattern
```

Want to debug with that core file? Run these commands:

```bash
gdb <executable file>
...
(gdb) core <core-file>
```

Most useful commands are:

- `bt` (backtrace)
- `info locals` (show values of local variables)
- `info registers` (show values of local variables)
- `frame X` (show values of local variables)
- `up` and `down` (navigate in the stack frame (call chain))

If you want to analyze core file with pwntools, see the session [pwntools](https://github.com/nhtri2003gmail/CTFNote#pwntools) below.

**Reference:**

- https://stackoverflow.com/a/54943610
- https://linuxhint.com/increase-open-file-limit-ubuntu/

</p>
</details>

<details>
<summary><h3>pwntools</h3></summary>
<p>

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

</p>
</details>

<details>
<summary><h3>Ascii shellcode</h3></summary>
<p>

https://blackcloud.me/Linux-shellcode-alphanumeric/

https://nets.ec/Ascii_shellcode

https://github.com/VincentDary/PolyAsciiShellGen

Some special assembly code:

```as
34 30                   xor    al,0x30                : ✓
80 f3 30                xor    bl,0x30                : ✘
80 f1 30                xor    cl,0x30                : ✘
80 f2 30                xor    dl,0x30                : ✘

66 35 30 30             xor    ax,0x3030              : ✓
66 81 f3 30 30          xor    bx,0x3030              : ✘
66 81 f1 30 30          xor    cx,0x3030              : ✘
66 81 f2 30 30          xor    dx,0x3030              : ✘

31 58 20                xor    [eax+0x20],ebx         : ✓
66 31 58 20             xor    [eax+0x20],bx          : ✓
30 78 20                xor    [eax+0x20],bh          : ✓
30 58 20                xor    [eax+0x20],bl          : ✓

You can change between eax, ebx, ecx or edx for both 2 operands for 4 instruction above.

31 44 24 40             xor    [esp+0x40],eax         : ✓ / ✘ (depends)
66 31 44 24 40          xor    [esp+0x40],ax          : ✓ / ✘ (depends)
30 64 24 40             xor    [esp+0x40],ah          : ✓ / ✘ (depends)
30 44 24 40             xor    [esp+0x40],al          : ✓ / ✘ (depends)

6a 30                   push   0x30                   : ✓
68 31 30 00 00          push   0x3031                 : ✓
68 32 31 30 00          push   0x303132               : ✓
68 33 32 31 30          push   0x30313233             : ✓
```

</p>
</details>

<details>
<summary><h3>Odd shellcode</h3></summary>
<p>

https://ctftime.org/writeup/34832

https://marcosvalle.github.io/re/exploit/2018/09/02/odd-even-encoder.html

Some special assembly code:

```as
35 31 31 31 31          xor    eax,0x31313131
81 f3 31 31 31 31       xor    ebx,0x31313131
81 f1 31 31 31 31       xor    ecx,0x31313131
81 f7 31 31 31 31       xor    edi,0x31313131
81 f5 31 31 31 31       xor    ebp,0x31313131
49 81 f1 31 31 31 31    xor    r9, 0x31313131
49 81 f3 31 31 31 31    xor    r11,0x31313131
49 81 f5 31 31 31 31    xor    r13,0x31313131
49 81 f7 31 31 31 31    xor    r15,0x31313131
35 ab ab ab ab          xor    eax,0xabababab
81 f3 ab ab ab ab       xor    ebx,0xabababab
81 f1 ab ab ab ab       xor    ecx,0xabababab
81 f7 ab ab ab ab       xor    edi,0xabababab
81 f5 ab ab ab ab       xor    ebp,0xabababab
83 f3 33                xor    ebx,0x33
83 f1 33                xor    ecx,0x33
83 f7 31                xor    edi,0x31
83 f5 31                xor    ebp,0x31
49 83 f1 31             xor    r9, 0x31
49 83 f3 31             xor    r11,0x31
49 83 f5 31             xor    r13,0x31
49 83 f7 31             xor    r15,0x31

67 31 43 31             xor    DWORD PTR [ebx+0x31],eax
67 31 4b 31             xor    DWORD PTR [ebx+0x31],ecx
67 31 53 31             xor    DWORD PTR [ebx+0x31],edx
67 31 41 31             xor    DWORD PTR [ecx+0x31],eax
67 31 59 31             xor    DWORD PTR [ecx+0x31],ebx
67 31 51 31             xor    DWORD PTR [ecx+0x31],edx

31 c3                   xor    ebx,eax
31 db                   xor    ebx,ebx
31 cb                   xor    ebx,ecx
31 d3                   xor    ebx,edx
31 c1                   xor    ecx,eax
31 d9                   xor    ecx,ebx
31 c9                   xor    ecx,ecx
31 d1                   xor    ecx,edx
31 c7                   xor    edi,eax
31 df                   xor    edi,ebx
31 cf                   xor    edi,ecx
31 d7                   xor    edi,edx
49 31 e1                xor    r9,rsp
49 31 e3                xor    r11,rsp
49 31 e5                xor    r13,rsp
49 31 e7                xor    r15,rsp

93                      xchg   ebx,eax
87 cb                   xchg   ebx,ecx
87 db                   xchg   ebx,ebx
87 d3                   xchg   ebx,edx
91                      xchg   ecx,eax
87 d9                   xchg   ecx,ebx
87 c9                   xchg   ecx,ecx
87 d1                   xchg   ecx,edx
97                      xchg   edi,eax
87 df                   xchg   edi,ebx
87 cf                   xchg   edi,ecx
87 d7                   xchg   edi,edx

49 91                   xchg   rax,r9
49 93                   xchg   rax,r11
49 95                   xchg   rax,r13
49 97                   xchg   rax,r15
49 87 d9                xchg   r9,rbx
49 87 c9                xchg   r9,rcx
49 87 d1                xchg   r9,rdx
49 87 f1                xchg   r9,rsi
49 87 f9                xchg   r9,rdi
49 87 e9                xchg   r9,rbp
49 87 e1                xchg   r9,rsp
4d 87 c1                xchg   r9,r8
4d 87 c9                xchg   r9,r9
4d 87 d1                xchg   r9,r10
4d 87 d9                xchg   r9,r11
4d 87 e1                xchg   r9,r12
4d 87 e9                xchg   r9,r13
4d 87 f1                xchg   r9,r14
4d 87 f9                xchg   r9,r15

49 8d 01                lea    rax,[r9]
49 8d 03                lea    rax,[r11]
49 8d 07                lea    rax,[r15]
49 8d 19                lea    rbx,[r9]
49 8d 1b                lea    rbx,[r11]
49 8d 1f                lea    rbx,[r15]
49 8d 09                lea    rcx,[r9]
49 8d 0b                lea    rcx,[r11]
49 8d 0f                lea    rcx,[r15]
49 8d 11                lea    rdx,[r9]
49 8d 13                lea    rdx,[r11]
49 8d 17                lea    rdx,[r15]
49 8d 39                lea    rdi,[r9]
49 8d 3b                lea    rdi,[r11]
49 8d 3f                lea    rdi,[r15]
49 8d 31                lea    rsi,[r9]
49 8d 33                lea    rsi,[r11]
49 8d 37                lea    rsi,[r15]

ff c3                   inc    ebx
ff c1                   inc    ecx
ff c7                   inc    edi
ff c5                   inc    ebp
49 ff c1                inc    r9
49 ff c3                inc    r11
49 ff c5                inc    r13
49 ff c7                inc    r13

ff cb                   dec    ebx
ff c9                   dec    ecx
ff cf                   dec    edi
ff cd                   dec    ebp
49 ff c9                dec    r9
49 ff cb                dec    r11
49 ff cd                dec    r13
49 ff cf                dec    r13

89 c3                   mov    ebx,eax
89 cb                   mov    ebx,ecx
89 d3                   mov    ebx,edx
89 c1                   mov    ecx,eax
89 d9                   mov    ecx,ebx
89 d1                   mov    ecx,edx
bb 33 33 33 33          mov    ebx,0x33333333
b3 37                   mov    bl,0x37
b7 39                   mov    bh,0x39
b9 33 33 33 33          mov    ecx,0x33333333
b1 37                   mov    cl,0x37
b5 39                   mov    ch,0x39

53                      push   rbx
51                      push   rcx
57                      push   rdi
5b                      pop    rbx
59                      pop    rcx
5f                      pop    rdi

c3                      ret
c9                      leave

0f 05                   syscall
```

</p>
</details>

<details>
<summary><h3>Get <a href="https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump">opcode</a> from binary</h3></summary>
<p>

```
objdump -d <Name of program>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

</p>
</details>

<details>
<summary><h3>movaps xmm0,... </h3></summary>
<p>

- rsp (esp) address must end with byte 0x00, 0x10, 0x20, 0x30... or it will cause error.</br>
Ex: if rsp address end with 0xe8 --> segfault.

</p>
</details>

<details>
<summary><h3>format string </h3></summary>
<p>

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

</p>
</details>

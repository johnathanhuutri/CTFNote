# Technique

| Name | Note |
| :---: | :--- |
| [Ret2dlresolve (64 bit)](Ret2dlresolve-64bit) | Just input, no output and no output function |
| [Heap Exploit](Heap-Exploitation) | Just notes. For a full technique, please visit [this page](https://github.com/shellphish/how2heap) |

# Note

<details>
<summary><h2>genscr</h2></summary>
<p>

```python
#!/usr/bin/python3

import sys, os

script = f'''#!/usr/bin/env python3

from pwn import *

# exe = ELF('', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=\'\'\'


        c
        \'\'\')
        input()


if args.REMOTE:
    p = remote('')
else:
    {('p = process([exe.path])') if len(sys.argv) >= 2 else ("p = process([''])")}
GDB()



p.interactive()
'''

if os.path.exists('exp.py'):
    script = open('exp.py', 'r').read()

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} BIN [LIBC]")
    print(f"Example:")
    print(f"    {sys.argv[0]} ./chall")
    print(f"    {sys.argv[0]} ./chall ./libc.so.6")
    exit(0)
if len(sys.argv) > 1:
    os.system('chmod +x ' + sys.argv[1])
    script = script.replace("# exe = ELF('', checksec=False)", f"exe = ELF('{sys.argv[1]}', checksec=False)")
if len(sys.argv) > 2:
    os.system('chmod +x ' + sys.argv[2])
    script = script.replace("# libc = ELF('', checksec=False)", f"libc = ELF('{sys.argv[2]}', checksec=False)")

with open('exp.py', 'wt') as f:
    f.write(script)

os.chmod('exp.py', 0o755)
os.system('subl exp.py &')
```

Copy this script and write it into `/usr/local/bin/genscr`, then `chmod +x /usr/local/bin/genscr` and you can use it!

</p>

</details>

<details>
<summary><h2>Execute @plt on stack (BOF)</h2></summary>
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
<summary><h2>Docker installation</h2></summary>
<p>

**Official Method**

https://docs.docker.com/engine/install/ubuntu/

**Another Method (old)**

Install [docker](https://stackoverflow.com/questions/57025264/installing-docker-on-parrot-os) on parrot:

```
sudo apt install docker.io
```

Install [docker-compose](https://docs.docker.com/compose/install/linux/) for convinient command. If you get errot `Unable to locate package docker-compose-plugin`, please read [this blog](https://dothanhlong.org/cai-docker-compose-tren-ubuntu-linux/) to install another way

</p>
</details>

<details>
<summary><h2>GDB Attach</h2></summary>
<p>

Using [x-terminal-emulator](https://www.systutorials.com/docs/linux/man/1-x-terminal-emulator/) to create popup shell and pass command in a file.

### Intel debug

- *NIX
```python
def GDB():
    # import clipboard
    # clipboard.copy()
    if not args.REMOTE:
        command = '''
        '''
        with open('/tmp/command.gdb', 'wt') as f:
            f.write(command)
        subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
        input()
```

- WSL2
```python
def GDB():
    # import clipboard
    # clipboard.copy()
    if not args.REMOTE:
        import os
        gdb_script = '''

        c
        '''
        open('/tmp/command.gdb', 'w').write(gdb_script)

        bash_script = '#!/bin/sh\n'
        bash_script += '\n'
        bash_script += f'cd {Path_to_folder_contain_running_binary}\n'
        bash_script += f'gdb -p {p.pid} -x /tmp/command.gdb\n'
        open('/tmp/script.sh', 'w').write(bash_script)

        os.system("chmod +x /tmp/script.sh")
        os.system(r'cmd.exe /c start wsl.exe -d Ubuntu-22.04 bash -c /tmp/script.sh')
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
<summary><h2>GDB Tips</h2></summary>
<p>

**1. Show data when stop**

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

**2. Disable "Type return to continue..."**
```
(gdb) set pagination off
```

References:
- https://stackoverflow.com/questions/28815621/how-to-disable-type-return-to-continue-or-q-return-to-quit-in-gdb

**3. Disable "Quit anyway?..."**

```
(gdb) set confirm off
```
References
- https://stackoverflow.com/questions/4355978/get-rid-of-quit-anyway-prompt-using-gdb-just-kill-the-process-and-quit

**4. Reload libc symbol**

```gdb
set solib-search-path <path>
```

When run that command with the `<path>` is where the libc (which has symbol) is stored. For example, if the libc is in `/home/user/test` but the gdb path is `/mnt/d/wsl2` and libc doesn't show any symbols, we can run:

```gdb
set solib-search-path /home/user/test
```

The symbol will be loaded!

References
- http://www.qnx.com/developers/docs/qnxcar2/index.jsp?topic=%2Fcom.qnx.doc.neutrino.prog%2Ftopic%2Fusing_gdb_SharedLibraries.html

**5. Custom GDB command**

You can create custom function in GDB with command `define`. For example:

```python
pwndbg> define custom_print
Type commands for definition of "custom_print".
End with a line saying just "end".
>p 1
>end
pwndbg>
pwndbg> custom_print
$8 = 1
```

So we can do several stuff with function in GDB like checking if register is equal to 0:

```python
pwndbg> define check_zero
Type commands for definition of "check_zero".
End with a line saying just "end".
>if $arg0==0
 >p 1
 >else
 >p 0
 >end
>end
pwndbg>
pwndbg> check_zero $rax
$13 = 0
pwndbg> check_zero 0
$14 = 1
pwndbg> set $rax=0
pwndbg> check_zero $rax
$15 = 1
```

You can also define function in `~/.gdbinit` so that you won't need to define when exit and launch GDB again:

```bash
define check_zero
        if $arg0==0
                p 1
        else
                p 0
        end
end
```
![](images/gdbinit_define_function.png)

If you want to have advanced function, you can write python script and include your script in `~/.gdbinit`. Below is a python script and I will save it at `/home/user/.customgdb.py`:

```python
# https://sourceware.org/gdb/current/onlinedocs/gdb.html/CLI-Commands-In-Python.html#CLI-Commands-In-Python

import gdb
import struct

class Greeting(gdb.Command):
        def __init__(self):
                super(Greeting, self).__init__ ("hello", gdb.COMMAND_USER)

        def invoke(self, argv, from_tty):
                print("Hello World")

class DecToHex(gdb.Command):
        def __init__(self):
                super(DecToHex, self).__init__ ("tohex", gdb.COMMAND_USER)

        def invoke(self, argv, from_tty):
                print(hex(int(argv)))

Greeting()
DecToHex()
```

Now I just need to import it to `~/.gdbinit`:

![](images/gdbinit_add_custom_function_written_in_python.png)

Then just load GDB and we can run our custom functions:

![](images/gdb_test_custom_function.png)

References:
- https://sourceware.org/gdb/current/onlinedocs/gdb.html/Define.html

**6. GDB expressions**

If else expression with custom variable:

```python
pwndbg> set $i=1
pwndbg> if $i==1
 >p 1
 >else
 >p 0
 >end
$1 = 1
pwndbg>
```

If expression with register:

```python
pwndbg> if ((unsigned short)$rsp)==0xd9f0
 >p 1
 >end
$4 = 1
pwndbg>
```

While expression changes value of pointer on register and change register:

```python
pwndbg> while($i<10)
 >set *(int*)$rax=($i*2)
 >set $rax=$rax+4
 >set $i=$i+1
 >end
pwndbg>
```

While expression changes value at specific address:

```python
pwndbg> while($i<20)
 >set *(int*)(0x7fffffffd820+$i*4)=$i*2
 >set $i=$i+1
 >end
pwndbg>
```

References
- https://stackoverflow.com/questions/70657261/gdb-defining-a-function-with-multiple-arguments-using-if-else
- https://www.reddit.com/r/learnprogramming/comments/z5edfu/is_there_loops_and_condition_in_gdb/

**7. Other tips**

- `r < <()` can input null byte, `r <<<$()` cannot.

- `flag +/-ZERO` to set or remove flag.

</p>
</details>

<details>
<summary><h2>Load libc in python</h2></summary>
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
<summary><h2>Core dump</h2></summary>
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

**References**
- https://stackoverflow.com/a/54943610
- https://linuxhint.com/increase-open-file-limit-ubuntu/

</p>
</details>

<details>
<summary><h2>pwntools</h2></summary>
<p>

**Get child pid (method 1)**
```
import os
from pwn import *

p = process(<Some Program>)
child_pid = pwnlib.util.proc.children(os.getpid())[0]
print(child_pid)
```

**Get child pid (method 2)**
```
from pwn import *

p = process(<Some Program>)
print(pidof(p))
```

**Get child pid (method 3)**
```
from pwn import *

p = process(<Some Program>)
print(p.pid)
```

**ARGS**

```
from pwn import *

# print(args.<ANY NAME IN CAPITAL>)
print(args.MYNAME)
print(args.MYAGE)
```
--> `python run.py MYNAME=Johnathan MYAGE=20`

**[Core](https://docs.pwntools.com/en/stable/elf/corefile.html) file**

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
<summary><h2>Ascii shellcode</h2></summary>
<p>

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

**References**
- https://blackcloud.me/Linux-shellcode-alphanumeric/
- https://nets.ec/Ascii_shellcode
- https://github.com/VincentDary/PolyAsciiShellGen
</p>
</details>

<details>
<summary><h2>Even shellcode</h2></summary>
<p>

Some special assembly code:
```as
01 c3                   add    ebx,eax
01 db                   add    ebx,ebx
01 cb                   add    ebx,ecx
01 d3                   add    ebx,edx
01 fb                   add    ebx,edi
01 f3                   add    ebx,esi
01 eb                   add    ebx,ebp
01 e3                   add    ebx,esp
01 c1                   add    ecx,eax
01 d9                   add    ecx,ebx
01 c9                   add    ecx,ecx
01 d1                   add    ecx,edx
01 f9                   add    ecx,edi
01 f1                   add    ecx,esi
01 e9                   add    ecx,ebp
01 e1                   add    ecx,esp
01 c7                   add    edi,eax
01 df                   add    edi,ebx
01 cf                   add    edi,ecx
01 d7                   add    edi,edx
01 ff                   add    edi,edi
01 f7                   add    edi,esi
01 ef                   add    edi,ebp
01 e7                   add    edi,esp
01 c5                   add    ebp,eax
01 dd                   add    ebp,ebx
01 cd                   add    ebp,ecx
01 d5                   add    ebp,edx
01 fd                   add    ebp,edi
01 f5                   add    ebp,esi
01 ed                   add    ebp,ebp
01 e5                   add    ebp,esp
49 01 c1                add    r9,rax
49 01 d9                add    r9,rbx
49 01 c9                add    r9,rcx
49 01 d1                add    r9,rdx
49 01 f9                add    r9,rdi
49 01 f1                add    r9,rsi
49 01 e9                add    r9,rbp
49 01 e1                add    r9,rsp
4d 01 c1                add    r9,r8
4d 01 c9                add    r9,r9
4d 01 d1                add    r9,r10
4d 01 d9                add    r9,r11
4d 01 e1                add    r9,r12
4d 01 e9                add    r9,r13
4d 01 f1                add    r9,r14
4d 01 f9                add    r9,r15
49 01 c3                add    r11,rax
49 01 db                add    r11,rbx
49 01 cb                add    r11,rcx
49 01 d3                add    r11,rdx
49 01 fb                add    r11,rdi
49 01 f3                add    r11,rsi
49 01 eb                add    r11,rbp
49 01 e3                add    r11,rsp
4d 01 c3                add    r11,r8
4d 01 cb                add    r11,r9
4d 01 d3                add    r11,r10
4d 01 db                add    r11,r11
4d 01 e3                add    r11,r12
4d 01 eb                add    r11,r13
4d 01 f3                add    r11,r14
4d 01 fb                add    r11,r15
49 01 c5                add    r13,rax
49 01 dd                add    r13,rbx
49 01 cd                add    r13,rcx
49 01 d5                add    r13,rdx
49 01 fd                add    r13,rdi
49 01 f5                add    r13,rsi
49 01 ed                add    r13,rbp
49 01 e5                add    r13,rsp
4d 01 c5                add    r13,r8
4d 01 cd                add    r13,r9
4d 01 d5                add    r13,r10
4d 01 dd                add    r13,r11
4d 01 e5                add    r13,r12
4d 01 ed                add    r13,r13
4d 01 f5                add    r13,r14
4d 01 fd                add    r13,r15
49 01 c7                add    r15,rax
49 01 df                add    r15,rbx
49 01 cf                add    r15,rcx
49 01 d7                add    r15,rdx
49 01 ff                add    r15,rdi
49 01 f7                add    r15,rsi
49 01 ef                add    r15,rbp
49 01 e7                add    r15,rsp
4d 01 c7                add    r15,r8
4d 01 cf                add    r15,r9
4d 01 d7                add    r15,r10
4d 01 df                add    r15,r11
4d 01 e7                add    r15,r12
4d 01 ef                add    r15,r13
4d 01 f7                add    r15,r14
4d 01 ff                add    r15,r15

29 c3                   sub    ebx,eax
29 db                   sub    ebx,ebx
29 cb                   sub    ebx,ecx
29 d3                   sub    ebx,edx
29 fb                   sub    ebx,edi
29 f3                   sub    ebx,esi
29 eb                   sub    ebx,ebp
29 e3                   sub    ebx,esp
29 c1                   sub    ecx,eax
29 d9                   sub    ecx,ebx
29 c9                   sub    ecx,ecx
29 d1                   sub    ecx,edx
29 f9                   sub    ecx,edi
29 f1                   sub    ecx,esi
29 e9                   sub    ecx,ebp
29 e1                   sub    ecx,esp
29 c7                   sub    edi,eax
29 df                   sub    edi,ebx
29 cf                   sub    edi,ecx
29 d7                   sub    edi,edx
29 ff                   sub    edi,edi
29 f7                   sub    edi,esi
29 ef                   sub    edi,ebp
29 e7                   sub    edi,esp
29 c5                   sub    ebp,eax
29 dd                   sub    ebp,ebx
29 cd                   sub    ebp,ecx
29 d5                   sub    ebp,edx
29 fd                   sub    ebp,edi
29 f5                   sub    ebp,esi
29 ed                   sub    ebp,ebp
29 e5                   sub    ebp,esp
49 29 c1                sub    r9,rax
49 29 d9                sub    r9,rbx
49 29 c9                sub    r9,rcx
49 29 d1                sub    r9,rdx
49 29 f9                sub    r9,rdi
49 29 f1                sub    r9,rsi
49 29 e9                sub    r9,rbp
49 29 e1                sub    r9,rsp
4d 29 c1                sub    r9,r8
4d 29 c9                sub    r9,r9
4d 29 d1                sub    r9,r10
4d 29 d9                sub    r9,r11
4d 29 e1                sub    r9,r12
4d 29 e9                sub    r9,r13
4d 29 f1                sub    r9,r14
4d 29 f9                sub    r9,r15
49 29 c3                sub    r11,rax
49 29 db                sub    r11,rbx
49 29 cb                sub    r11,rcx
49 29 d3                sub    r11,rdx
49 29 fb                sub    r11,rdi
49 29 f3                sub    r11,rsi
49 29 eb                sub    r11,rbp
49 29 e3                sub    r11,rsp
4d 29 c3                sub    r11,r8
4d 29 cb                sub    r11,r9
4d 29 d3                sub    r11,r10
4d 29 db                sub    r11,r11
4d 29 e3                sub    r11,r12
4d 29 eb                sub    r11,r13
4d 29 f3                sub    r11,r14
4d 29 fb                sub    r11,r15
49 29 c5                sub    r13,rax
49 29 dd                sub    r13,rbx
49 29 cd                sub    r13,rcx
49 29 d5                sub    r13,rdx
49 29 fd                sub    r13,rdi
49 29 f5                sub    r13,rsi
49 29 ed                sub    r13,rbp
49 29 e5                sub    r13,rsp
4d 29 c5                sub    r13,r8
4d 29 cd                sub    r13,r9
4d 29 d5                sub    r13,r10
4d 29 dd                sub    r13,r11
4d 29 e5                sub    r13,r12
4d 29 ed                sub    r13,r13
4d 29 f5                sub    r13,r14
4d 29 fd                sub    r13,r15
49 29 c7                sub    r15,rax
49 29 df                sub    r15,rbx
49 29 cf                sub    r15,rcx
49 29 d7                sub    r15,rdx
49 29 ff                sub    r15,rdi
49 29 f7                sub    r15,rsi
49 29 ef                sub    r15,rbp
49 29 e7                sub    r15,rsp
4d 29 c7                sub    r15,r8
4d 29 cf                sub    r15,r9
4d 29 d7                sub    r15,r10
4d 29 df                sub    r15,r11
4d 29 e7                sub    r15,r12
4d 29 ef                sub    r15,r13
4d 29 f7                sub    r15,r14
4d 29 ff                sub    r15,r15

ff cb                   dec    ebx
ff c9                   dec    ecx
ff cf                   dec    edi
ff cd                   dec    ebp
49 ff c9                dec    r9
49 ff cb                dec    r11
49 ff cd                dec    r13
49 ff cf                dec    r13

ff c3                   inc    ebx
ff c1                   inc    ecx
ff c7                   inc    edi
ff c5                   inc    ebp
49 ff c1                inc    r9
49 ff c3                inc    r11
49 ff c5                inc    r13
49 ff c7                inc    r13

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

89 c3                   mov    ebx,eax
89 cb                   mov    ebx,ecx
89 d3                   mov    ebx,edx
89 fb                   mov    ebx,edi
89 c1                   mov    ecx,eax
89 d9                   mov    ecx,ebx
89 d1                   mov    ecx,edx
89 f9                   mov    ecx,edi
bb 33 33 33 33          mov    ebx,0x33333333
b3 37                   mov    bl,0x37
b7 39                   mov    bh,0x39
b9 33 33 33 33          mov    ecx,0x33333333
b1 37                   mov    cl,0x37
b5 39                   mov    ch,0x39
49 8b 01                mov    rax,QWORD PTR [r9]
49 8b 03                mov    rax,QWORD PTR [r11]
49 8b 45 ff             mov    rax,QWORD PTR [r13-0x1]
49 8b 07                mov    rax,QWORD PTR [r15]
49 8b 19                mov    rbx,QWORD PTR [r9]
49 8b 1b                mov    rbx,QWORD PTR [r11]
49 8b 5d ff             mov    rbx,QWORD PTR [r13-0x1]
49 8b 1f                mov    rbx,QWORD PTR [r15]
49 8b 09                mov    rcx,QWORD PTR [r9]
49 8b 0b                mov    rcx,QWORD PTR [r11]
49 8b 4d ff             mov    rcx,QWORD PTR [r13-0x1]
49 8b 0f                mov    rcx,QWORD PTR [r15]
49 8b 11                mov    rdx,QWORD PTR [r9]
49 8b 13                mov    rdx,QWORD PTR [r11]
49 8b 55 ff             mov    rdx,QWORD PTR [r13-0x1]
49 8b 17                mov    rdx,QWORD PTR [r15]
49 8b 39                mov    rdi,QWORD PTR [r9]
49 8b 3b                mov    rdi,QWORD PTR [r11]
49 8b 7d ff             mov    rdi,QWORD PTR [r13-0x1]
49 8b 3f                mov    rdi,QWORD PTR [r15]
49 8b 31                mov    rsi,QWORD PTR [r9]
49 8b 33                mov    rsi,QWORD PTR [r11]
49 8b 75 ff             mov    rsi,QWORD PTR [r13-0x1]
49 8b 37                mov    rsi,QWORD PTR [r15]
49 8b 21                mov    rsp,QWORD PTR [r9]
49 8b 23                mov    rsp,QWORD PTR [r11]
49 8b 65 ff             mov    rsp,QWORD PTR [r13-0x1]
49 8b 27                mov    rsp,QWORD PTR [r15]
49 8b 29                mov    rbp,QWORD PTR [r9]
49 8b 2b                mov    rbp,QWORD PTR [r11]
49 8b 6d ff             mov    rbp,QWORD PTR [r13-0x1]
49 8b 2f                mov    rbp,QWORD PTR [r15]
4d 8b 01                mov    r8,QWORD PTR [r9]
4d 8b 03                mov    r8,QWORD PTR [r11]
4d 8b 45 ff             mov    r8,QWORD PTR [r13-0x1]
4d 8b 07                mov    r8,QWORD PTR [r15]
4d 8b 09                mov    r9,QWORD PTR [r9]
4d 8b 0b                mov    r9,QWORD PTR [r11]
4d 8b 4d ff             mov    r9,QWORD PTR [r13-0x1]
4d 8b 0f                mov    r9,QWORD PTR [r15]

53                      push   rbx
51                      push   rcx
57                      push   rdi
55                      push   rbp
41 51                   push   r9
41 53                   push   r11
41 55                   push   r13
41 57                   push   r15
5b                      pop    rbx
59                      pop    rcx
5f                      pop    rdi
5d                      pop    rbp
41 59                   pop    r9
41 5b                   pop    r11
41 5d                   pop    r13
41 5f                   pop    r15

c1 e3 03                shl    ebx,0x3
c1 e1 03                shl    ecx,0x3
c1 e7 03                shl    edi,0x3
c1 e5 03                shl    ebp,0x3
d3 e3                   shl    ebx,cl
d3 e1                   shl    ecx,cl
d3 e7                   shl    edi,cl
d3 e5                   shl    ebp,cl
d3 eb                   shr    ebx,cl
d3 e9                   shr    ecx,cl
d3 ef                   shr    edi,cl

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
31 fb                   xor    ebx,edi
31 c1                   xor    ecx,eax
31 d9                   xor    ecx,ebx
31 c9                   xor    ecx,ecx
31 d1                   xor    ecx,edx
31 f9                   xor    ecx,edi
31 c7                   xor    edi,eax
31 df                   xor    edi,ebx
31 cf                   xor    edi,ecx
31 d7                   xor    edi,edx
31 ff                   xor    edi,edi
49 31 e1                xor    r9,rsp
49 31 e3                xor    r11,rsp
49 31 e5                xor    r13,rsp
49 31 e7                xor    r15,rsp

93                      xchg   ebx,eax
87 cb                   xchg   ebx,ecx
87 db                   xchg   ebx,ebx
87 d3                   xchg   ebx,edx
87 fb                   xchg   ebx,edi
87 f3                   xchg   ebx,esi
87 eb                   xchg   ebx,ebp
87 e3                   xchg   ebx,esp
91                      xchg   ecx,eax
87 d9                   xchg   ecx,ebx
87 c9                   xchg   ecx,ecx
87 d1                   xchg   ecx,edx
87 f9                   xchg   ecx,edi
87 f1                   xchg   ecx,esi
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

c3                      ret
c9                      leave

0f 05                   syscall
```

**References**
- https://ctftime.org/writeup/34832
- https://marcosvalle.github.io/re/exploit/2018/09/02/odd-even-encoder.html
</p>
</details>

<details>
<summary><h2>Odd shellcode</h2></summary>
<p>

Some special assembly code:
```as
49 01 c1                add    r9,rax
49 01 d9                add    r9,rbx
49 01 c9                add    r9,rcx
49 01 d1                add    r9,rdx
49 01 f9                add    r9,rdi
49 01 f1                add    r9,rsi
49 01 e9                add    r9,rbp
49 01 e1                add    r9,rsp
4d 01 c1                add    r9,r8
4d 01 c9                add    r9,r9
4d 01 d1                add    r9,r10
4d 01 d9                add    r9,r11
4d 01 e1                add    r9,r12
4d 01 e9                add    r9,r13
4d 01 f1                add    r9,r14
4d 01 f9                add    r9,r15
49 01 c3                add    r11,rax
49 01 db                add    r11,rbx
49 01 cb                add    r11,rcx
49 01 d3                add    r11,rdx
49 01 fb                add    r11,rdi
49 01 f3                add    r11,rsi
49 01 eb                add    r11,rbp
49 01 e3                add    r11,rsp
4d 01 c3                add    r11,r8
4d 01 cb                add    r11,r9
4d 01 d3                add    r11,r10
4d 01 db                add    r11,r11
4d 01 e3                add    r11,r12
4d 01 eb                add    r11,r13
4d 01 f3                add    r11,r14
4d 01 fb                add    r11,r15
49 01 c5                add    r13,rax
49 01 dd                add    r13,rbx
49 01 cd                add    r13,rcx
49 01 d5                add    r13,rdx
49 01 fd                add    r13,rdi
49 01 f5                add    r13,rsi
49 01 ed                add    r13,rbp
49 01 e5                add    r13,rsp
4d 01 c5                add    r13,r8
4d 01 cd                add    r13,r9
4d 01 d5                add    r13,r10
4d 01 dd                add    r13,r11
4d 01 e5                add    r13,r12
4d 01 ed                add    r13,r13
4d 01 f5                add    r13,r14
4d 01 fd                add    r13,r15
49 01 c7                add    r15,rax
49 01 df                add    r15,rbx
49 01 cf                add    r15,rcx
49 01 d7                add    r15,rdx
49 01 ff                add    r15,rdi
49 01 f7                add    r15,rsi
49 01 ef                add    r15,rbp
49 01 e7                add    r15,rsp
4d 01 c7                add    r15,r8
4d 01 cf                add    r15,r9
4d 01 d7                add    r15,r10
4d 01 df                add    r15,r11
4d 01 e7                add    r15,r12
4d 01 ef                add    r15,r13
4d 01 f7                add    r15,r14
4d 01 ff                add    r15,r15
---
01 c3                   add    ebx,eax
01 db                   add    ebx,ebx
01 cb                   add    ebx,ecx
01 d3                   add    ebx,edx
01 fb                   add    ebx,edi
01 f3                   add    ebx,esi
01 eb                   add    ebx,ebp
01 e3                   add    ebx,esp
01 c1                   add    ecx,eax
01 d9                   add    ecx,ebx
01 c9                   add    ecx,ecx
01 d1                   add    ecx,edx
01 f9                   add    ecx,edi
01 f1                   add    ecx,esi
01 e9                   add    ecx,ebp
01 e1                   add    ecx,esp
01 c7                   add    edi,eax
01 df                   add    edi,ebx
01 cf                   add    edi,ecx
01 d7                   add    edi,edx
01 ff                   add    edi,edi
01 f7                   add    edi,esi
01 ef                   add    edi,ebp
01 e7                   add    edi,esp
01 c5                   add    ebp,eax
01 dd                   add    ebp,ebx
01 cd                   add    ebp,ecx
01 d5                   add    ebp,edx
01 fd                   add    ebp,edi
01 f5                   add    ebp,esi
01 ed                   add    ebp,ebp
01 e5                   add    ebp,esp
---
49 03 01                add    rax,QWORD PTR [r9]
49 03 03                add    rax,QWORD PTR [r11]
49 03 45 31             add    rax,QWORD PTR [r13+0x31]
49 03 07                add    rax,QWORD PTR [r15]
49 03 19                add    rbx,QWORD PTR [r9]
49 03 1b                add    rbx,QWORD PTR [r11]
49 03 5d 31             add    rbx,QWORD PTR [r13+0x31]
49 03 1f                add    rbx,QWORD PTR [r15]
49 03 09                add    rcx,QWORD PTR [r9]
49 03 0b                add    rcx,QWORD PTR [r11]
49 03 4d 31             add    rcx,QWORD PTR [r13+0x31]
49 03 0f                add    rcx,QWORD PTR [r15]
49 03 11                add    rdx,QWORD PTR [r9]
49 03 13                add    rdx,QWORD PTR [r11]
49 03 55 31             add    rdx,QWORD PTR [r13+0x31]
49 03 17                add    rdx,QWORD PTR [r15]
49 03 39                add    rdi,QWORD PTR [r9]
49 03 3b                add    rdi,QWORD PTR [r11]
49 03 7d 31             add    rdi,QWORD PTR [r13+0x31]
49 03 3f                add    rdi,QWORD PTR [r15]
49 03 31                add    rsi,QWORD PTR [r9]
49 03 33                add    rsi,QWORD PTR [r11]
49 03 75 31             add    rsi,QWORD PTR [r13+0x31]
49 03 37                add    rsi,QWORD PTR [r15]
49 03 21                add    rsp,QWORD PTR [r9]
49 03 23                add    rsp,QWORD PTR [r11]
49 03 65 31             add    rsp,QWORD PTR [r13+0x31]
49 03 27                add    rsp,QWORD PTR [r15]
49 03 29                add    rbp,QWORD PTR [r9]
49 03 2b                add    rbp,QWORD PTR [r11]
49 03 6d 31             add    rbp,QWORD PTR [r13+0x31]
49 03 2f                add    rbp,QWORD PTR [r15]
4d 03 01                add    r8,QWORD PTR [r9]
4d 03 03                add    r8,QWORD PTR [r11]
4d 03 45 31             add    r8,QWORD PTR [r13+0x31]
4d 03 07                add    r8,QWORD PTR [r15]
4d 03 09                add    r9,QWORD PTR [r9]
4d 03 0b                add    r9,QWORD PTR [r11]
4d 03 4d 31             add    r9,QWORD PTR [r13+0x31]
4d 03 0f                add    r9,QWORD PTR [r15]
4d 03 11                add    r10,QWORD PTR [r9]
4d 03 13                add    r10,QWORD PTR [r11]
4d 03 55 31             add    r10,QWORD PTR [r13+0x31]
4d 03 17                add    r10,QWORD PTR [r15]
4d 03 19                add    r11,QWORD PTR [r9]
4d 03 1b                add    r11,QWORD PTR [r11]
4d 03 5d 31             add    r11,QWORD PTR [r13+0x31]
4d 03 1f                add    r11,QWORD PTR [r15]
4d 03 21                add    r12,QWORD PTR [r9]
4d 03 23                add    r12,QWORD PTR [r11]
4d 03 65 31             add    r12,QWORD PTR [r13+0x31]
4d 03 27                add    r12,QWORD PTR [r15]
4d 03 29                add    r13,QWORD PTR [r9]
4d 03 2b                add    r13,QWORD PTR [r11]
4d 03 6d 31             add    r13,QWORD PTR [r13+0x31]
4d 03 2f                add    r13,QWORD PTR [r15]
4d 03 31                add    r14,QWORD PTR [r9]
4d 03 33                add    r14,QWORD PTR [r11]
4d 03 75 31             add    r14,QWORD PTR [r13+0x31]
4d 03 37                add    r14,QWORD PTR [r15]
4d 03 39                add    r15,QWORD PTR [r9]
4d 03 3b                add    r15,QWORD PTR [r11]
4d 03 7d 31             add    r15,QWORD PTR [r13+0x31]
4d 03 3f                add    r15,QWORD PTR [r15]
---
03 03                   add    eax,DWORD PTR [rbx]
03 01                   add    eax,DWORD PTR [rcx]
03 07                   add    eax,DWORD PTR [rdi]
03 45 31                add    eax,DWORD PTR [rbp+0x31]
41 03 01                add    eax,DWORD PTR [r9]
41 03 03                add    eax,DWORD PTR [r11]
41 03 45 31             add    eax,DWORD PTR [r13+0x31]
41 03 07                add    eax,DWORD PTR [r15]
03 1b                   add    ebx,DWORD PTR [rbx]
03 19                   add    ebx,DWORD PTR [rcx]
03 1f                   add    ebx,DWORD PTR [rdi]
03 5d 31                add    ebx,DWORD PTR [rbp+0x31]
41 03 19                add    ebx,DWORD PTR [r9]
41 03 1b                add    ebx,DWORD PTR [r11]
41 03 5d 31             add    ebx,DWORD PTR [r13+0x31]
41 03 1f                add    ebx,DWORD PTR [r15]
03 0b                   add    ecx,DWORD PTR [rbx]
03 09                   add    ecx,DWORD PTR [rcx]
03 0f                   add    ecx,DWORD PTR [rdi]
03 4d 31                add    ecx,DWORD PTR [rbp+0x31]
41 03 09                add    ecx,DWORD PTR [r9]
41 03 0b                add    ecx,DWORD PTR [r11]
41 03 4d 31             add    ecx,DWORD PTR [r13+0x31]
41 03 0f                add    ecx,DWORD PTR [r15]
03 13                   add    edx,DWORD PTR [rbx]
03 11                   add    edx,DWORD PTR [rcx]
03 17                   add    edx,DWORD PTR [rdi]
03 55 31                add    edx,DWORD PTR [rbp+0x31]
41 03 11                add    edx,DWORD PTR [r9]
41 03 13                add    edx,DWORD PTR [r11]
41 03 55 31             add    edx,DWORD PTR [r13+0x31]
41 03 17                add    edx,DWORD PTR [r15]
03 3b                   add    edi,DWORD PTR [rbx]
03 39                   add    edi,DWORD PTR [rcx]
03 3f                   add    edi,DWORD PTR [rdi]
03 7d 31                add    edi,DWORD PTR [rbp+0x31]
41 03 39                add    edi,DWORD PTR [r9]
41 03 3b                add    edi,DWORD PTR [r11]
41 03 7d 31             add    edi,DWORD PTR [r13+0x31]
41 03 3f                add    edi,DWORD PTR [r15]
03 33                   add    esi,DWORD PTR [rbx]
03 31                   add    esi,DWORD PTR [rcx]
03 37                   add    esi,DWORD PTR [rdi]
03 75 31                add    esi,DWORD PTR [rbp+0x31]
41 03 31                add    esi,DWORD PTR [r9]
41 03 33                add    esi,DWORD PTR [r11]
41 03 75 31             add    esi,DWORD PTR [r13+0x31]
41 03 37                add    esi,DWORD PTR [r15]
03 23                   add    esp,DWORD PTR [rbx]
03 21                   add    esp,DWORD PTR [rcx]
03 27                   add    esp,DWORD PTR [rdi]
03 65 31                add    esp,DWORD PTR [rbp+0x31]
41 03 21                add    esp,DWORD PTR [r9]
41 03 23                add    esp,DWORD PTR [r11]
41 03 65 31             add    esp,DWORD PTR [r13+0x31]
41 03 27                add    esp,DWORD PTR [r15]
03 2b                   add    ebp,DWORD PTR [rbx]
03 29                   add    ebp,DWORD PTR [rcx]
03 2f                   add    ebp,DWORD PTR [rdi]
03 6d 31                add    ebp,DWORD PTR [rbp+0x31]
41 03 29                add    ebp,DWORD PTR [r9]
41 03 2b                add    ebp,DWORD PTR [r11]
41 03 6d 31             add    ebp,DWORD PTR [r13+0x31]
41 03 2f                add    ebp,DWORD PTR [r15]




49 29 c1                sub    r9,rax
49 29 d9                sub    r9,rbx
49 29 c9                sub    r9,rcx
49 29 d1                sub    r9,rdx
49 29 f9                sub    r9,rdi
49 29 f1                sub    r9,rsi
49 29 e9                sub    r9,rbp
49 29 e1                sub    r9,rsp
4d 29 c1                sub    r9,r8
4d 29 c9                sub    r9,r9
4d 29 d1                sub    r9,r10
4d 29 d9                sub    r9,r11
4d 29 e1                sub    r9,r12
4d 29 e9                sub    r9,r13
4d 29 f1                sub    r9,r14
4d 29 f9                sub    r9,r15
49 29 c3                sub    r11,rax
49 29 db                sub    r11,rbx
49 29 cb                sub    r11,rcx
49 29 d3                sub    r11,rdx
49 29 fb                sub    r11,rdi
49 29 f3                sub    r11,rsi
49 29 eb                sub    r11,rbp
49 29 e3                sub    r11,rsp
4d 29 c3                sub    r11,r8
4d 29 cb                sub    r11,r9
4d 29 d3                sub    r11,r10
4d 29 db                sub    r11,r11
4d 29 e3                sub    r11,r12
4d 29 eb                sub    r11,r13
4d 29 f3                sub    r11,r14
4d 29 fb                sub    r11,r15
49 29 c5                sub    r13,rax
49 29 dd                sub    r13,rbx
49 29 cd                sub    r13,rcx
49 29 d5                sub    r13,rdx
49 29 fd                sub    r13,rdi
49 29 f5                sub    r13,rsi
49 29 ed                sub    r13,rbp
49 29 e5                sub    r13,rsp
4d 29 c5                sub    r13,r8
4d 29 cd                sub    r13,r9
4d 29 d5                sub    r13,r10
4d 29 dd                sub    r13,r11
4d 29 e5                sub    r13,r12
4d 29 ed                sub    r13,r13
4d 29 f5                sub    r13,r14
4d 29 fd                sub    r13,r15
49 29 c7                sub    r15,rax
49 29 df                sub    r15,rbx
49 29 cf                sub    r15,rcx
49 29 d7                sub    r15,rdx
49 29 ff                sub    r15,rdi
49 29 f7                sub    r15,rsi
49 29 ef                sub    r15,rbp
49 29 e7                sub    r15,rsp
4d 29 c7                sub    r15,r8
4d 29 cf                sub    r15,r9
4d 29 d7                sub    r15,r10
4d 29 df                sub    r15,r11
4d 29 e7                sub    r15,r12
4d 29 ef                sub    r15,r13
4d 29 f7                sub    r15,r14
4d 29 ff                sub    r15,r15
---
29 c3                   sub    ebx,eax
29 db                   sub    ebx,ebx
29 cb                   sub    ebx,ecx
29 d3                   sub    ebx,edx
29 fb                   sub    ebx,edi
29 f3                   sub    ebx,esi
29 eb                   sub    ebx,ebp
29 e3                   sub    ebx,esp
29 c1                   sub    ecx,eax
29 d9                   sub    ecx,ebx
29 c9                   sub    ecx,ecx
29 d1                   sub    ecx,edx
29 f9                   sub    ecx,edi
29 f1                   sub    ecx,esi
29 e9                   sub    ecx,ebp
29 e1                   sub    ecx,esp
29 c7                   sub    edi,eax
29 df                   sub    edi,ebx
29 cf                   sub    edi,ecx
29 d7                   sub    edi,edx
29 ff                   sub    edi,edi
29 f7                   sub    edi,esi
29 ef                   sub    edi,ebp
29 e7                   sub    edi,esp
29 c5                   sub    ebp,eax
29 dd                   sub    ebp,ebx
29 cd                   sub    ebp,ecx
29 d5                   sub    ebp,edx
29 fd                   sub    ebp,edi
29 f5                   sub    ebp,esi
29 ed                   sub    ebp,ebp
29 e5                   sub    ebp,esp
---
49 2b 01                sub    rax,QWORD PTR [r9]
49 2b 03                sub    rax,QWORD PTR [r11]
49 2b 45 31             sub    rax,QWORD PTR [r13+0x31]
49 2b 07                sub    rax,QWORD PTR [r15]
49 2b 19                sub    rbx,QWORD PTR [r9]
49 2b 1b                sub    rbx,QWORD PTR [r11]
49 2b 5d 31             sub    rbx,QWORD PTR [r13+0x31]
49 2b 1f                sub    rbx,QWORD PTR [r15]
49 2b 09                sub    rcx,QWORD PTR [r9]
49 2b 0b                sub    rcx,QWORD PTR [r11]
49 2b 4d 31             sub    rcx,QWORD PTR [r13+0x31]
49 2b 0f                sub    rcx,QWORD PTR [r15]
49 2b 11                sub    rdx,QWORD PTR [r9]
49 2b 13                sub    rdx,QWORD PTR [r11]
49 2b 55 31             sub    rdx,QWORD PTR [r13+0x31]
49 2b 17                sub    rdx,QWORD PTR [r15]
49 2b 39                sub    rdi,QWORD PTR [r9]
49 2b 3b                sub    rdi,QWORD PTR [r11]
49 2b 7d 31             sub    rdi,QWORD PTR [r13+0x31]
49 2b 3f                sub    rdi,QWORD PTR [r15]
49 2b 31                sub    rsi,QWORD PTR [r9]
49 2b 33                sub    rsi,QWORD PTR [r11]
49 2b 75 31             sub    rsi,QWORD PTR [r13+0x31]
49 2b 37                sub    rsi,QWORD PTR [r15]
49 2b 21                sub    rsp,QWORD PTR [r9]
49 2b 23                sub    rsp,QWORD PTR [r11]
49 2b 65 31             sub    rsp,QWORD PTR [r13+0x31]
49 2b 27                sub    rsp,QWORD PTR [r15]
49 2b 29                sub    rbp,QWORD PTR [r9]
49 2b 2b                sub    rbp,QWORD PTR [r11]
49 2b 6d 31             sub    rbp,QWORD PTR [r13+0x31]
49 2b 2f                sub    rbp,QWORD PTR [r15]
4d 2b 01                sub    r8,QWORD PTR [r9]
4d 2b 03                sub    r8,QWORD PTR [r11]
4d 2b 45 31             sub    r8,QWORD PTR [r13+0x31]
4d 2b 07                sub    r8,QWORD PTR [r15]
4d 2b 09                sub    r9,QWORD PTR [r9]
4d 2b 0b                sub    r9,QWORD PTR [r11]
4d 2b 4d 31             sub    r9,QWORD PTR [r13+0x31]
4d 2b 0f                sub    r9,QWORD PTR [r15]
4d 2b 11                sub    r10,QWORD PTR [r9]
4d 2b 13                sub    r10,QWORD PTR [r11]
4d 2b 55 31             sub    r10,QWORD PTR [r13+0x31]
4d 2b 17                sub    r10,QWORD PTR [r15]
4d 2b 19                sub    r11,QWORD PTR [r9]
4d 2b 1b                sub    r11,QWORD PTR [r11]
4d 2b 5d 31             sub    r11,QWORD PTR [r13+0x31]
4d 2b 1f                sub    r11,QWORD PTR [r15]
4d 2b 21                sub    r12,QWORD PTR [r9]
4d 2b 23                sub    r12,QWORD PTR [r11]
4d 2b 65 31             sub    r12,QWORD PTR [r13+0x31]
4d 2b 27                sub    r12,QWORD PTR [r15]
4d 2b 29                sub    r13,QWORD PTR [r9]
4d 2b 2b                sub    r13,QWORD PTR [r11]
4d 2b 6d 31             sub    r13,QWORD PTR [r13+0x31]
4d 2b 2f                sub    r13,QWORD PTR [r15]
4d 2b 31                sub    r14,QWORD PTR [r9]
4d 2b 33                sub    r14,QWORD PTR [r11]
4d 2b 75 31             sub    r14,QWORD PTR [r13+0x31]
4d 2b 37                sub    r14,QWORD PTR [r15]
4d 2b 39                sub    r15,QWORD PTR [r9]
4d 2b 3b                sub    r15,QWORD PTR [r11]
4d 2b 7d 31             sub    r15,QWORD PTR [r13+0x31]
4d 2b 3f                sub    r15,QWORD PTR [r15]
---
2b 03                   sub    eax,DWORD PTR [rbx]
2b 01                   sub    eax,DWORD PTR [rcx]
2b 07                   sub    eax,DWORD PTR [rdi]
2b 45 31                sub    eax,DWORD PTR [rbp+0x31]
41 2b 01                sub    eax,DWORD PTR [r9]
41 2b 03                sub    eax,DWORD PTR [r11]
41 2b 45 31             sub    eax,DWORD PTR [r13+0x31]
41 2b 07                sub    eax,DWORD PTR [r15]
2b 1b                   sub    ebx,DWORD PTR [rbx]
2b 19                   sub    ebx,DWORD PTR [rcx]
2b 1f                   sub    ebx,DWORD PTR [rdi]
2b 5d 31                sub    ebx,DWORD PTR [rbp+0x31]
41 2b 19                sub    ebx,DWORD PTR [r9]
41 2b 1b                sub    ebx,DWORD PTR [r11]
41 2b 5d 31             sub    ebx,DWORD PTR [r13+0x31]
41 2b 1f                sub    ebx,DWORD PTR [r15]
2b 0b                   sub    ecx,DWORD PTR [rbx]
2b 09                   sub    ecx,DWORD PTR [rcx]
2b 0f                   sub    ecx,DWORD PTR [rdi]
2b 4d 31                sub    ecx,DWORD PTR [rbp+0x31]
41 2b 09                sub    ecx,DWORD PTR [r9]
41 2b 0b                sub    ecx,DWORD PTR [r11]
41 2b 4d 31             sub    ecx,DWORD PTR [r13+0x31]
41 2b 0f                sub    ecx,DWORD PTR [r15]
2b 13                   sub    edx,DWORD PTR [rbx]
2b 11                   sub    edx,DWORD PTR [rcx]
2b 17                   sub    edx,DWORD PTR [rdi]
2b 55 31                sub    edx,DWORD PTR [rbp+0x31]
41 2b 11                sub    edx,DWORD PTR [r9]
41 2b 13                sub    edx,DWORD PTR [r11]
41 2b 55 31             sub    edx,DWORD PTR [r13+0x31]
41 2b 17                sub    edx,DWORD PTR [r15]
2b 3b                   sub    edi,DWORD PTR [rbx]
2b 39                   sub    edi,DWORD PTR [rcx]
2b 3f                   sub    edi,DWORD PTR [rdi]
2b 7d 31                sub    edi,DWORD PTR [rbp+0x31]
41 2b 39                sub    edi,DWORD PTR [r9]
41 2b 3b                sub    edi,DWORD PTR [r11]
41 2b 7d 31             sub    edi,DWORD PTR [r13+0x31]
41 2b 3f                sub    edi,DWORD PTR [r15]
2b 33                   sub    esi,DWORD PTR [rbx]
2b 31                   sub    esi,DWORD PTR [rcx]
2b 37                   sub    esi,DWORD PTR [rdi]
2b 75 31                sub    esi,DWORD PTR [rbp+0x31]
41 2b 31                sub    esi,DWORD PTR [r9]
41 2b 33                sub    esi,DWORD PTR [r11]
41 2b 75 31             sub    esi,DWORD PTR [r13+0x31]
41 2b 37                sub    esi,DWORD PTR [r15]
2b 23                   sub    esp,DWORD PTR [rbx]
2b 21                   sub    esp,DWORD PTR [rcx]
2b 27                   sub    esp,DWORD PTR [rdi]
2b 65 31                sub    esp,DWORD PTR [rbp+0x31]
41 2b 21                sub    esp,DWORD PTR [r9]
41 2b 23                sub    esp,DWORD PTR [r11]
41 2b 65 31             sub    esp,DWORD PTR [r13+0x31]
41 2b 27                sub    esp,DWORD PTR [r15]
2b 2b                   sub    ebp,DWORD PTR [rbx]
2b 29                   sub    ebp,DWORD PTR [rcx]
2b 2f                   sub    ebp,DWORD PTR [rdi]
2b 6d 31                sub    ebp,DWORD PTR [rbp+0x31]
41 2b 29                sub    ebp,DWORD PTR [r9]
41 2b 2b                sub    ebp,DWORD PTR [r11]
41 2b 6d 31             sub    ebp,DWORD PTR [r13+0x31]
41 2b 2f                sub    ebp,DWORD PTR [r15]


49 89 c1                mov    r9,rax
49 89 d9                mov    r9,rbx
49 89 c9                mov    r9,rcx
49 89 d1                mov    r9,rdx
49 89 f9                mov    r9,rdi
49 89 f1                mov    r9,rsi
49 89 e1                mov    r9,rsp
49 89 e9                mov    r9,rbp
4d 89 c1                mov    r9,r8
4d 89 c9                mov    r9,r9
4d 89 d1                mov    r9,r10
4d 89 d9                mov    r9,r11
4d 89 e1                mov    r9,r12
4d 89 e9                mov    r9,r13
4d 89 f1                mov    r9,r14
4d 89 f9                mov    r9,r15
49 89 c3                mov    r11,rax
49 89 db                mov    r11,rbx
49 89 cb                mov    r11,rcx
49 89 d3                mov    r11,rdx
49 89 fb                mov    r11,rdi
49 89 f3                mov    r11,rsi
49 89 e3                mov    r11,rsp
49 89 eb                mov    r11,rbp
4d 89 c3                mov    r11,r8
4d 89 cb                mov    r11,r9
4d 89 d3                mov    r11,r10
4d 89 db                mov    r11,r11
4d 89 e3                mov    r11,r12
4d 89 eb                mov    r11,r13
4d 89 f3                mov    r11,r14
4d 89 fb                mov    r11,r15
49 89 c5                mov    r13,rax
49 89 dd                mov    r13,rbx
49 89 cd                mov    r13,rcx
49 89 d5                mov    r13,rdx
49 89 fd                mov    r13,rdi
49 89 f5                mov    r13,rsi
49 89 e5                mov    r13,rsp
49 89 ed                mov    r13,rbp
4d 89 c5                mov    r13,r8
4d 89 cd                mov    r13,r9
4d 89 d5                mov    r13,r10
4d 89 dd                mov    r13,r11
4d 89 e5                mov    r13,r12
4d 89 ed                mov    r13,r13
4d 89 f5                mov    r13,r14
4d 89 fd                mov    r13,r15
49 89 c7                mov    r15,rax
49 89 df                mov    r15,rbx
49 89 cf                mov    r15,rcx
49 89 d7                mov    r15,rdx
49 89 ff                mov    r15,rdi
49 89 f7                mov    r15,rsi
49 89 e7                mov    r15,rsp
49 89 ef                mov    r15,rbp
4d 89 c7                mov    r15,r8
4d 89 cf                mov    r15,r9
4d 89 d7                mov    r15,r10
4d 89 df                mov    r15,r11
4d 89 e7                mov    r15,r12
4d 89 ef                mov    r15,r13
4d 89 f7                mov    r15,r14
4d 89 ff                mov    r15,r15
---
89 c3                   mov    ebx,eax
89 db                   mov    ebx,ebx
89 cb                   mov    ebx,ecx
89 d3                   mov    ebx,edx
89 fb                   mov    ebx,edi
89 f3                   mov    ebx,esi
89 e3                   mov    ebx,esp
89 eb                   mov    ebx,ebp
89 c1                   mov    ecx,eax
89 d9                   mov    ecx,ebx
89 c9                   mov    ecx,ecx
89 d1                   mov    ecx,edx
89 f9                   mov    ecx,edi
89 f1                   mov    ecx,esi
89 e1                   mov    ecx,esp
89 e9                   mov    ecx,ebp
89 c7                   mov    edi,eax
89 df                   mov    edi,ebx
89 cf                   mov    edi,ecx
89 d7                   mov    edi,edx
89 ff                   mov    edi,edi
89 f7                   mov    edi,esi
89 e7                   mov    edi,esp
89 ef                   mov    edi,ebp
89 c5                   mov    ebp,eax
89 dd                   mov    ebp,ebx
89 cd                   mov    ebp,ecx
89 d5                   mov    ebp,edx
89 fd                   mov    ebp,edi
89 f5                   mov    ebp,esi
89 e5                   mov    ebp,esp
89 ed                   mov    ebp,ebp
---
49 8b 01                mov    rax,QWORD PTR [r9]
49 8b 03                mov    rax,QWORD PTR [r11]
49 8b 45 31             mov    rax,QWORD PTR [r13+0x31]
49 8b 07                mov    rax,QWORD PTR [r15]
49 8b 19                mov    rbx,QWORD PTR [r9]
49 8b 1b                mov    rbx,QWORD PTR [r11]
49 8b 5d 31             mov    rbx,QWORD PTR [r13+0x31]
49 8b 1f                mov    rbx,QWORD PTR [r15]
49 8b 09                mov    rcx,QWORD PTR [r9]
49 8b 0b                mov    rcx,QWORD PTR [r11]
49 8b 4d 31             mov    rcx,QWORD PTR [r13+0x31]
49 8b 0f                mov    rcx,QWORD PTR [r15]
49 8b 11                mov    rdx,QWORD PTR [r9]
49 8b 13                mov    rdx,QWORD PTR [r11]
49 8b 55 31             mov    rdx,QWORD PTR [r13+0x31]
49 8b 17                mov    rdx,QWORD PTR [r15]
49 8b 39                mov    rdi,QWORD PTR [r9]
49 8b 3b                mov    rdi,QWORD PTR [r11]
49 8b 7d 31             mov    rdi,QWORD PTR [r13+0x31]
49 8b 3f                mov    rdi,QWORD PTR [r15]
49 8b 31                mov    rsi,QWORD PTR [r9]
49 8b 33                mov    rsi,QWORD PTR [r11]
49 8b 75 31             mov    rsi,QWORD PTR [r13+0x31]
49 8b 37                mov    rsi,QWORD PTR [r15]
49 8b 21                mov    rsp,QWORD PTR [r9]
49 8b 23                mov    rsp,QWORD PTR [r11]
49 8b 65 31             mov    rsp,QWORD PTR [r13+0x31]
49 8b 27                mov    rsp,QWORD PTR [r15]
49 8b 29                mov    rbp,QWORD PTR [r9]
49 8b 2b                mov    rbp,QWORD PTR [r11]
49 8b 6d 31             mov    rbp,QWORD PTR [r13+0x31]
49 8b 2f                mov    rbp,QWORD PTR [r15]
4d 8b 01                mov    r8,QWORD PTR [r9]
4d 8b 03                mov    r8,QWORD PTR [r11]
4d 8b 45 31             mov    r8,QWORD PTR [r13+0x31]
4d 8b 07                mov    r8,QWORD PTR [r15]
4d 8b 09                mov    r9,QWORD PTR [r9]
4d 8b 0b                mov    r9,QWORD PTR [r11]
4d 8b 4d 31             mov    r9,QWORD PTR [r13+0x31]
4d 8b 0f                mov    r9,QWORD PTR [r15]
4d 8b 11                mov    r10,QWORD PTR [r9]
4d 8b 13                mov    r10,QWORD PTR [r11]
4d 8b 55 31             mov    r10,QWORD PTR [r13+0x31]
4d 8b 17                mov    r10,QWORD PTR [r15]
4d 8b 19                mov    r11,QWORD PTR [r9]
4d 8b 1b                mov    r11,QWORD PTR [r11]
4d 8b 5d 31             mov    r11,QWORD PTR [r13+0x31]
4d 8b 1f                mov    r11,QWORD PTR [r15]
4d 8b 21                mov    r12,QWORD PTR [r9]
4d 8b 23                mov    r12,QWORD PTR [r11]
4d 8b 65 31             mov    r12,QWORD PTR [r13+0x31]
4d 8b 27                mov    r12,QWORD PTR [r15]
4d 8b 29                mov    r13,QWORD PTR [r9]
4d 8b 2b                mov    r13,QWORD PTR [r11]
4d 8b 6d 31             mov    r13,QWORD PTR [r13+0x31]
4d 8b 2f                mov    r13,QWORD PTR [r15]
4d 8b 31                mov    r14,QWORD PTR [r9]
4d 8b 33                mov    r14,QWORD PTR [r11]
4d 8b 75 31             mov    r14,QWORD PTR [r13+0x31]
4d 8b 37                mov    r14,QWORD PTR [r15]
4d 8b 39                mov    r15,QWORD PTR [r9]
4d 8b 3b                mov    r15,QWORD PTR [r11]
4d 8b 7d 31             mov    r15,QWORD PTR [r13+0x31]
4d 8b 3f                mov    r15,QWORD PTR [r15]
---
8b 03                   mov    eax,DWORD PTR [rbx]
8b 01                   mov    eax,DWORD PTR [rcx]
8b 07                   mov    eax,DWORD PTR [rdi]
8b 45 31                mov    eax,DWORD PTR [rbp+0x31]
41 8b 01                mov    eax,DWORD PTR [r9]
41 8b 03                mov    eax,DWORD PTR [r11]
41 8b 45 31             mov    eax,DWORD PTR [r13+0x31]
41 8b 07                mov    eax,DWORD PTR [r15]
8b 1b                   mov    ebx,DWORD PTR [rbx]
8b 19                   mov    ebx,DWORD PTR [rcx]
8b 1f                   mov    ebx,DWORD PTR [rdi]
8b 5d 31                mov    ebx,DWORD PTR [rbp+0x31]
41 8b 19                mov    ebx,DWORD PTR [r9]
41 8b 1b                mov    ebx,DWORD PTR [r11]
41 8b 5d 31             mov    ebx,DWORD PTR [r13+0x31]
41 8b 1f                mov    ebx,DWORD PTR [r15]
8b 0b                   mov    ecx,DWORD PTR [rbx]
8b 09                   mov    ecx,DWORD PTR [rcx]
8b 0f                   mov    ecx,DWORD PTR [rdi]
8b 4d 31                mov    ecx,DWORD PTR [rbp+0x31]
41 8b 09                mov    ecx,DWORD PTR [r9]
41 8b 0b                mov    ecx,DWORD PTR [r11]
41 8b 4d 31             mov    ecx,DWORD PTR [r13+0x31]
41 8b 0f                mov    ecx,DWORD PTR [r15]
8b 13                   mov    edx,DWORD PTR [rbx]
8b 11                   mov    edx,DWORD PTR [rcx]
8b 17                   mov    edx,DWORD PTR [rdi]
8b 55 31                mov    edx,DWORD PTR [rbp+0x31]
41 8b 11                mov    edx,DWORD PTR [r9]
41 8b 13                mov    edx,DWORD PTR [r11]
41 8b 55 31             mov    edx,DWORD PTR [r13+0x31]
41 8b 17                mov    edx,DWORD PTR [r15]
8b 3b                   mov    edi,DWORD PTR [rbx]
8b 39                   mov    edi,DWORD PTR [rcx]
8b 3f                   mov    edi,DWORD PTR [rdi]
8b 7d 31                mov    edi,DWORD PTR [rbp+0x31]
41 8b 39                mov    edi,DWORD PTR [r9]
41 8b 3b                mov    edi,DWORD PTR [r11]
41 8b 7d 31             mov    edi,DWORD PTR [r13+0x31]
41 8b 3f                mov    edi,DWORD PTR [r15]
8b 33                   mov    esi,DWORD PTR [rbx]
8b 31                   mov    esi,DWORD PTR [rcx]
8b 37                   mov    esi,DWORD PTR [rdi]
8b 75 31                mov    esi,DWORD PTR [rbp+0x31]
41 8b 31                mov    esi,DWORD PTR [r9]
41 8b 33                mov    esi,DWORD PTR [r11]
41 8b 75 31             mov    esi,DWORD PTR [r13+0x31]
41 8b 37                mov    esi,DWORD PTR [r15]
8b 23                   mov    esp,DWORD PTR [rbx]
8b 21                   mov    esp,DWORD PTR [rcx]
8b 27                   mov    esp,DWORD PTR [rdi]
8b 65 31                mov    esp,DWORD PTR [rbp+0x31]
41 8b 21                mov    esp,DWORD PTR [r9]
41 8b 23                mov    esp,DWORD PTR [r11]
41 8b 65 31             mov    esp,DWORD PTR [r13+0x31]
41 8b 27                mov    esp,DWORD PTR [r15]
8b 2b                   mov    ebp,DWORD PTR [rbx]
8b 29                   mov    ebp,DWORD PTR [rcx]
8b 2f                   mov    ebp,DWORD PTR [rdi]
8b 6d 31                mov    ebp,DWORD PTR [rbp+0x31]
41 8b 29                mov    ebp,DWORD PTR [r9]
41 8b 2b                mov    ebp,DWORD PTR [r11]
41 8b 6d 31             mov    ebp,DWORD PTR [r13+0x31]
41 8b 2f                mov    ebp,DWORD PTR [r15]
---
bb 33 33 33 33          mov    ebx,0x33333333
b3 37                   mov    bl,0x37
b7 39                   mov    bh,0x39
b9 33 33 33 33          mov    ecx,0x33333333
b1 37                   mov    cl,0x37
b5 39                   mov    ch,0x39



49 91                   xchg   r9,rax
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
49 93                   xchg   r11,rax
49 87 db                xchg   r11,rbx
49 87 cb                xchg   r11,rcx
49 87 d3                xchg   r11,rdx
49 87 fb                xchg   r11,rdi
49 87 f3                xchg   r11,rsi
49 87 e3                xchg   r11,rsp
49 87 eb                xchg   r11,rbp
4d 87 c3                xchg   r11,r8
4d 87 cb                xchg   r11,r9
4d 87 d3                xchg   r11,r10
4d 87 db                xchg   r11,r11
4d 87 e3                xchg   r11,r12
4d 87 eb                xchg   r11,r13
4d 87 f3                xchg   r11,r14
4d 87 fb                xchg   r11,r15
49 95                   xchg   r13,rax
49 87 dd                xchg   r13,rbx
49 87 cd                xchg   r13,rcx
49 87 d5                xchg   r13,rdx
49 87 fd                xchg   r13,rdi
49 87 f5                xchg   r13,rsi
49 87 e5                xchg   r13,rsp
49 87 ed                xchg   r13,rbp
4d 87 c5                xchg   r13,r8
4d 87 cd                xchg   r13,r9
4d 87 d5                xchg   r13,r10
4d 87 dd                xchg   r13,r11
4d 87 e5                xchg   r13,r12
4d 87 ed                xchg   r13,r13
4d 87 f5                xchg   r13,r14
4d 87 fd                xchg   r13,r15
49 97                   xchg   r15,rax
49 87 df                xchg   r15,rbx
49 87 cf                xchg   r15,rcx
49 87 d7                xchg   r15,rdx
49 87 ff                xchg   r15,rdi
49 87 f7                xchg   r15,rsi
49 87 e7                xchg   r15,rsp
49 87 ef                xchg   r15,rbp
4d 87 c7                xchg   r15,r8
4d 87 cf                xchg   r15,r9
4d 87 d7                xchg   r15,r10
4d 87 df                xchg   r15,r11
4d 87 e7                xchg   r15,r12
4d 87 ef                xchg   r15,r13
4d 87 f7                xchg   r15,r14
4d 87 ff                xchg   r15,r15
---
93                      xchg   ebx,eax
87 db                   xchg   ebx,ebx
87 cb                   xchg   ebx,ecx
87 d3                   xchg   ebx,edx
87 fb                   xchg   ebx,edi
87 f3                   xchg   ebx,esi
87 e3                   xchg   ebx,esp
87 eb                   xchg   ebx,ebp
91                      xchg   ecx,eax
87 d9                   xchg   ecx,ebx
87 c9                   xchg   ecx,ecx
87 d1                   xchg   ecx,edx
87 f9                   xchg   ecx,edi
87 f1                   xchg   ecx,esi
87 e1                   xchg   ecx,esp
87 e9                   xchg   ecx,ebp
97                      xchg   edi,eax
87 df                   xchg   edi,ebx
87 cf                   xchg   edi,ecx
87 d7                   xchg   edi,edx
87 ff                   xchg   edi,edi
87 f7                   xchg   edi,esi
87 e7                   xchg   edi,esp
87 ef                   xchg   edi,ebp
95                      xchg   ebp,eax
87 dd                   xchg   ebp,ebx
87 cd                   xchg   ebp,ecx
87 d5                   xchg   ebp,edx
87 fd                   xchg   ebp,edi
87 f5                   xchg   ebp,esi
87 e5                   xchg   ebp,esp
87 ed                   xchg   ebp,ebp
---
49 87 01                xchg   QWORD PTR [r9],rax
49 87 03                xchg   QWORD PTR [r11],rax
49 87 45 31             xchg   QWORD PTR [r13+0x31],rax
49 87 07                xchg   QWORD PTR [r15],rax
49 87 19                xchg   QWORD PTR [r9],rbx
49 87 1b                xchg   QWORD PTR [r11],rbx
49 87 5d 31             xchg   QWORD PTR [r13+0x31],rbx
49 87 1f                xchg   QWORD PTR [r15],rbx
49 87 09                xchg   QWORD PTR [r9],rcx
49 87 0b                xchg   QWORD PTR [r11],rcx
49 87 4d 31             xchg   QWORD PTR [r13+0x31],rcx
49 87 0f                xchg   QWORD PTR [r15],rcx
49 87 11                xchg   QWORD PTR [r9],rdx
49 87 13                xchg   QWORD PTR [r11],rdx
49 87 55 31             xchg   QWORD PTR [r13+0x31],rdx
49 87 17                xchg   QWORD PTR [r15],rdx
49 87 39                xchg   QWORD PTR [r9],rdi
49 87 3b                xchg   QWORD PTR [r11],rdi
49 87 7d 31             xchg   QWORD PTR [r13+0x31],rdi
49 87 3f                xchg   QWORD PTR [r15],rdi
49 87 31                xchg   QWORD PTR [r9],rsi
49 87 33                xchg   QWORD PTR [r11],rsi
49 87 75 31             xchg   QWORD PTR [r13+0x31],rsi
49 87 37                xchg   QWORD PTR [r15],rsi
49 87 21                xchg   QWORD PTR [r9],rsp
49 87 23                xchg   QWORD PTR [r11],rsp
49 87 65 31             xchg   QWORD PTR [r13+0x31],rsp
49 87 27                xchg   QWORD PTR [r15],rsp
49 87 29                xchg   QWORD PTR [r9],rbp
49 87 2b                xchg   QWORD PTR [r11],rbp
49 87 6d 31             xchg   QWORD PTR [r13+0x31],rbp
49 87 2f                xchg   QWORD PTR [r15],rbp
4d 87 01                xchg   QWORD PTR [r9],r8
4d 87 03                xchg   QWORD PTR [r11],r8
4d 87 45 31             xchg   QWORD PTR [r13+0x31],r8
4d 87 07                xchg   QWORD PTR [r15],r8
4d 87 09                xchg   QWORD PTR [r9],r9
4d 87 0b                xchg   QWORD PTR [r11],r9
4d 87 4d 31             xchg   QWORD PTR [r13+0x31],r9
4d 87 0f                xchg   QWORD PTR [r15],r9
4d 87 11                xchg   QWORD PTR [r9],r10
4d 87 13                xchg   QWORD PTR [r11],r10
4d 87 55 31             xchg   QWORD PTR [r13+0x31],r10
4d 87 17                xchg   QWORD PTR [r15],r10
4d 87 19                xchg   QWORD PTR [r9],r11
4d 87 1b                xchg   QWORD PTR [r11],r11
4d 87 5d 31             xchg   QWORD PTR [r13+0x31],r11
4d 87 1f                xchg   QWORD PTR [r15],r11
4d 87 21                xchg   QWORD PTR [r9],r12
4d 87 23                xchg   QWORD PTR [r11],r12
4d 87 65 31             xchg   QWORD PTR [r13+0x31],r12
4d 87 27                xchg   QWORD PTR [r15],r12
4d 87 29                xchg   QWORD PTR [r9],r13
4d 87 2b                xchg   QWORD PTR [r11],r13
4d 87 6d 31             xchg   QWORD PTR [r13+0x31],r13
4d 87 2f                xchg   QWORD PTR [r15],r13
4d 87 31                xchg   QWORD PTR [r9],r14
4d 87 33                xchg   QWORD PTR [r11],r14
4d 87 75 31             xchg   QWORD PTR [r13+0x31],r14
4d 87 37                xchg   QWORD PTR [r15],r14
4d 87 39                xchg   QWORD PTR [r9],r15
4d 87 3b                xchg   QWORD PTR [r11],r15
4d 87 7d 31             xchg   QWORD PTR [r13+0x31],r15
4d 87 3f                xchg   QWORD PTR [r15],r15
---
87 03                   xchg   DWORD PTR [rbx],eax
87 01                   xchg   DWORD PTR [rcx],eax
87 07                   xchg   DWORD PTR [rdi],eax
87 45 31                xchg   DWORD PTR [rbp+0x31],eax
41 87 01                xchg   DWORD PTR [r9],eax
41 87 03                xchg   DWORD PTR [r11],eax
41 87 45 31             xchg   DWORD PTR [r13+0x31],eax
41 87 07                xchg   DWORD PTR [r15],eax
87 1b                   xchg   DWORD PTR [rbx],ebx
87 19                   xchg   DWORD PTR [rcx],ebx
87 1f                   xchg   DWORD PTR [rdi],ebx
87 5d 31                xchg   DWORD PTR [rbp+0x31],ebx
41 87 19                xchg   DWORD PTR [r9],ebx
41 87 1b                xchg   DWORD PTR [r11],ebx
41 87 5d 31             xchg   DWORD PTR [r13+0x31],ebx
41 87 1f                xchg   DWORD PTR [r15],ebx
87 0b                   xchg   DWORD PTR [rbx],ecx
87 09                   xchg   DWORD PTR [rcx],ecx
87 0f                   xchg   DWORD PTR [rdi],ecx
87 4d 31                xchg   DWORD PTR [rbp+0x31],ecx
41 87 09                xchg   DWORD PTR [r9],ecx
41 87 0b                xchg   DWORD PTR [r11],ecx
41 87 4d 31             xchg   DWORD PTR [r13+0x31],ecx
41 87 0f                xchg   DWORD PTR [r15],ecx
87 13                   xchg   DWORD PTR [rbx],edx
87 11                   xchg   DWORD PTR [rcx],edx
87 17                   xchg   DWORD PTR [rdi],edx
87 55 31                xchg   DWORD PTR [rbp+0x31],edx
41 87 11                xchg   DWORD PTR [r9],edx
41 87 13                xchg   DWORD PTR [r11],edx
41 87 55 31             xchg   DWORD PTR [r13+0x31],edx
41 87 17                xchg   DWORD PTR [r15],edx
87 3b                   xchg   DWORD PTR [rbx],edi
87 39                   xchg   DWORD PTR [rcx],edi
87 3f                   xchg   DWORD PTR [rdi],edi
87 7d 31                xchg   DWORD PTR [rbp+0x31],edi
41 87 39                xchg   DWORD PTR [r9],edi
41 87 3b                xchg   DWORD PTR [r11],edi
41 87 7d 31             xchg   DWORD PTR [r13+0x31],edi
41 87 3f                xchg   DWORD PTR [r15],edi
87 33                   xchg   DWORD PTR [rbx],esi
87 31                   xchg   DWORD PTR [rcx],esi
87 37                   xchg   DWORD PTR [rdi],esi
87 75 31                xchg   DWORD PTR [rbp+0x31],esi
41 87 31                xchg   DWORD PTR [r9],esi
41 87 33                xchg   DWORD PTR [r11],esi
41 87 75 31             xchg   DWORD PTR [r13+0x31],esi
41 87 37                xchg   DWORD PTR [r15],esi
87 23                   xchg   DWORD PTR [rbx],esp
87 21                   xchg   DWORD PTR [rcx],esp
87 27                   xchg   DWORD PTR [rdi],esp
87 65 31                xchg   DWORD PTR [rbp+0x31],esp
41 87 21                xchg   DWORD PTR [r9],esp
41 87 23                xchg   DWORD PTR [r11],esp
41 87 65 31             xchg   DWORD PTR [r13+0x31],esp
41 87 27                xchg   DWORD PTR [r15],esp
87 2b                   xchg   DWORD PTR [rbx],ebp
87 29                   xchg   DWORD PTR [rcx],ebp
87 2f                   xchg   DWORD PTR [rdi],ebp
87 6d 31                xchg   DWORD PTR [rbp+0x31],ebp
41 87 29                xchg   DWORD PTR [r9],ebp
41 87 2b                xchg   DWORD PTR [r11],ebp
41 87 6d 31             xchg   DWORD PTR [r13+0x31],ebp
41 87 2f                xchg   DWORD PTR [r15],ebp




49 31 c1                xor    r9,rax
49 31 d9                xor    r9,rbx
49 31 c9                xor    r9,rcx
49 31 d1                xor    r9,rdx
49 31 f9                xor    r9,rdi
49 31 f1                xor    r9,rsi
49 31 e1                xor    r9,rsp
49 31 e9                xor    r9,rbp
4d 31 c1                xor    r9,r8
4d 31 c9                xor    r9,r9
4d 31 d1                xor    r9,r10
4d 31 d9                xor    r9,r11
4d 31 e1                xor    r9,r12
4d 31 e9                xor    r9,r13
4d 31 f1                xor    r9,r14
4d 31 f9                xor    r9,r15
49 31 c3                xor    r11,rax
49 31 db                xor    r11,rbx
49 31 cb                xor    r11,rcx
49 31 d3                xor    r11,rdx
49 31 fb                xor    r11,rdi
49 31 f3                xor    r11,rsi
49 31 e3                xor    r11,rsp
49 31 eb                xor    r11,rbp
4d 31 c3                xor    r11,r8
4d 31 cb                xor    r11,r9
4d 31 d3                xor    r11,r10
4d 31 db                xor    r11,r11
4d 31 e3                xor    r11,r12
4d 31 eb                xor    r11,r13
4d 31 f3                xor    r11,r14
4d 31 fb                xor    r11,r15
49 31 c5                xor    r13,rax
49 31 dd                xor    r13,rbx
49 31 cd                xor    r13,rcx
49 31 d5                xor    r13,rdx
49 31 fd                xor    r13,rdi
49 31 f5                xor    r13,rsi
49 31 e5                xor    r13,rsp
49 31 ed                xor    r13,rbp
4d 31 c5                xor    r13,r8
4d 31 cd                xor    r13,r9
4d 31 d5                xor    r13,r10
4d 31 dd                xor    r13,r11
4d 31 e5                xor    r13,r12
4d 31 ed                xor    r13,r13
4d 31 f5                xor    r13,r14
4d 31 fd                xor    r13,r15
49 31 c7                xor    r15,rax
49 31 df                xor    r15,rbx
49 31 cf                xor    r15,rcx
49 31 d7                xor    r15,rdx
49 31 ff                xor    r15,rdi
49 31 f7                xor    r15,rsi
49 31 e7                xor    r15,rsp
49 31 ef                xor    r15,rbp
4d 31 c7                xor    r15,r8
4d 31 cf                xor    r15,r9
4d 31 d7                xor    r15,r10
4d 31 df                xor    r15,r11
4d 31 e7                xor    r15,r12
4d 31 ef                xor    r15,r13
4d 31 f7                xor    r15,r14
4d 31 ff                xor    r15,r15
---
31 c3                   xor    ebx,eax
31 db                   xor    ebx,ebx
31 cb                   xor    ebx,ecx
31 d3                   xor    ebx,edx
31 fb                   xor    ebx,edi
31 f3                   xor    ebx,esi
31 e3                   xor    ebx,esp
31 eb                   xor    ebx,ebp
31 c1                   xor    ecx,eax
31 d9                   xor    ecx,ebx
31 c9                   xor    ecx,ecx
31 d1                   xor    ecx,edx
31 f9                   xor    ecx,edi
31 f1                   xor    ecx,esi
31 e1                   xor    ecx,esp
31 e9                   xor    ecx,ebp
31 c7                   xor    edi,eax
31 df                   xor    edi,ebx
31 cf                   xor    edi,ecx
31 d7                   xor    edi,edx
31 ff                   xor    edi,edi
31 f7                   xor    edi,esi
31 e7                   xor    edi,esp
31 ef                   xor    edi,ebp
31 c5                   xor    ebp,eax
31 dd                   xor    ebp,ebx
31 cd                   xor    ebp,ecx
31 d5                   xor    ebp,edx
31 fd                   xor    ebp,edi
31 f5                   xor    ebp,esi
31 e5                   xor    ebp,esp
31 ed                   xor    ebp,ebp
---
49 33 01                xor    rax,QWORD PTR [r9]
49 33 03                xor    rax,QWORD PTR [r11]
49 33 45 31             xor    rax,QWORD PTR [r13+0x31]
49 33 07                xor    rax,QWORD PTR [r15]
49 33 19                xor    rbx,QWORD PTR [r9]
49 33 1b                xor    rbx,QWORD PTR [r11]
49 33 5d 31             xor    rbx,QWORD PTR [r13+0x31]
49 33 1f                xor    rbx,QWORD PTR [r15]
49 33 09                xor    rcx,QWORD PTR [r9]
49 33 0b                xor    rcx,QWORD PTR [r11]
49 33 4d 31             xor    rcx,QWORD PTR [r13+0x31]
49 33 0f                xor    rcx,QWORD PTR [r15]
49 33 11                xor    rdx,QWORD PTR [r9]
49 33 13                xor    rdx,QWORD PTR [r11]
49 33 55 31             xor    rdx,QWORD PTR [r13+0x31]
49 33 17                xor    rdx,QWORD PTR [r15]
49 33 39                xor    rdi,QWORD PTR [r9]
49 33 3b                xor    rdi,QWORD PTR [r11]
49 33 7d 31             xor    rdi,QWORD PTR [r13+0x31]
49 33 3f                xor    rdi,QWORD PTR [r15]
49 33 31                xor    rsi,QWORD PTR [r9]
49 33 33                xor    rsi,QWORD PTR [r11]
49 33 75 31             xor    rsi,QWORD PTR [r13+0x31]
49 33 37                xor    rsi,QWORD PTR [r15]
49 33 21                xor    rsp,QWORD PTR [r9]
49 33 23                xor    rsp,QWORD PTR [r11]
49 33 65 31             xor    rsp,QWORD PTR [r13+0x31]
49 33 27                xor    rsp,QWORD PTR [r15]
49 33 29                xor    rbp,QWORD PTR [r9]
49 33 2b                xor    rbp,QWORD PTR [r11]
49 33 6d 31             xor    rbp,QWORD PTR [r13+0x31]
49 33 2f                xor    rbp,QWORD PTR [r15]
4d 33 01                xor    r8,QWORD PTR [r9]
4d 33 03                xor    r8,QWORD PTR [r11]
4d 33 45 31             xor    r8,QWORD PTR [r13+0x31]
4d 33 07                xor    r8,QWORD PTR [r15]
4d 33 09                xor    r9,QWORD PTR [r9]
4d 33 0b                xor    r9,QWORD PTR [r11]
4d 33 4d 31             xor    r9,QWORD PTR [r13+0x31]
4d 33 0f                xor    r9,QWORD PTR [r15]
4d 33 11                xor    r10,QWORD PTR [r9]
4d 33 13                xor    r10,QWORD PTR [r11]
4d 33 55 31             xor    r10,QWORD PTR [r13+0x31]
4d 33 17                xor    r10,QWORD PTR [r15]
4d 33 19                xor    r11,QWORD PTR [r9]
4d 33 1b                xor    r11,QWORD PTR [r11]
4d 33 5d 31             xor    r11,QWORD PTR [r13+0x31]
4d 33 1f                xor    r11,QWORD PTR [r15]
4d 33 21                xor    r12,QWORD PTR [r9]
4d 33 23                xor    r12,QWORD PTR [r11]
4d 33 65 31             xor    r12,QWORD PTR [r13+0x31]
4d 33 27                xor    r12,QWORD PTR [r15]
4d 33 29                xor    r13,QWORD PTR [r9]
4d 33 2b                xor    r13,QWORD PTR [r11]
4d 33 6d 31             xor    r13,QWORD PTR [r13+0x31]
4d 33 2f                xor    r13,QWORD PTR [r15]
4d 33 31                xor    r14,QWORD PTR [r9]
4d 33 33                xor    r14,QWORD PTR [r11]
4d 33 75 31             xor    r14,QWORD PTR [r13+0x31]
4d 33 37                xor    r14,QWORD PTR [r15]
4d 33 39                xor    r15,QWORD PTR [r9]
4d 33 3b                xor    r15,QWORD PTR [r11]
4d 33 7d 31             xor    r15,QWORD PTR [r13+0x31]
4d 33 3f                xor    r15,QWORD PTR [r15]
---
33 03                   xor    eax,DWORD PTR [rbx]
33 01                   xor    eax,DWORD PTR [rcx]
33 07                   xor    eax,DWORD PTR [rdi]
33 45 31                xor    eax,DWORD PTR [rbp+0x31]
41 33 01                xor    eax,DWORD PTR [r9]
41 33 03                xor    eax,DWORD PTR [r11]
41 33 45 31             xor    eax,DWORD PTR [r13+0x31]
41 33 07                xor    eax,DWORD PTR [r15]
33 1b                   xor    ebx,DWORD PTR [rbx]
33 19                   xor    ebx,DWORD PTR [rcx]
33 1f                   xor    ebx,DWORD PTR [rdi]
33 5d 31                xor    ebx,DWORD PTR [rbp+0x31]
41 33 19                xor    ebx,DWORD PTR [r9]
41 33 1b                xor    ebx,DWORD PTR [r11]
41 33 5d 31             xor    ebx,DWORD PTR [r13+0x31]
41 33 1f                xor    ebx,DWORD PTR [r15]
33 0b                   xor    ecx,DWORD PTR [rbx]
33 09                   xor    ecx,DWORD PTR [rcx]
33 0f                   xor    ecx,DWORD PTR [rdi]
33 4d 31                xor    ecx,DWORD PTR [rbp+0x31]
41 33 09                xor    ecx,DWORD PTR [r9]
41 33 0b                xor    ecx,DWORD PTR [r11]
41 33 4d 31             xor    ecx,DWORD PTR [r13+0x31]
41 33 0f                xor    ecx,DWORD PTR [r15]
33 13                   xor    edx,DWORD PTR [rbx]
33 11                   xor    edx,DWORD PTR [rcx]
33 17                   xor    edx,DWORD PTR [rdi]
33 55 31                xor    edx,DWORD PTR [rbp+0x31]
41 33 11                xor    edx,DWORD PTR [r9]
41 33 13                xor    edx,DWORD PTR [r11]
41 33 55 31             xor    edx,DWORD PTR [r13+0x31]
41 33 17                xor    edx,DWORD PTR [r15]
33 3b                   xor    edi,DWORD PTR [rbx]
33 39                   xor    edi,DWORD PTR [rcx]
33 3f                   xor    edi,DWORD PTR [rdi]
33 7d 31                xor    edi,DWORD PTR [rbp+0x31]
41 33 39                xor    edi,DWORD PTR [r9]
41 33 3b                xor    edi,DWORD PTR [r11]
41 33 7d 31             xor    edi,DWORD PTR [r13+0x31]
41 33 3f                xor    edi,DWORD PTR [r15]
33 33                   xor    esi,DWORD PTR [rbx]
33 31                   xor    esi,DWORD PTR [rcx]
33 37                   xor    esi,DWORD PTR [rdi]
33 75 31                xor    esi,DWORD PTR [rbp+0x31]
41 33 31                xor    esi,DWORD PTR [r9]
41 33 33                xor    esi,DWORD PTR [r11]
41 33 75 31             xor    esi,DWORD PTR [r13+0x31]
41 33 37                xor    esi,DWORD PTR [r15]
33 23                   xor    esp,DWORD PTR [rbx]
33 21                   xor    esp,DWORD PTR [rcx]
33 27                   xor    esp,DWORD PTR [rdi]
33 65 31                xor    esp,DWORD PTR [rbp+0x31]
41 33 21                xor    esp,DWORD PTR [r9]
41 33 23                xor    esp,DWORD PTR [r11]
41 33 65 31             xor    esp,DWORD PTR [r13+0x31]
41 33 27                xor    esp,DWORD PTR [r15]
33 2b                   xor    ebp,DWORD PTR [rbx]
33 29                   xor    ebp,DWORD PTR [rcx]
33 2f                   xor    ebp,DWORD PTR [rdi]
33 6d 31                xor    ebp,DWORD PTR [rbp+0x31]
41 33 29                xor    ebp,DWORD PTR [r9]
41 33 2b                xor    ebp,DWORD PTR [r11]
41 33 6d 31             xor    ebp,DWORD PTR [r13+0x31]
41 33 2f                xor    ebp,DWORD PTR [r15]
---
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
---
67 31 43 31             xor    DWORD PTR [ebx+0x31],eax
67 31 4b 31             xor    DWORD PTR [ebx+0x31],ecx
67 31 53 31             xor    DWORD PTR [ebx+0x31],edx
67 31 41 31             xor    DWORD PTR [ecx+0x31],eax
67 31 59 31             xor    DWORD PTR [ecx+0x31],ebx
67 31 51 31             xor    DWORD PTR [ecx+0x31],edx




49 8d 01                lea    rax,[r9]
49 8d 03                lea    rax,[r11]
49 8d 45 31             lea    rax,[r13+0x31]
49 8d 07                lea    rax,[r15]
49 8d 19                lea    rbx,[r9]
49 8d 1b                lea    rbx,[r11]
49 8d 5d 31             lea    rbx,[r13+0x31]
49 8d 1f                lea    rbx,[r15]
49 8d 09                lea    rcx,[r9]
49 8d 0b                lea    rcx,[r11]
49 8d 4d 31             lea    rcx,[r13+0x31]
49 8d 0f                lea    rcx,[r15]
49 8d 11                lea    rdx,[r9]
49 8d 13                lea    rdx,[r11]
49 8d 55 31             lea    rdx,[r13+0x31]
49 8d 17                lea    rdx,[r15]
49 8d 39                lea    rdi,[r9]
49 8d 3b                lea    rdi,[r11]
49 8d 7d 31             lea    rdi,[r13+0x31]
49 8d 3f                lea    rdi,[r15]
49 8d 31                lea    rsi,[r9]
49 8d 33                lea    rsi,[r11]
49 8d 75 31             lea    rsi,[r13+0x31]
49 8d 37                lea    rsi,[r15]
49 8d 21                lea    rsp,[r9]
49 8d 23                lea    rsp,[r11]
49 8d 65 31             lea    rsp,[r13+0x31]
49 8d 27                lea    rsp,[r15]
49 8d 29                lea    rbp,[r9]
49 8d 2b                lea    rbp,[r11]
49 8d 6d 31             lea    rbp,[r13+0x31]
49 8d 2f                lea    rbp,[r15]
4d 8d 01                lea    r8,[r9]
4d 8d 03                lea    r8,[r11]
4d 8d 45 31             lea    r8,[r13+0x31]
4d 8d 07                lea    r8,[r15]
4d 8d 09                lea    r9,[r9]
4d 8d 0b                lea    r9,[r11]
4d 8d 4d 31             lea    r9,[r13+0x31]
4d 8d 0f                lea    r9,[r15]
4d 8d 11                lea    r10,[r9]
4d 8d 13                lea    r10,[r11]
4d 8d 55 31             lea    r10,[r13+0x31]
4d 8d 17                lea    r10,[r15]
4d 8d 19                lea    r11,[r9]
4d 8d 1b                lea    r11,[r11]
4d 8d 5d 31             lea    r11,[r13+0x31]
4d 8d 1f                lea    r11,[r15]
4d 8d 21                lea    r12,[r9]
4d 8d 23                lea    r12,[r11]
4d 8d 65 31             lea    r12,[r13+0x31]
4d 8d 27                lea    r12,[r15]
4d 8d 29                lea    r13,[r9]
4d 8d 2b                lea    r13,[r11]
4d 8d 6d 31             lea    r13,[r13+0x31]
4d 8d 2f                lea    r13,[r15]
4d 8d 31                lea    r14,[r9]
4d 8d 33                lea    r14,[r11]
4d 8d 75 31             lea    r14,[r13+0x31]
4d 8d 37                lea    r14,[r15]
4d 8d 39                lea    r15,[r9]
4d 8d 3b                lea    r15,[r11]
4d 8d 7d 31             lea    r15,[r13+0x31]
4d 8d 3f                lea    r15,[r15]
---
8d 03                   lea    eax,[rbx]
8d 01                   lea    eax,[rcx]
8d 07                   lea    eax,[rdi]
8d 45 31                lea    eax,[rbp+0x31]
41 8d 01                lea    eax,[r9]
41 8d 03                lea    eax,[r11]
41 8d 45 31             lea    eax,[r13+0x31]
41 8d 07                lea    eax,[r15]
8d 1b                   lea    ebx,[rbx]
8d 19                   lea    ebx,[rcx]
8d 1f                   lea    ebx,[rdi]
8d 5d 31                lea    ebx,[rbp+0x31]
41 8d 19                lea    ebx,[r9]
41 8d 1b                lea    ebx,[r11]
41 8d 5d 31             lea    ebx,[r13+0x31]
41 8d 1f                lea    ebx,[r15]
8d 0b                   lea    ecx,[rbx]
8d 09                   lea    ecx,[rcx]
8d 0f                   lea    ecx,[rdi]
8d 4d 31                lea    ecx,[rbp+0x31]
41 8d 09                lea    ecx,[r9]
41 8d 0b                lea    ecx,[r11]
41 8d 4d 31             lea    ecx,[r13+0x31]
41 8d 0f                lea    ecx,[r15]
8d 13                   lea    edx,[rbx]
8d 11                   lea    edx,[rcx]
8d 17                   lea    edx,[rdi]
8d 55 31                lea    edx,[rbp+0x31]
41 8d 11                lea    edx,[r9]
41 8d 13                lea    edx,[r11]
41 8d 55 31             lea    edx,[r13+0x31]
41 8d 17                lea    edx,[r15]
8d 3b                   lea    edi,[rbx]
8d 39                   lea    edi,[rcx]
8d 3f                   lea    edi,[rdi]
8d 7d 31                lea    edi,[rbp+0x31]
41 8d 39                lea    edi,[r9]
41 8d 3b                lea    edi,[r11]
41 8d 7d 31             lea    edi,[r13+0x31]
41 8d 3f                lea    edi,[r15]
8d 33                   lea    esi,[rbx]
8d 31                   lea    esi,[rcx]
8d 37                   lea    esi,[rdi]
8d 75 31                lea    esi,[rbp+0x31]
41 8d 31                lea    esi,[r9]
41 8d 33                lea    esi,[r11]
41 8d 75 31             lea    esi,[r13+0x31]
41 8d 37                lea    esi,[r15]
8d 23                   lea    esp,[rbx]
8d 21                   lea    esp,[rcx]
8d 27                   lea    esp,[rdi]
8d 65 31                lea    esp,[rbp+0x31]
41 8d 21                lea    esp,[r9]
41 8d 23                lea    esp,[r11]
41 8d 65 31             lea    esp,[r13+0x31]
41 8d 27                lea    esp,[r15]
8d 2b                   lea    ebp,[rbx]
8d 29                   lea    ebp,[rcx]
8d 2f                   lea    ebp,[rdi]
8d 6d 31                lea    ebp,[rbp+0x31]
41 8d 29                lea    ebp,[r9]
41 8d 2b                lea    ebp,[r11]
41 8d 6d 31             lea    ebp,[r13+0x31]
41 8d 2f                lea    ebp,[r15]
---






ff cb                   dec    ebx
ff c9                   dec    ecx
ff cf                   dec    edi
ff cd                   dec    ebp
49 ff c9                dec    r9
49 ff cb                dec    r11
49 ff cd                dec    r13
49 ff cf                dec    r13

ff c3                   inc    ebx
ff c1                   inc    ecx
ff c7                   inc    edi
ff c5                   inc    ebp
49 ff c1                inc    r9
49 ff c3                inc    r11
49 ff c5                inc    r13
49 ff c7                inc    r13



53                      push   rbx
51                      push   rcx
57                      push   rdi
55                      push   rbp
41 51                   push   r9
41 53                   push   r11
41 55                   push   r13
41 57                   push   r15
5b                      pop    rbx
59                      pop    rcx
5f                      pop    rdi
5d                      pop    rbp
41 59                   pop    r9
41 5b                   pop    r11
41 5d                   pop    r13
41 5f                   pop    r15

c1 e3 03                shl    ebx,0x3
c1 e1 03                shl    ecx,0x3
c1 e7 03                shl    edi,0x3
c1 e5 03                shl    ebp,0x3
d3 e3                   shl    ebx,cl
d3 e1                   shl    ecx,cl
d3 e7                   shl    edi,cl
d3 e5                   shl    ebp,cl
d3 eb                   shr    ebx,cl
d3 e9                   shr    ecx,cl
d3 ef                   shr    edi,cl


c3                      ret
c9                      leave

0f 05                   syscall
```

**References**
- https://ctftime.org/writeup/34832
- https://marcosvalle.github.io/re/exploit/2018/09/02/odd-even-encoder.html
</p>
</details>

<details>
<summary><h2>Get opcode from binary</h2></summary>
<p>

```
objdump -d <Name of program>|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/\ $//g'|sed 's/\ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

**References**
- https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump
</p>
</details>

<details>
<summary><h2>movaps xmm0,... </h2></summary>
<p>

Register rsp (esp) address must end with byte 0x00, 0x10, 0x20, 0x30... or it will cause error.</br>
- Ex: if rsp address end with 0xe8 --> segfault.

</p>
</details>

<details>
<summary><h2>format string </h2></summary>
<p>

**Basic**
- `%p%p%p%n` will write and access easily.
- `%4$n` will write but cannot access.
- Payload should have `%c` instead `%x` to make sure it write a byte, **not** a random byte on stack.
- Enter `.` to `scanf()` with number format (`%d`, `%u`, `%ld`...) won't enter new value to var.

**Advance**
- `%*c`: print padding that %c is pointing to (full form)
- `%*<k>$c`: print padding that %c is pointing to (short form)
- `%<k>$<padding>c`: print value that %c is pointing to with padding
- Format string can be use to modify and read data at the same time just in case you don't use the short format (`%<k>$c`), use the plain format instead (`%p`, `%n`, `%s`, `%c`).
    - Example: `%c%c%c%c%1234c%hn%6$s` to change address and read from that changed address
- From man page: `printf("%*d", width, num);` == `printf("%2$*1$d", width, num);`

</p>
</details>

<details>
    <summary><h2>Z3</h2></summary>

<p>
BitVec when you want to solve multiplication:

```python
>>> x = BitVec('x', 8)
>>> y = BitVec('y', 8)
>>> x_ext = ZeroExt(24, x)      # x_ext is 32bit because of 8 + 24
>>> y_ext = ZeroExt(24, y)      # y_ext is 32bit because of 8 + 24
>>> solve(x_ext*y_ext == 64770)
[y = 254, x = 255]
```

If you solve without ZeroExt, result is diffent
```python
>>> x = BitVec('x', 8)
>>> y = BitVec('y', 8)
>>> solve(x*y == 64770)
[x = 2, y = 1]
```

</p>
</details>


<details>
    <summary><h2>Kernel stuff</h2></summary>

<p>

Compress image:

```
#!/bin/bash

strip_option=1

while getopts "c:f:nl:L:sd" opt; do
  case $opt in
    c) c="$OPTARG";;
    f) f="${OPTARG%/}";;
    n) no_gzip=1;;
    l) 
        if [ -z "$lflags" ]; then
            lflags="-l$OPTARG"
        else
            lflags+=" -l$OPTARG"
        fi
        ;;
    L)
        if [ -z "$lflags" ]; then
            lflags="/usr/lib/x86_64-linux-gnu/lib$OPTARG.a"
        else
            lflags+=" /usr/lib/x86_64-linux-gnu/lib$OPTARG.a"
        fi
        ;;
    s) static=1;;
    d) strip_option=;;
  esac
done

if [ -n "$f" ]; then
    if [ -n "$c" ]; then
        read -ra files <<< "$c"
        file_name=$(basename "${files[0]}")
        if [ -n "$lflags" ]; then
            if [ -n "$static" ]; then
                gcc_options="-static $c $lflags"
            else
                gcc_options="$c $lflags"
            fi
        else
            if [ -n "$static" ]; then
                gcc_options="-static $c"
            else
                gcc_options="$c"
            fi
        fi
    fi

    if [ -n "$gcc_options" ]; then
        if [ -n "$strip_option" ]; then
            gcc_options+=" -s"
        fi
        gcc -o "$f/${file_name%.c}" $gcc_options
    fi

    cd $f
    if [ "$no_gzip" ]; then
        find . | cpio -o -H newc -R root:root > "../$f.cpio"
    else
        find . | cpio -o -H newc -R root:root | gzip -9 > "../$f.cpio.gz"
    fi
    cd ..
fi
```



</p>
</details>

<details>
    <summary><h2>Creating challenge</h2></summary>

<p>

Canary mode:
- `-fno-stack-protector`: No canary
- `-fstack-protector`: Turn on canary of a function when local buffer is < 8 bytes
- `--param ssp-buffer-size=<k>`: Used with `-fstack-protector` to specify if local buffer larger than `<k>` bytes, then add canary to that function
- `-fstack-full-protector` (default): Turn on canary for all functions

No RelRO: `-z norelro`

No NX: `-z execstack`

No pie: `-no-pie`

Static built: `-static`

Write seccomp rule: https://blog.yadutaf.fr/2014/05/29/introduction-to-seccomp-bpf-linux-syscall-filter/


</p>
</details>

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
<summary>GDB Attach</summary>
<p>

### Attach GDB to running process in docker

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
<summary><h3>Another version for gdb.attach()</h3></summary>
<p>

Using [x-terminal-emulator](https://www.systutorials.com/docs/linux/man/1-x-terminal-emulator/) to create popup shell and pass command in a file.

- Intel debug

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

- Arm debug

```python
def GDB(filename, port):
    q = process(f"/usr/bin/x-terminal-emulator --geometry 960x1080+960+0 -x gdb-multiarch -q --nh -ex 'source ~/.gef-283690ae9bfcecbb3deb80cd275d327c46b276b5.py' -ex 'set architecture arm64' -ex 'file {filename}' -ex 'target remote localhost:{port}'", shell=True)


port = 1234
filename = ''
p = process(f'qemu-aarch64 -L /usr/aarch64-linux-gnu -g {port} {filename}'.split())
GDB(filename, port)
```

- Kernel debug (add before qemu command, add `-s` to qemu, using wsl2 ubuntu 20.04)

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
<summary><h3>GDB show data when stop</h3></summary>
<p>

### GDB show data when stop

You can read [this blog](https://www.cse.unsw.edu.au/~learn/debugging/modules/gdb_watch_display/) for example.

- watch

```
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

</p>
</details>

<details>
<summary><h3>GDB disable "Type return to continue..."</h3></summary>
<p>

I got it from https://stackoverflow.com/questions/28815621/how-to-disable-type-return-to-continue-or-q-return-to-quit-in-gdb

```
(gdb) set pagination off
```

</p>
</details>

<details>
<summary><h3>GDB disable "Quit anyway?..."</h3></summary>
<p>

I got it from https://stackoverflow.com/questions/4355978/get-rid-of-quit-anyway-prompt-using-gdb-just-kill-the-process-and-quit

```
(gdb) set confirm off
```

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
<summary><h3>gdb</h3></summary>
<p>

- `r < <()` can pass null byte, `r <<<$()` cannot.

- `flag +/-ZERO` to set or remove flag.

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

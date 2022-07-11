# vsCTF 2022 - EzOrange

File [ezorange_docker.zip](ezorange_docker.zip) is docker & solve script & source code.

File [ezorange.zip](ezorange.zip) will be published to player.

### Difficulty: Medium

### Solution

There are no `free()` and `Our-of-bound` bug in modifying cell of orange. Also we will use technique house of orange for this challenge too.

One thing to notice is that in libc 2.32, there is a xor mechanism added to modify the forward pointer of tcache before it is written to chunk. More information can be found on gg with the word `safe-linking libc 2.32` or from source [here](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2933):

```c
#define PROTECT_PTR(pos, ptr) \
    ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

The solution can be divided into 3 stage:

- Stage 1: Leak heap address

Overwrite size of topchunk, malloc with a large number which larger than overwritten size of topchunk and we can trigger that topchunk to be freed. Then modify cell to leak address.

- Stage 2: Leak libc address

Use technique of house of orange to have 2 freed chunk in tcache, then overwrite forward pointer of 1 chunk to `alarm@got` and malloc, then read the address of alarm and get the libc base address.

- Stage 3: Again, free 2 chunk to make them go to tcache and overwrite the forward pointer with `__malloc_hook`, then malloc 2 times to overwrite `__malloc_hook` with `one_gadget`
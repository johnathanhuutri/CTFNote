# [Technique] Heap exploitation

If you're not familiar with heap exploitation and all types of chunks, read this blog for a better approach: https://guyinatuxedo.github.io/25-heap/index.html

This post is just about all small stuffs and things I want to note. For a full technique, please refer this page: https://github.com/shellphish/how2heap

---

Table of content:
- Tcache

# Tcache

### Double free
- For libc <= 2.28, we just simply free() a chunk twice.
- For libc > 2.28, there will be a key inserted to freed chunk when this chunk goes to tcache. To do a double free, we first free() a chunk, then change the key (Bk pointer) to another value and free() again:

```gdb
               malloc(0x20)
                    ↓
-----------------------------------------
| 0x0000000000000000 0x0000000000000031 |    <-- prev_size / size
| 0x0000000000000000 0x0000000000000000 |
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
                    ↓
                  free()
                    ↓
-----------------------------------------
| 0x0000000000000000 0x0000000000000031 |    <-- prev_size  / size
| 0x0000000000000000 0x000055555555b010 |    <-- Fw pointer / Bk pointer (key)
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
                    ↓
          Change key (Bk pointer)
                    ↓
-----------------------------------------
| 0x0000000000000000 0x0000000000000031 |    <-- prev_size  / size
| 0x0000000000000000 0x0000000000000001 |    <-- Fw pointer / Bk pointer (key)
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
                    ↓
               free() again
                    ↓
-----------------------------------------
| 0x0000000000000000 0x0000000000000031 |    <-- prev_size  / size
| 0x000055555555b260 0x000055555555b010 |    <-- Fw pointer / Bk pointer (key)
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
```

### Forward pointer
- For libc <= 2.31, when we free a chunk and it goes to tcache, the forward pointer of this chunk will be changed into the address of the next chunk if this next chunk exist and will be null if there is no next chunk:

```gdb
------------------------- Chunk 1 ------------------------
| 0x555555559290: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x5555555592a0: 0x0000000000000000  0x0000555555559010 |    <-- Fw pointer / Bk pointer (key)
| 0x5555555592b0: 0x0000000000000000  0x0000000000000000 |
------------------------- Chunk 2 ------------------------
| 0x5555555592c0: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x5555555592d0: 0x00005555555592a0  0x0000555555559010 |    <-- Fw pointer / Bk pointer (key)
| 0x5555555592e0: 0x0000000000000000  0x0000000000000000 |
----------------------------------------------------------
```

We can see that after free Chunk 1, it will go to tcache. But because there are no freed chunk with the same size as `0x30` in tcache so the `Fw pointer` of Chunk 1 is null.

For the Chunk 2, because we've freed the Chunk 1 and this Chunk 2 has the same size as `0x30` with Chunk 1, so when we free Chunk 2, it will go to tcache and make the `Fw pointer` point to Chunk 1.

- For libc > 2.31, there is a xor mechanism added to change the behaviour of `Fw pointer`:

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
```

`pos` is the address of current chunk is being freed and `ptr` is the address of previous freed chunk has the same size with chunk at `pos`. For a better view, here is an example:

```gdb
------------------------- Chunk 1 ------------------------
| 0x55555555a290: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x55555555a2a0: 0x0000000000000000  0x0000000000000000 |
| 0x55555555a2b0: 0x0000000000000000  0x0000000000000000 |
------------------------- Chunk 2 ------------------------
| 0x55555555a2c0: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x55555555a2d0: 0x0000000000000000  0x0000000000000000 |
| 0x55555555a2e0: 0x0000000000000000  0x0000000000000000 |
----------------------------------------------------------
                            ↓
                      free(Chunk 1)
                            ↓
------------------------- Chunk 1 ------------------------
| 0x55555555a290: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x55555555a2a0: 0x000000055555555a  0x000055555555a010 |    <-- Fw pointer / Bk pointer (key)
| 0x55555555a2b0: 0x0000000000000000  0x0000000000000000 |
------------------------- Chunk 2 ------------------------
| 0x55555555a2c0: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x55555555a2d0: 0x0000000000000000  0x0000000000000000 |    <-- Fw pointer / Bk pointer (key)
| 0x55555555a2e0: 0x0000000000000000  0x0000000000000000 |
----------------------------------------------------------
```

Can you see the `Fw pointer` of Chunk 1 changed? The value `0x000000055555555a` is the result from the xor mechanism:

```python
>>> # Fw pointer =  (<Address of chunk freeing> >> 12) ^ <Address of previous freed chunk>
>>> (0x55555555a2a0 >> 12) ^ 0
0x000000055555555a
```

Because there were no freed chunk before Chunk 1 so `<Address of previous freed chunk>` will be null.

Continue freeing the Chunk 2 and we can see this:

```gdb
------------------------- Chunk 1 ------------------------
| 0x55555555a290: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x55555555a2a0: 0x000000055555555a  0x000055555555a010 |    <-- Fw pointer / Bk pointer (key)
| 0x55555555a2b0: 0x0000000000000000  0x0000000000000000 |
------------------------- Chunk 2 ------------------------
| 0x55555555a2c0: 0x0000000000000000  0x0000000000000031 |    <-- prev_size  / size
| 0x55555555a2d0: 0x000055500000f7fa  0x000055555555a010 |    <-- Fw pointer / Bk pointer (key)
| 0x55555555a2e0: 0x0000000000000000  0x0000000000000000 |
----------------------------------------------------------
```

So the `Fw pointer` for Chunk 2 can be calculate as:

```python
>>> # Fw pointer =  (<Address of chunk freeing> >> 12) ^ <Address of previous freed chunk>
>>> (0x55555555a2d0 >> 12) ^ 0x55555555a2a0
0x55500000f7fa
```

Chunk 1 was the previous freed chunk which has the same size as Chunk 2 so after we freed Chunk 1, we freed Chunk 2 next and the forward pointer will be `0x55500000f7fa` due to the xor mechanism.

Remember that the address of Chunk 1 is `0x55555555a2a0` and Chunk 2 is `0x55555555a2d0`, not include the metadata of each chunk.

<!-- ###  -->
---

<detail>
<summary>**Create and free custom chunk**</summary>
<p>

```
abcd

asf
da
sd
f
ads
```

</p>
</detail>
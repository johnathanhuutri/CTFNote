# [Technique] Heap exploitation

If you're not familiar with heap exploitation and all types of chunks, read this blog for a better approach: https://guyinatuxedo.github.io/25-heap/index.html

This post is just about all small stuffs and things I want to note. For a full technique, please refer this page: https://github.com/shellphish/how2heap

---

Table of content:
- Tcache

# Tcache

**Double free**
- For libc <= 2.28, we just simply free() a chunk twice.
- For libc > 2.28, there will be a key inserted to freed chunk when this chunk goes to tcache. To do a double free, we first free() a chunk, then change this key to another value and free() again:

```bash
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
| 0x0000000000000000 0x000055555555b010 |    <-- Fw pointer / Bw pointer (key)
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
                    ↓
          Change key (Bw pointer)
                    ↓
-----------------------------------------
| 0x0000000000000000 0x0000000000000031 |    <-- prev_size  / size
| 0x0000000000000000 0x0000000000000001 |    <-- Fw pointer / Bw pointer (key)
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
                    ↓
               free() again
                    ↓
-----------------------------------------
| 0x0000000000000000 0x0000000000000031 |    <-- prev_size  / size
| 0x000055555555b260 0x000055555555b010 |    <-- Fw pointer / Bw pointer (key)
| 0x0000000000000000 0x0000000000000000 |
-----------------------------------------
```
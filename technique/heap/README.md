# [Technique] Heap exploitation

If you're not familiar with heap exploitation and all types of chunks, read this blog for a better approach: https://guyinatuxedo.github.io/25-heap/index.html

This post is just about all small stuffs and things I want to note. For a full technique, please refer this page: https://github.com/shellphish/how2heap

---

Table of content:
- Tcache

## Tcache

***Double free***
- For libc <= 2.28
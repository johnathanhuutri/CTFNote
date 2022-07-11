# vsCTF 2022 - ForNBack

File [fornback_docker.zip](fornback_docker.zip) is docker & solve script & source code.

File [fornback.zip](fornback.zip) will be published to player.

### Difficulty: Easy - Medium

### Solution

This challenge is created to check your knowledge about heap consolidation so that would not too hard.

Again, libc 2.32 has safe-linking in tcache so source can be found [here](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L339).

Solution can be divided into 3 stage:

- Stage 1: Fake consolidation to leak heap

We want to leak data so we need the pointer to be remain after free. Hence, we need a fake heap consolidation and we will have **Use After Free** bug to leak heap address.

- Stage 2: Heap consolidation to leak libc

This is where the real heap consolidation occurs. It will free a chunk and consolidate with forward and previous chunk, it will write the address of main arena to chunk too. And with **Use After Free**, we can easily get the libc base.

- Stage 3: Get shell

Just a simple case to get shell: Overwrite `__free_hook` with system and freeing a chunk with string `/bin/sh` will get us a shell.
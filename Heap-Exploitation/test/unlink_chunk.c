static void unlink_chunk(mstate av, mchunkptr p) {
    if (chunksize(p) != prev_size(next_chunk(p)))
        malloc_printerr("corrupted size vs. prev_size");

    mchunkptr fd = p -> fd;
    mchunkptr bk = p -> bk;

    if (__builtin_expect(fd -> bk != p || bk -> fd != p, 0))
        malloc_printerr("corrupted double-linked list");

    fd -> bk = bk;
    bk -> fd = fd;
    if (!in_smallbin_range(chunksize_nomask(p)) && p -> fd_nextsize != NULL) {
        if (p -> fd_nextsize -> bk_nextsize != p ||
            p -> bk_nextsize -> fd_nextsize != p)
            malloc_printerr("corrupted double-linked list (not small)");

        if (fd -> fd_nextsize == NULL) {
            if (p -> fd_nextsize == p)
                fd -> fd_nextsize = fd -> bk_nextsize = fd;
            else {
                fd -> fd_nextsize = p -> fd_nextsize;
                fd -> bk_nextsize = p -> bk_nextsize;
                p -> fd_nextsize -> bk_nextsize = fd;
                p -> bk_nextsize -> fd_nextsize = fd;
            }
        } else {
            p -> fd_nextsize -> bk_nextsize = p -> bk_nextsize;
            p -> bk_nextsize -> fd_nextsize = p -> fd_nextsize;
        }
    }
}
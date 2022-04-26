#!/usr/bin/env python3

from pwn import *
import subprocess

# p = process(['./guessMe'])
p = connect('45.77.39.59',10004)
# context.log_level = 'debug'

# Get random number
proc = subprocess.Popen(['./get_rand'],stdout=subprocess.PIPE)
line = proc.stdout.readline()
guess = int(str(line)[2:-3], 16) % 0x539

p.sendline('{}'.format(guess).encode())
print(p.recv())

p.interactive()
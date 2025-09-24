def filter_shellcode(opcodes):
	parity = -1
	for op in opcodes:
		if op > 0x7f:
			return False
		if parity==-1:
			p = bin(op).count("1") & 1
		elif p==(bin(op).count("1") & 1):
			return False
		p = bin(op).count("1") & 1
		# print(op, p)
	return True
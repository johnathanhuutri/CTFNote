def filter_shellcode(opcodes):
	parity = -1
	for op in opcodes:
		if op > 0x7f:
			return False
		if parity==-1:
			parity = bin(op).count("1") & 1
		elif parity!=(bin(op).count("1") & 1):
			return False
		parity = (parity + 1) % 2
	return True
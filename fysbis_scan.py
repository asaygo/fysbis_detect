#! python
import struct
import os
import binascii
import string
import sys

elfMagic = "7F454C46"
MIN_SIG_LEN = 4

def check_elf():
	print ("File: " + str(sys.argv[1]))
	with open(str(sys.argv[1]), "rb") as f:
		#read magic value
		buf = f.read(MIN_SIG_LEN)
		fileOffset = 0
		while buf:
			magic = binascii.hexlify(buf)
			magic = magic.upper()
			print ("magic = " + str(magic))
			pos = string.find(magic, elfMagic);
			if (pos == 0):
				return 1
			else:
				return 0

###MAIN###
isElf = check_elf()
if isElf == 1:
	print ("ELF file")
else:
	print ("Not an ELF file")

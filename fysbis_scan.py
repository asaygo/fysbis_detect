#! python
import struct
import os
import binascii
import string
import sys

MAX_FILE_SIZE = 200000
MIN_FILE_SIZE = 100000

elfMagic = "7F454C46"
flag_elf = 0
flag_64bit = 0
flag_32bit = 0
fsize = 0
buf = None
entry_point = 0
program_header_offset = 0
section_header_offset = 0

def check_size():
	global MIN_FILE_SIZE
	global MAX_FILE_SIZE
	
	fsize = os.path.getsize(sys.argv[1])
	if fsize < MIN_FILE_SIZE or fsize > MAX_FILE_SIZE:
		return 0
	return fsize

def check_elf():
	global buf
	global fsize
	global elfMagic
	global flag_64bit
	global flag_32bit
	global entry_point
	
	print ("File: " + str(sys.argv[1]))

	with open(str(sys.argv[1]), "rb") as f:
		#read header
		buf = f.read(fsize)
		if buf:
			#parse the ELF structure, more details here: http://wiki.osdev.org/ELF
			aux = buf[:4]
			hexval = binascii.hexlify(aux).upper()
			pos = string.find(hexval, elfMagic);
			if (pos == 0):
				flag_elf = 1
			else:
				flag_elf = 0
			
			#check if 32 or 64bit
			aux = buf[4:5]
			hexval = binascii.hexlify(aux).upper()
			print ("bits = " + str(hexval))
			if (hexval == "02"):
				flag_64bit = 1
			if (hexval == "01"):
				flag_32bit = 1
			
			endian = binascii.hexlify(buf[5:6]).upper()			
			if (flag_64bit == 1):
				if endian == "01":
					#get entrypoint
					aux = buf[24:32]
					val = struct.unpack('Q', aux);
					entry_point = hex(val[0])
					#print ("entrypoint = " + str(entry_point))
					
				else:
					aux = buf[24:28]
					val = struct.unpack('Q', aux);
					entry_point = hex(val[0])					
			
		return flag_elf

###MAIN###
fsize = check_size()
if (fsize == 0):
	print ("Incorrect file size")
	sys.exit(0)

isElf = check_elf()
if (isElf == 1):
	print ("ELF file")
else:
	print ("Not an ELF file")

if (flag_64bit == 1):
	print ("64bit file")

print ("EP = " + str(entry_point))
#start search from EP onwards

sys.exit(0)

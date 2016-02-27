#! python
import struct
import os
import binascii
import string
import sys

MAX_FILE_SIZE = 200000
MIN_FILE_SIZE = 100000
HEADER_SIZE	  = 64
F_CLEAN		  = 0
F_INFECTED	  = 1

SIGNATURE = [
				"73797374656d63746c2064697361626c65",	#systemctl disable
				"2f6c69622f6376612d73737973"			#/lib/cva-ssys
			]

elfMagic = "7F454C46"

flag_elf = 0
flag_64bit = 0
flag_32bit = 0
fsize = 0
buf = None
entry_point = 0
program_header_offset = 0
section_header_offset = 0
header_size = 0

def check_size():
	global MIN_FILE_SIZE
	global MAX_FILE_SIZE
	
	fsize = os.path.getsize(sys.argv[1])
	if fsize < MIN_FILE_SIZE or fsize > MAX_FILE_SIZE:
		return 0
	return fsize

def scan_file():
	global buf
	global fsize
	global elfMagic
	global flag_64bit
	global flag_32bit
	global entry_point
	global program_header_offset
	global section_header_offset
	global header_size
	flag_infected = 0
	pheader_entry_sz	= 0
	pheader_entry_no	= 0
	sheader_entry_sz	= 0
	sheader_entry_no	= 0
	shstrtab_index		= 0


	print ("File: " + str(sys.argv[1]))

	with open(str(sys.argv[1]), "rb") as f:
		#read header
		buf = f.read(fsize)
		if buf:
			#parse the ELF structure, more details here: http://wiki.osdev.org/ELF
			aux = buf[:4]
			hexval = binascii.hexlify(aux).upper()
			pos = string.find(hexval, elfMagic)
			if (pos == 0):
				flag_elf = 1
			else:
				flag_elf = 0
			
			#check if 32 or 64bit
			aux = buf[4:5]
			hexval = binascii.hexlify(aux).upper()
			if (hexval == "02"):
				flag_64bit = 1
			if (hexval == "01"):
				flag_32bit = 1
			
			endian = binascii.hexlify(buf[5:6]).upper()			
			if (flag_64bit == 1):
				if endian == "01":

					aux = buf[24:32]
					val = struct.unpack('Q', aux);
					entry_point = hex(val[0])
										
					aux = buf[32:40]
					val = struct.unpack('Q', aux);
					program_header_offset = hex(val[0])
					
					aux = buf[40:48]
					val = struct.unpack('Q', aux);
					section_header_offset = hex(val[0])
					
					aux = buf[52:54]
					val = struct.unpack('H', aux);
					header_size = hex(val[0])
					
					aux = buf[54:56]
					val = struct.unpack('H', aux);
					pheader_entry_sz = val[0]
					
					aux = buf[56:58]
					val = struct.unpack('H', aux);
					pheader_entry_no = val[0]
					
					aux = buf[58:60]
					val = struct.unpack('H', aux);
					sheader_entry_sz = hex(val[0])

					aux = buf[60:62]
					val = struct.unpack('H', aux);
					sheader_entry_no = hex(val[0])

					aux = buf[62:64]
					val = struct.unpack('H', aux);
					shstrtab_index = hex(val[0])

				else:
					aux = buf[24:28]
					val = struct.unpack('Q', aux);
					entry_point = hex(val[0])					
			
			
			max_load_addr = 0
			max_file_offset = 0
			start_offset = 64
			load_addr = 0
			for i in range(0,int(pheader_entry_no)):						
				aux = buf[i*pheader_entry_sz+start_offset+8:i*pheader_entry_sz+start_offset+16]
				val = struct.unpack('Q', aux);
				file_offset = val[0]
						
				aux = buf[i*pheader_entry_sz+start_offset+16:i*pheader_entry_sz+start_offset+24]
				val = struct.unpack('Q', aux);
				load_addr = val[0]
						
				if load_addr < entry_point and load_addr > max_load_addr:
					max_load_addr = load_addr
					max_file_offset = file_offset
					
			if max_load_addr > 0 and max_file_offset > 0:
				print ("Section load addr: " + str(max_load_addr))
				print ("Section file offset: " + str(max_file_offset))
			else:
				return F_CLEAN	
			
			#if (flag_64bit == 1):
			#	print ("64bit file")
			
			if max_file_offset < fsize:
				f.seek(max_file_offset)
				
				strbuf = binascii.hexlify(buf)
				for index in range(len(SIGNATURE)):
					pos = strbuf.find(SIGNATURE[index], max_file_offset)
					#print "Malware identified at offset: " + str(pos)
					if ( pos > 0):
						return F_INFECTED
				
		return F_CLEAN

###MAIN###
fsize = check_size()
if (fsize == 0):
	print ("Incorrect file size")
	sys.exit(0)

isInf = scan_file()
if (isInf == 1):
	print ("[+] Malware detected")
else:
	print ("[-] No malware detected")

#start search from EP onwards

sys.exit(0)

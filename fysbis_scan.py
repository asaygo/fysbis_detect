#! python
#####################################
#	Copyright LF-2095				#
#	Developed for Linux Forensics	#
#	course on pentesteracademy.com	#
#####################################

import struct
import os
import binascii
import string
import sys

MAX_FILE_SIZE = 200000
MIN_FILE_SIZE = 100000
F_CLEAN		  = 0
F_INFECTED	  = 1

SIGNATURE = [
				"73797374656d63746c2064697361626c65",						#systemctl disable
				"2f6c69622f6376612d73737973",								#/lib/cva-ssys
				"746172676574",												#target
				"636f6e6669672f6175746f7374617274",							#config/autostart
				"726d202d6620",												#rm -f 
				"57524954452046494c45204953204e4f542053554343455353"		#WRITE FILE IS NOT SUCCESS
			]

#to increase the heuristic, reduce the SENSITIVITY
SENSITIVITY	  = len(SIGNATURE)

elfMagic = "7F454C46"
fsize = 0
filename = ""
buf = None

def check_size():
	global MIN_FILE_SIZE
	global MAX_FILE_SIZE
	global filename
	global fsize
	
	try:
		fsize = os.path.getsize(filename)
		if fsize < MIN_FILE_SIZE or fsize > MAX_FILE_SIZE:
			return 0
	except:
		print sys.exc_info()[1]
	
	return fsize

def scan_file():
	global elfMagic
	global fsize	
	global filename
	entry_point 			= 0
	program_header_offset 	= 0
	section_header_offset 	= 0
	header_size 			= 0
	flag_infected 			= 0
	flag_elf 				= 0
	flag_64bit 				= 0
	flag_32bit 				= 0
	pheader_entry_sz		= 0
	pheader_entry_no		= 0
	sheader_entry_sz		= 0
	sheader_entry_no		= 0
	shstrtab_index			= 0

	print ("File: " + str(filename))
	try:
		with open(str(filename), "rb") as f:
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
					if endian == "01":
						aux = buf[24:28]
						val = struct.unpack('L', aux);
						entry_point = hex(val[0])
											
						aux = buf[28:32]
						val = struct.unpack('L', aux);
						program_header_offset = hex(val[0])
						
						aux = buf[32:36]
						val = struct.unpack('L', aux);
						section_header_offset = hex(val[0])
						
						aux = buf[40:42]
						val = struct.unpack('H', aux);
						header_size = hex(val[0])
						
						aux = buf[42:44]
						val = struct.unpack('H', aux);
						pheader_entry_sz = val[0]
						
						aux = buf[44:46]
						val = struct.unpack('H', aux);
						pheader_entry_no = val[0]
						
						aux = buf[46:48]
						val = struct.unpack('H', aux);
						sheader_entry_sz = hex(val[0])
	
						aux = buf[48:50]
						val = struct.unpack('H', aux);
						sheader_entry_no = hex(val[0])
	
						aux = buf[50:52]
						val = struct.unpack('H', aux);
						shstrtab_index = hex(val[0])
							
				max_load_addr = 0
				max_file_offset = 0
				start_offset = 64
				load_addr = 0
				for i in range(0,int(pheader_entry_no)):
					if (flag_64bit == 1):
						aux = buf[i*pheader_entry_sz+start_offset+8:i*pheader_entry_sz+start_offset+16]
						val = struct.unpack('Q', aux);
						file_offset = val[0]
							
						aux = buf[i*pheader_entry_sz+start_offset+16:i*pheader_entry_sz+start_offset+24]
						val = struct.unpack('Q', aux);
						load_addr = val[0]
	
					else:
						aux = buf[i*pheader_entry_sz+start_offset+8:i*pheader_entry_sz+start_offset+12]
						val = struct.unpack('L', aux);
						file_offset = val[0]
							
						aux = buf[i*pheader_entry_sz+start_offset+12:i*pheader_entry_sz+start_offset+16]
						val = struct.unpack('L', aux);
						load_addr = val[0]
							
					if load_addr < entry_point and load_addr > max_load_addr:
						max_load_addr = load_addr
						max_file_offset = file_offset
						
				if max_load_addr < 0 or max_file_offset < 0:
					return F_CLEAN	
							
				if max_file_offset < fsize:
					f.seek(max_file_offset)
					
					strbuf = binascii.hexlify(buf).upper()
					count = 0
					for index in range(len(SIGNATURE)):
						pos = strbuf.find(SIGNATURE[index].upper(), max_file_offset)
						#print "Malware identified at offset: " + str(pos)
						if ( pos > 0):
							count = count +1
					
					if (count >= SENSITIVITY):
						return F_INFECTED
		
	except:
		print sys.exc_info()[1]
					
		return F_CLEAN

#more details about the IOCs
#http://malwrforensics.com/fysbis.html
def examine_filesystem():
	trace = 0
	if os.path.exists("/bin/rsyncd"):
		print("\t/bin/rsyncd found")
		trace = 1
	
	if os.path.exists("~/.config/autostart/dbus-inotifier"):
		print("\t~/.config/autostart/dbus-inotifier found")
		trace = 1
	
	if os.path.exists("~/.config/autostart/dbus-inotifier.desktop"):
		print("\t~/.config/autostart/dbus-inotifier.desktop found")
		trace = 1

	if os.path.exists("~/.config/dbus-notifier/dbus-inotifier"):
		print("\t~/.config/dbus-notifier/dbus-inotifier found")
		trace = 1

	if os.path.exists("~/.config/dbus-notifier/dbus-inotifier.desktop"):
		print("\t~/.config/dbus-notifier/dbus-inotifier.desktop found")
		trace = 1
 	
	if os.path.exists("/usr/lib/cva-ssys"):
		print("\t/usr/lib/cva-ssys found")
		trace = 1
	
	if os.path.exists("/lib/systemd/system/rsyncd.service"):
		print("\t/lib/systemd/system/rsyncd.service found")
		trace = 1
	
	if os.path.exists("/etc/systemd/system/multi-user.target.wants/rsyncd.service"):
		print("\t/etc/systemd/system/multi-user.target.wants/rsyncd.service found")
		trace = 1
	
	return trace

def examine_processes():
	pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
	trace = 0
	for pid in pids:
		try:
			proc_data = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read()
			pos = proc_data.find(' ')
			if pos > 0:
				pname = proc_data[0:pos]
				
				if pname.find("/bin/rsyncd") >= 0:
					trace = 1
					print "\t/bin/rsyncd found"

				if pname.find("dbus-inotifier") >= 0:
					trace = 1
					print "\tdbus-inotifier found"
					
		except IOError:
			continue

	return trace

def examine_system():
	if examine_processes() == 1:
		return 1
	if examine_filesystem() == 1:
		return 1 

	return 0

def show_help():
	print ("Program [option] <file name>")
	print ("\nOptions:")
	print ("-f filename\t\tscan a file to see if it's malicious")
	print ("-s\t\t\tscan a system for forensic traces (checks the list of running processes and files)")
	

###MAIN###
if len(sys.argv) < 2 or len(sys.argv) > 3:
	show_help()
	sys.exit(0)

if sys.argv[1] == '-f':
	if len(sys.argv) == 3:
		filename = sys.argv[2] 
	else:
		show_help()
		sys.exit(0)

	fsize = check_size()
	if (fsize == 0):
		print ("Incorrect file size")
		sys.exit(0)

	isInf = scan_file()
	if (isInf == 1):
		print ("[+] Malware detected")
	else:
		print ("[-] No malware detected")

if sys.argv[1] == '-s':
	if examine_system() == 1:
		print ("[+] Forensic traces detected")
	else:
		print ("[-] No infection found")

sys.exit(0)

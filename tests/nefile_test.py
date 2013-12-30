#!/usr/bin/env python2

import sys

sys.path.append(r'..')
sys.path.append(r'../lib')

import nefile
import pydasm

ne = nefile.NE(sys.argv[1])
print len(ne.segmentTable), "Start %4X:%4X" % (ne.NE_HEADER.InitialCS, ne.NE_HEADER.InitialIP)
code = ne.get_segment_data(ne.NE_HEADER.InitialCS - 1 )

startIP = ne.NE_HEADER.InitialIP
instr = pydasm.get_instruction(code[startIP:startIP+13], pydasm.MODE_16)
print pydasm.get_instruction_string(instr, pydasm.FORMAT_INTEL, 0)

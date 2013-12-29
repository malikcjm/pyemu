#!/usr/bin/env python2

import sys

sys.path.append(r'..')
sys.path.append(r'../lib')

import nefile

ne = nefile.NE(sys.argv[1])
print ne

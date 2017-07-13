#!/usr/bin/env python

import sys, random, os, tempfile
sys.path.append('/home/jake/templite')
from templite import Templite

template = open('14_angr_execute_stack.c.templite', 'r').read()
c_code = Templite(template).render()
with tempfile.NamedTemporaryFile(delete=False, suffix='.c') as temp:
  temp.write(c_code)
  temp.seek(0)
  os.system('gcc -fno-stack-protector -Wl,--section-start=.text=0x34343434 -m32 -o 14_angr_execute_stack ' + temp.name)
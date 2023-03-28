#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef0 = ''.join(random.choice(userdef_charset) for _ in range(8))
  userdef1 = ''.join(random.choice(userdef_charset) for _ in range(8))

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '07_angr_symbolic_file.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', userdef0=userdef0, userdef1=userdef1)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    print(repr(temp.name))
    os.system('gcc -fno-pie -no-pie -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)

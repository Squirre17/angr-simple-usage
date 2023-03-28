# Essentially, the program does the following:
#
# scanf("%d %20s", &key, user_input);
# ...
#   // if certain unknown conditions are true...
#   strncpy(random_buffer, user_input);
# ...
# if (strncmp(secure_buffer, reference_string)) {
#   // The secure_buffer does not equal the reference string.
#   puts("Try again.");
# } else {
#   // The two are equal.
#   puts("Good Job.");
# }
#
# If this program has no bugs in it, it would _always_ print "Try again." since
# user_input copies into random_buffer, not secure_buffer.
#
# The question is: can we find a buffer overflow that will allow us to overwrite
# the random_buffer pointer to point to secure_buffer? (Spoiler: we can, but we
# will need to use Angr.)
#
# We want to identify a place in the binary, when strncpy is called, when we can:
#  1) Control the source contents (not the source pointer!)
#     * This will allow us to write arbitrary data to the destination.
#  2) Control the destination pointer
#     * This will allow us to write to an arbitrary location.
# If we can meet both of those requirements, we can write arbitrary data to an
# arbitrary location. Finally, we need to contrain the source contents to be
# equal to the reference_string and the destination pointer to be equal to the
# secure_buffer.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # You can either use a blank state or an entry state; just make sure to start
  # at the beginning of the program.
  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):
    # Hint: scanf("%u %20s")
    def run(self, format_string, key_addr, buf_addr):
      # %u
      scanf0 = claripy.BVS('scanf0', 4 * 8)
      
      # %24s
      scanf1 = claripy.BVS('scanf1', 24 * 8)

      for char in scanf1.chop(bits=8):
        # self.state.add_constraints(char >= ???, char <= ???)
        ...

      scanf0_address = key_addr
      scanf1_address = buf_addr
      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)
      ...

      self.state.globals['solutions0'] = scanf0
      self.state.globals['solutions1'] = scanf1

  scanf_symbol = "__isoc99_scanf"  # :string
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  # In this challenge, we want to check strncpy to determine if we can control
  # both the source and the destination. It is common that we will be able to
  # control at least one of the parameters, (such as when the program copies a
  # string that it received via stdin).
  def check_strncpy(state):
    '''
     4012a3:       eb 32                   jmp    4012d7 <main+0xde>
 
BB-> 4012a5:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
     4012a9:       48 8d 4d e0             lea    rcx,[rbp-0x20]
     4012ad:       ba 10 00 00 00          mov    edx,0x10
     4012b2:       48 89 ce                mov    rsi,rcx
     4012b5:       48 89 c7                mov    rdi,rax
     4012b8:       e8 d3 fd ff ff          call   401090 <strncpy@plt>
    '''
    strncpy_dest = state.memory.load(state.regs.rbp - 0x10, 8, endness = project.arch.memory_endness)
    strncpy_src  = state.regs.rbp - 0x20
    strncpy_len  = 0x10

    # We need to find out if src is symbolic, however, we care about the
    # contents, rather than the pointer itself. Therefore, we have to load the
    # the contents of src to determine if they are symbolic.
    # Hint: How many bytes is strncpy copying?
    # (!)
    src_contents = state.memory.load(strncpy_src, strncpy_len)

    # Our goal is to determine if we can write arbitrary data to an arbitrary
    # location. This means determining if the source contents are symbolic
    # (arbitrary data) and the destination pointer is symbolic (arbitrary
    # destination).
    # (!)
    if state.solver.symbolic(src_contents) and state.solver.symbolic(strncpy_dest):
      # Use ltrace to determine the password. Decompile the binary to determine
      # the address of the buffer it checks the password against. Our goal is to
      # overwrite that buffer to store the password.
      # (!)
      password_string = "GCDAHMGI" # :string
      buffer_address = claripy.BVV(0x404080, 8 * 8) # :integer, probably in hexadecimal

      # Create an expression that tests if the first n bytes is length. Warning:
      # while typical Python slices (array[start:end]) will work with bitvectors,
      # they are indexed in an odd way. The ranges must start with a high value
      # and end with a low value. Additionally, the bits are indexed from right
      # to left. For example, let a bitvector, b, equal 'ABCDEFGH', (64 bits).
      # The following will read bit 0-7 (total of 1 byte) from the right-most
      # bit (the end of the string).
      #  b[7:0] == 'H'
      # To access the beginning of the string, we need to access the last 16
      # bits, or bits 48-63:
      #  b[63:48] == 'AB'
      # In this specific case, since we don't necessarily know the length of the
      # contents (unless you look at the binary), we can use the following:
      #  b[-1:-16] == 'AB', since, in Python, -1 is the end of the list, and -16
      # is the 16th element from the end of the list. The actual numbers should
      # correspond with the length of password_string.
      # (!)
      # IMPORTANT: 
      does_src_hold_password = src_contents[-1:len(password_string)*8] == password_string

      # Create an expression to check if the dest parameter can be set to
      # buffer_address. If this is true, then we have found our exploit!
      # (!)
      does_dest_equal_buffer_address = strncpy_dest == buffer_address

      # In the previous challenge, we copied the state, added constraints to the
      # copied state, and then determined if the constraints of the new state
      # were satisfiable. Since that pattern is so common, Angr implemented a
      # parameter 'extra_constraints' for the satisfiable function that does the
      # exact same thing.  Note that we can pass multiple expressions to
      # extra_constraints.
      if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
        state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
        return True
      else:
        return False
    else: # not state.solver.symbolic(???)
      return False

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    # print(hex(state.addr))
    '''
     4012a3:       eb 32                   jmp    4012d7 <main+0xde>
 
BB-> 4012a5:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
     4012a9:       48 8d 4d e0             lea    rcx,[rbp-0x20]
     4012ad:       ba 10 00 00 00          mov    edx,0x10
     4012b2:       48 89 ce                mov    rsi,rcx
     4012b5:       48 89 c7                mov    rdi,rax
     4012b8:       e8 d3 fd ff ff          call   401090 <strncpy@plt>
    '''
    strncpy_address = 0x4012a5 # TODO:
    if state.addr == strncpy_address:
      return check_strncpy(state)
    else:
      return False

  simulation.explore(find=is_successful)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(solution_state.globals["solutions0"])
    solution1 = solution_state.solver.eval(solution_state.globals["solutions1"], cast_to=bytes)

    print(solution0)
    print(solution1[::-1])
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)

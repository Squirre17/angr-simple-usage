# This binary takes both an integer and a string as a parameter. A certain
# integer input causes the program to reach a buffer overflow with which we can
# read a string from an arbitrary memory location. Our goal is to use Angr to
# search the program for this buffer overflow and then automatically generate
# an exploit to read the string "Good Job."
#
# What is the point of reading the string "Good Job."?
# This CTF attempts to replicate a simplified version of a possible vulnerability
# where a user can exploit the program to print a secret, such as a password or
# a private key. In order to keep consistency with the other challenges and to
# simplify the challenge, the goal of this program will be to print "Good Job."
# instead.
#
# The general strategy for crafting this script will be to:
# 1) Search for calls of the 'puts' function, which will eventually be exploited
#    to print out "Good Job."
# 2) Determine if the first parameter of 'puts', a pointer to the string to be
#    printed, can be controlled by the user to be set to the location of the
#    "Good Job." string.
# 3) Solve for the input that prints "Good Job."
#
# Note: The script is structured to implement step #2 before #1.

# Some of the source code for this challenge:
#
# #include <stdio.h>
# #include <stdlib.h>
# #include <string.h>
# #include <stdint.h>
# 
# // This will all be in .rodata
# char msg[] = "${ description }$";
# char* try_again = "Try again.";
# char* good_job = "Good Job.";
# uint32_t key;
# 
# void print_msg() {
#   printf("%s", msg);
# }
#
# uint32_t complex_function(uint32_t input) {
#   ...
# }
# 
# struct overflow_me {
#   char buffer[16];
#   char* to_print;
# }; 
# 
# int main(int argc, char* argv[]) {
#   struct overflow_me locals;
#   locals.to_print = try_again;
# 
#   print_msg();
# 
#   printf("Enter the password: ");
#   scanf("%u %20s", &key, locals.buffer);
#
#   key = complex_function(key);
# 
#   switch (key) {
#     case ?:
#       puts(try_again);
#       break;
#
#     ...
#
#     case ?:
#       // Our goal is to trick this call to puts to print the "secret
#       // password" (which happens, in our case, to be the string
#       // "Good Job.")
#       puts(locals.to_print);
#       break;
#     
#     ...
#   }
# 
#   return 0;
# }

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # You can either use a blank state or an entry state; just make sure to start
  # at the beginning of the program.
  # (!)
  initial_state = project.factory.entry_state()

  # Again, scanf needs to be replaced.
  class ReplacementScanf(angr.SimProcedure):
    # Hint: scanf("%u %20s")
    def run(self, format_string, key_addr, overflow_addr):
      # %u
      scanf0 = claripy.BVS('scanf0', 4 * 8)
      
      # %20s
      scanf1 = claripy.BVS('scanf1', 24 * 8)

      # The bitvector.chop(bits=n) function splits the bitvector into a Python
      # list containing the bitvector in segments of n bits each. In this case,
      # we are splitting them into segments of 8 bits (one byte.)
      for char in scanf1.chop(bits=8):
        # Ensure that each character in the string is printable. An interesting
        # experiment, once you have a working solution, would be to run the code
        # without constraining the characters to the printable range of ASCII.
        # Even though the solution will technically work without this, it's more
        # difficult to enter in a solution that contains character you can't
        # copy, paste, or type into your terminal or the web form that checks 
        # your solution.
        # (!)
        # password is assumed as printable
        # self.state.add_constraints(char >='\x30' , char <= '\x7e')
        ...

      # Warning: Endianness only applies to integers. If you store a string in
      # memory and treat it as a little-endian integer, it will be backwards.
      scanf0_address = key_addr
      scanf1_address = overflow_addr
      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)
      ...

      self.state.globals['solution0'] = scanf0
      self.state.globals['solution1'] = scanf1
      ...

  scanf_symbol = "__isoc99_scanf"  # :string
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  # We will call this whenever puts is called. The goal of this function is to
  # determine if the pointer passed to puts is controllable by the user, such
  # that we can rewrite it to point to the string "Good Job."
  def check_puts(state):
    # Recall that puts takes one parameter, a pointer to the string it will
    # print. If we load that pointer from memory, we can analyse it to determine
    # if it can be controlled by the user input in order to point it to the
    # location of the "Good Job." string.
    #
    # Treat the implementation of this function as if puts was just called.
    # The stack, registers, memory, etc should be set up as if the x86 call
    # instruction was just invoked (but, of course, the function hasn't copied
    # the buffers yet.)
    # The stack will look as follows:
    # ...
    # esp + 7 -> /----------------\
    # esp + 6 -> |      puts      |
    # esp + 5 -> |    parameter   |
    # esp + 4 -> \----------------/
    # esp + 3 -> /----------------\
    # esp + 2 -> |     return     |
    # esp + 1 -> |     address    |
    #     esp -> \----------------/
    #
    # Hint: Look at level 08, 09, or 10 to review how to load a value from a
    # memory address. Remember to use the correct endianness in the future when
    # loading integers; it has been included for you here.
    # (!)
    # puts_parameter = state.memory.load(???, ???, endness=project.arch.memory_endness)
    '''
    4011fd:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
    401201:       48 89 c7                mov    rdi,rax
    401204:       e8 57 fe ff ff          call   401060 <puts@plt>
    '''
    print("[D] HIT check_puts")
    puts_parameter = state.memory.load(state.regs.rbp - 0x10, 8, endness=project.arch.memory_endness)
    print("[D] puts para" + repr(puts_parameter))

    # The following function takes a bitvector as a parameter and checks if it
    # can take on more than one value. While this does not necessary tell us we
    # have found an exploitable state, it is a strong indication that the 
    # bitvector we checked may be controllable by the user.
    # Use it to determine if the pointer passed to puts is symbolic.
    # (!)
    if state.solver.symbolic(puts_parameter):
      # Determine the location of the "Good Job." string. We want to print it
      # out, and we will do so by attempting to constrain the puts parameter to
      # equal it. Hint: use 'objdump -s <binary>' to look for the string's
      # address in .rodata.
      # (!)
      good_job_string_address = claripy.BVV(0x40200f, 8 * 8)# :integer, probably hexadecimal

      # Create an expression that will test if puts_parameter equals
      # good_job_string_address. If we add this as a constraint to our solver,
      # it will try and find an input to make this expression true. Take a look
      # at level 08 to remind yourself of the syntax of this.
      # (!)
      is_vulnerable_expression = puts_parameter == good_job_string_address # :boolean bitvector expression
      print(is_vulnerable_expression)

      # Finally, we test if we can satisfy the constraints of the state.
      if state.satisfiable(extra_constraints=(is_vulnerable_expression,)):
        # Before we return, let's add the constraint to the solver for real,
        # instead of just querying whether the constraint _could_ be added.
        state.add_constraints(is_vulnerable_expression)
        return True
      else:
        return False
    else: # not state.solver.symbolic(???)
      return False

  simulation = project.factory.simgr(initial_state)

  # In order to determine if we have found a vulnerable call to 'puts',  we need
  # to run the function check_puts (defined above) whenever we reach a 'puts'
  # call. To do this, we will look for the place where the instruction pointer,
  # state.addr, is equal to the beginning of the puts function.
  def is_successful(state):
    # We are looking for puts. Check that the address is at the (very) beginning
    # of the puts function. Warning: while, in theory, you could look for
    # any address in puts, if you execute any instruction that adjusts the stack
    # pointer, the stack diagram above will be incorrect. Therefore, it is
    # recommended that you check for the very beginning of puts.
    # (!)
    '''
    .text:00000000004011FD loc_4011FD:                             ; CODE XREF: main+59↑j
    .text:00000000004011FD                 mov     rax, [rbp+locals.to_print]
    .text:0000000000401201                 mov     rdi, rax        ; s
    .text:0000000000401204                 call    _puts
    .text:0000000000401209                 jmp     short loc_40122B
    '''
    puts_address = 0x4011FD
    # print(hex(state.addr))
    if state.addr == puts_address:
      # Return True if we determine this call to puts is exploitable.
      return check_puts(state)
    else:
      # We have not yet found a call to puts; we should continue!
      return False

  simulation.explore(find=is_successful)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(solution_state.globals["solution0"])
    solution1 = solution_state.solver.eval(solution_state.globals["solution1"], cast_to=bytes)
    print(solution0)

    import binascii
    byte_sequence = solution1
    hex_string = binascii.hexlify(byte_sequence).decode('utf-8')
    escaped_string = ''.join('\\x{}'.format(hex_string[i:i+2]) for i in range(0, len(hex_string), 2))
    print(escaped_string)

  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)

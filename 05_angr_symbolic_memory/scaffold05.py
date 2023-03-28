import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x4012bc
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  pswds = []
  [pswds.append(claripy.BVS('password%d' % i, 64)) for i in range(4)]

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0x1877e20
  for i, pswd in enumerate(pswds):
    initial_state.memory.store(password0_address + i * 8, pswds[i])

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Good Job." in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"Try again." in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=bytes
    # which returns bytes that can be decoded to a string instead of an integer.
    # (!)
    solutions = []
    for i in range(4):
        solutions.append(solution_state.solver.eval(pswds[i],cast_to=bytes).decode())

    [print(solutions[i]) for i in range(4)]
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x40133C
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # The binary is calling scanf("%8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)

  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  useless_addr = 0x4040A0 

  fake_heap_address0 = useless_addr
  pointer_to_malloc_memory_address0 = 0x22F4370

  initial_state.memory.store(
    pointer_to_malloc_memory_address0, 
    fake_heap_address0, 
    endness=project.arch.memory_endness,
    
  )
 
  fake_heap_address1 = useless_addr + 0x10
  pointer_to_malloc_memory_address1 = 0x22F4380

  initial_state.memory.store(
    pointer_to_malloc_memory_address1, 
    fake_heap_address1, 
    endness=project.arch.memory_endness
  )

  # Store our symbolic values at our fake_heap_address. Look at the binary to
  # determine the offsets from the fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)

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

    solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()

    print(solution0, end = " ")
    print(solution1)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)

import angr
import claripy
import sys

def main(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Start at the beginning of handle_user()
    start_address = 0x40139B
    initial_state = project.factory.blank_state(
        addr=start_address,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # Initialize the stack as symbolic variables
    pswd = claripy.BVS('password', 64)
    password0 = pswd[63:32]
    password1 = pswd[31:0]
    initial_state.regs.rbp = initial_state.regs.rsp
    initial_state.stack_push(pswd)

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
        print(solution_state.posix.dumps(1))

        solution0 = solution_state.solver.eval(password0)
        solution1 = solution_state.solver.eval(password1)

        print("{} {}".format(solution0, solution1))
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)

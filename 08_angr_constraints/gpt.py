import angr
import claripy
import sys

def main(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    start_address = 0x40129f
    initial_state = project.factory.blank_state(
        addr=start_address,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    password = claripy.BVS('password', 16 * 8)

    password_address = 0x404060
    initial_state.memory.store(password_address, password)

    simulation = project.factory.simgr(initial_state)

    address_to_check_constraint = 0x40123d
    simulation.explore(find=address_to_check_constraint)

    if simulation.found:
        solution_state = simulation.found[0]
        constrained_parameter_address = 0x404060
        constrained_parameter_size_bytes = 16
        constrained_parameter_bitvector = solution_state.memory.load(
            constrained_parameter_address,
            constrained_parameter_size_bytes
        )
        constrained_parameter_desired_value = b"LCILGCDAHMGIBNZL"
        solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)
        solution = initial_state.solver.eval(password, cast_to=bytes)
        print(solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)

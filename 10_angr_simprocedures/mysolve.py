
import angr
import claripy
import sys

def main(argv):
    path_to_binary = argv[1]
    p = angr.Project(path_to_binary)

    initial_state = p.factory.entry_state()


    class SimProce(angr.SimProcedure):
        def run(self, user_input_addr, user_input_length):
            print(f"[D] {user_input_addr} {user_input_length}")
            user_input_bvs = self.state.memory.load(
                user_input_addr,
                user_input_length
            )
            # print(f"[D] {user_input_bvs}")

            desired = b"LCILGCDAHMGIBNZL"
            
            return claripy.If(
                user_input_bvs == desired ,
                claripy.BVV(1 ,64), 
                claripy.BVV(0 ,64)
            )

    symbol = "check_equals_LCILGCDAHMGIBNZL" # :string
    p.hook_symbol(symbol, SimProce())

    sm = p.factory.simgr(initial_state)

    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        return b"Good Job." in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        return b"Try again." in stdout_output

    sm.explore(find=is_successful, avoid=should_abort)

    if sm.found:
        solution_state = sm.found[0]

        solution = solution_state.posix.dumps(0)
        print(solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)

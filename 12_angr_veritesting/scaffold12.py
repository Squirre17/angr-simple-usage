# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.
import angr
import claripy
import sys
def main(argv):
    p = angr.Project(argv[1])
    init_state = p.factory.entry_state()
    simu = p.factory.simgr(init_state, veritesting = True)

    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"Good Job." in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"Try again." in stdout_output

    simu.explore(find = is_successful, avoid = should_abort)
    if simu.found:
        solu_state = simu.found[0]
        print(solu_state.posix.dumps(0))


if __name__ == "__main__":
    main(sys.argv)
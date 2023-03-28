# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.
import angr
import sys

printf_addr       = 0x410b10
scanf_addr        = 0x410ca0
puts_addr         = 0x420a30
__libc_start_main = 0x402230
strcmp_addr       = 0x430e60

p = angr.Project(sys.argv[1])
init_state = p.factory.entry_state(
    add_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    },
)
sm = p.factory.simgr(init_state)

p.hook(printf_addr      , angr.SIM_PROCEDURES["libc"]["printf"]())
p.hook(scanf_addr       , angr.SIM_PROCEDURES["libc"]["scanf"]())
# p.hook(puts_addr        , angr.SIM_PROCEDURES["libc"]["puts"]())
p.hook(strcmp_addr      , angr.SIM_PROCEDURES["libc"]["strcmp"]())
p.hook(__libc_start_main, angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]())

def is_successful(state):
    return b"Good Job" in state.posix.dumps(1)

def should_abort(state):
    return b"Try again" in state.posix.dumps(1)


sm.explore(find = 0x401E85)

if sm.found:
    print(sm.found[0].posix.dumps(1))
    print(sm.found[0].posix.dumps(0))
else:
    raise Exception("Not found")
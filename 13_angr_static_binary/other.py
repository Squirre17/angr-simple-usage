import sys

import pwn
import angr


def main():
    path_to_binary = "./angr_static_bin"
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state(
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    project.hook(0x410b10, angr.SIM_PROCEDURES["libc"]["printf"]())
    project.hook(0x410ca0, angr.SIM_PROCEDURES["libc"]["scanf"]())
    project.hook(0x420a30, angr.SIM_PROCEDURES["libc"]["puts"]())
    project.hook(0x402230, angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]())

    simulation = project.factory.simgr(initial_state)
    print_good_address = 0x401E85
    simulation.explore(find=print_good_address)
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
        run_binary(solution, path_to_binary)
    else:
        raise Exception("Could not find the solution")


def run_binary(solution, path_to_binary):
    if type(solution) == str:
        solution = bytes(solution, "utf-8")
    print(f"[+] Solution found: {solution.decode()}")
    print("    [|] Running binary")
    pwn.context.log_level = "error"
    elf = pwn.ELF(path_to_binary, checksec=False)
    pty = pwn.process.PTY
    io = elf.process(stdin=pty, stdout=pty, level="warn")
    io.recvuntil(b":")
    io.sendline(solution)
    output = io.recvline().decode().splitlines()[0].strip()
    print(f"    [+] Output: {output}")


if __name__ == "__main__":
    main()
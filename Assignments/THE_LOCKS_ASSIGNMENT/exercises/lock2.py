from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import sys

ADDRESS = 0x1000000


def read_elf_binary(filepath):
    with open(filepath, "rb") as f:
        return f.read()


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    # read this instruction code from memory
    tmp = uc.mem_read(address, size)
    print("*** PC = %x *** :" % (address), end="")
    for i in tmp:
        print(" %02x" % i, end="")
    print("")


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret


# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    # only handle Linux syscall
    if intno != 0x80:
        print("got interrupt %x ???" % intno)
        uc.emu_stop()
        return

    eax = uc.reg_read(UC_X86_REG_EAX)
    eip = uc.reg_read(UC_X86_REG_EIP)

    if eax == 1:  # sys_exit
        print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" % (eip, intno, eax))
        uc.emu_stop()
    elif eax == 4:  # sys_write
        # ECX = buffer address
        ecx = uc.reg_read(UC_X86_REG_ECX)
        # EDX = buffer size
        edx = uc.reg_read(UC_X86_REG_EDX)
        try:
            buf = uc.mem_read(ecx, edx)
            print(
                ">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = "
                % (eip, intno, ecx, edx),
                end="",
            )
            for i in buf:
                print("%c" % i, end="")
            print("")
        except UcError as e:
            print(
                ">>> 0x%x: interrupt 0x%x, SYS_WRITE. buffer = 0x%x, size = %u, content = <unknown>\n"
                % (eip, intno, ecx, edx)
            )
    elif eax == 11:  # sys_write
        ebx = uc.reg_read(UC_X86_REG_EBX)
        filename = read_string(uc, ebx)
        print(">>> SYS_EXECV filename=%s" % filename)
    else:
        print(">>> 0x%x: interrupt 0x%x, EAX = 0x%x" % (eip, intno, eax))


def hook_syscall64(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    rdi = mu.reg_read(UC_X86_REG_RDI)

    print(">>> got SYSCALL with RAX = %d" % (rax))

    if rax == 59:  # sys_execve
        filename = read_string(mu, rdi)
        print(">>> SYS_EXECV filename=%s" % filename)

    else:
        rip = mu.reg_read(UC_X86_REG_RIP)
        print(">>> Syscall Found at 0x%x: , RAX = 0x%x" % (rip, rax))

    mu.emu_stop()


def main(code):
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(ADDRESS, 40 * 1024 * 1024)
        mu.mem_write(ADDRESS, code)
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

        mu.hook_add(UC_HOOK_BLOCK, hook_block)
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_INSN, hook_syscall64, None, 1, 0, UC_X86_INS_SYSCALL)

        mu.emu_start(ADDRESS, ADDRESS + len(code))

        print(">>> Emulation done")

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == "__main__":
    main(read_elf_binary(sys.argv[1]))

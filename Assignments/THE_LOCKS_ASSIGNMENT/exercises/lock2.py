from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import sys

ADDRESS = 0x1000000
CODE_ADDRESS = 0x2000000


def read_elf_binary(filepath):
    with open(filepath, "rb") as f:
        return f.read()


def read_string(uc, address):
    ret = ""
    c = uc.mem_read(address, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(address + read_bytes, 1)[0]
        read_bytes += 1
    return ret


def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    tmp = uc.mem_read(address, size)
    print("*** PC = %x *** :" % (address), end="")
    for i in tmp:
        print(" %02x" % i, end="")
    print("")


def main(code):
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # setting up the stack
        mu.mem_map(ADDRESS, 4 * 1024 * 1024)

        # placing rsp in the middle of the stack
        reg_rsp = ADDRESS + (4 * 1024 * 1024) // 2
        mu.reg_write(UC_X86_REG_RSP, reg_rsp)

        # map memory for code and write code to mapped memory
        mu.mem_map(CODE_ADDRESS, 1024 * 1024)  # TODO gotta check this memory mapping
        mu.mem_write(CODE_ADDRESS, code)

        # adding hook to capture the password
        mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(code))

        print(">>> Emulation done")

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == "__main__":
    main(read_elf_binary(sys.argv[1]))

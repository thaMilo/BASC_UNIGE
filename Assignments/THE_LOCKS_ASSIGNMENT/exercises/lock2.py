from unicorn import *
from unicorn.x86_const import *
from pwn import *
import struct

BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024 * 1024
skip_list = [0x4006A7]


def hook_code(mu, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

    if address in skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)


if __name__ == "__main__":
    code = b""
    with open("./thaMilo-the_lock-level_2", "rb") as f:
        code = f.read()

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # setting up memory for stack
    mu.mem_map(BASE, 1024 * 1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # setting up memory for code
    mu.mem_write(BASE, code)
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)

    # setting up hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # starting the emulation
    mu.emu_start(0x0000000000401620, 0x0000000000401833)

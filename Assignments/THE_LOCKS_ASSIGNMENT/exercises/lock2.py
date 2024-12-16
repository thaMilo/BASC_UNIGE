from unicorn import *
from unicorn.x86_const import *
from pwn import *

CODE = 0x10000000
CODE_SIZE = 0x30000000
STACK = 0x60000000
STACK_SIZE = 0x10000000

skip_list = []


def hook_code(mu, address, size, user_data):
    print(f"[ INS - 0x{address:x} ] [ SIZE - {size}B ]")

    # rdi = mu.reg_read(UC_X86_REG_RDI)
    # print(hex(rdi))

    if address == 0x100010CF:
        mu.reg_write(UC_X86_REG_RIP, CODE + 0x1620)

    if address == 0x10001632:
        mu.reg_write(UC_X86_REG_RIP, 0x10001733)


def init_mu():
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(STACK, STACK_SIZE)

    mu.reg_write(UC_X86_REG_RSP, STACK + (STACK_SIZE // 2))
    return mu


if __name__ == "__main__":
    with open("./thaMilo-the_lock-level_2", "rb") as f:
        code = f.read()

    mu = init_mu()

    # setting up the code
    mu.mem_map(CODE, CODE_SIZE)
    mu.mem_write(CODE, code)

    # adding hook to trace instructions
    mu.hook_add(UC_HOOK_CODE, hook_code)

    print(mu.mem_read(CODE + 0x17510, 25))
    mu.emu_start(CODE + 0x10B0, CODE + 0x1751)
    print(mu.mem_read(CODE + 0x17510, 25))

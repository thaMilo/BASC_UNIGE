from unicorn import *
from unicorn.x86_const import *
from pwn import *

# Base address and stack definitions
CODE_BASE = 0x10000000
CODE_SIZE = 0x10000000
STACK_BASE = 0x00100000
STACK_SIZE = 0x00100000

skip_list = [
    0x10001632,
    0x10001647,
    0x10001653,
    0x10001668,
    0x10001674,
    0x10001689,
    0x100014EF,
    0x100014FE,
    0x100016A2,
    0x100016C0,
    0x100016DE,
    0x100016FC,
    0x1000170B,
    0x10001729,
    0x10001751,
    0x1000175D,
    0x1000176F,
    0x1000178D,
    0x1000179E,
    0x10001814,
    0x10001825,
]


def hook_code(mu, address, size, user_data):
    print(
        f"[ INS - 0x{address:x} ] [ SIZE - {size}B ] [ RSP - 0x{mu.reg_read(UC_X86_REG_RSP, 64):x}]"
    )
    if address in skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)


if __name__ == "__main__":
    try:
        with open("./thaMilo-the_lock-level_2", "rb") as f:
            code = f.read()

        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # setting up the stack
        rsp = STACK_BASE + (STACK_SIZE // 2)
        mu.mem_map(STACK_BASE, STACK_SIZE)
        mu.reg_write(UC_X86_REG_RSP, rsp)

        # setting up the code
        mu.mem_map(CODE_BASE, CODE_SIZE, UC_PROT_ALL)
        mu.mem_write(CODE_BASE, code)

        # adding hook to trace instructions
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # starting emulation from main
        mu.emu_start(CODE_BASE + 0x1620, CODE_BASE + 0x1828, timeout=0, count=0)

        print(mu.mem_read(CODE_BASE, CODE_SIZE).decode("latin1"))

    except UcError as e:
        print(f"ERROR: {e}")

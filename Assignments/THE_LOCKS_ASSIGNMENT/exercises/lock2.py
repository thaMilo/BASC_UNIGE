from unicorn import *
from unicorn.x86_const import *
from pwn import *

# Base address and stack definitions
BASE = 0x00100000
STACK_ADDR = 0x00200000
STACK_SIZE = 2 * 1024 * 1024
skip_list = [
    0x1011F1,
    0x1011FF,
    0x101209,
    0x101217,
    0x101221,
    0x10122F,
    0x101239,
    0x101247,
    0x101251,
    0x10125F,
    0x101269,
    0x101277,
    0x101281,
    0x10128F,
    0x101295,
    0x1012A1,
    0x1012AB,
    0x1012B9,
    0x1012C3,
    0x1012D1,
    0x1012DB,
    0x1012E9,
    0x1012F3,
    0x101301,
    0x10130B,
    0x101319,
    0x101323,
    0x101331,
    0x10133B,
    0x101349,
    0x101353,
    0x101361,
    0x10136B,
    0x101379,
    0x101383,
    0x101391,
    0x10139B,
    0x1013A9,
    0x1013B3,
    0x1013C1,
    0x1013CB,
    0x1013D9,
    0x1013E3,
    0x1013F1,
    0x1013FB,
    0x101409,
    0x101413,
    0x101421,
    0x10142B,
    0x101439,
]


def hook_code(mu, address, size, user_data):
    print(f"INSTRUCTION 0x{address:x} SIZE {size}")
    if address in skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)
        if address == 0x101439:
            password = mu.mem_read(0x117510, 16)
            print(password)


if __name__ == "__main__":
    try:
        with open("./thaMilo-the_lock-level_2", "rb") as f:
            code = f.read()
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(BASE, max(len(code), 1024 * 1024), UC_PROT_ALL)
        mu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)

        mu.mem_write(BASE, code)
        mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 8)
        mu.reg_write(UC_X86_REG_RAX, 0x100000)

        mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.emu_start(BASE + 0x173D, BASE + 0x1833)

    except UcError as e:
        print(f"ERROR: {e}")

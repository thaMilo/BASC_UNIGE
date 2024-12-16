from unicorn import *
from unicorn.x86_const import *
from pwn import *

CODE = 0x10000000
CODE_SIZE = 0x10000000
STACK = 0x30000000
STACK_SIZE = 0x10000000
HEAP = 0x50000000
HEAP_SIZE = 0x10000000

skip_list = []


def hook_code(mu, address, size, user_data):
    print(f"[ INS - 0x{address:x} ] [ SIZE - {size}B ]")
    if address in skip_list:
        mu.reg_write(UC_X86_REG_RIP, address + size)


def init_mu():
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(HEAP, HEAP_SIZE)

    mu.reg_write(UC_X86_REG_ESP, STACK + (STACK_SIZE // 2) - 0x200)
    mu.reg_write(UC_X86_REG_EBP, STACK + (STACK_SIZE // 2))
    return mu


if __name__ == "__main__":
    # with open("./thaMilo-the_lock-level_2", "rb") as f:
    #     code = f.read()

    code = b"\x31\xc0\xb8\x42\x00\x00\x00\x05\xf5\x12\x00\x00"
    mu = init_mu()

    # # setting up the stack
    # rsp = STACK_BASE + (STACK_SIZE // 2)
    # mu.mem_map(STACK_BASE, STACK_SIZE)
    # mu.reg_write(UC_X86_REG_ESP, rsp)

    # setting up the code
    mu.mem_map(CODE, CODE_SIZE)
    mu.mem_write(CODE, code)
    mu.reg_write(UC_X86_REG_EIP, CODE)

    # adding hook to trace instructions
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # emulating the decode function
    # mu.emu_start(CODE_BASE + 0x173D, CODE_BASE + 0x1751, timeout=0, count=0)
    mu.emu_start(CODE, CODE + len(code))
    print(hex(mu.reg_read(UC_X86_REG_EAX)))

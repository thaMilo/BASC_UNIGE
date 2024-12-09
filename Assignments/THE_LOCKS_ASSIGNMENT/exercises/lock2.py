from unicorn import *
from unicorn.x86_const import *
from pwn import *
import os


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    code = b""
    with open("./thaMilo-the_lock-level_2", "rb") as f:
        code = f.read()

    stack_base = 0x00100000
    stack_size = 0x00100000

    ESP = stack_base + (stack_size // 2)

    uc.mem_map(stack_base, stack_size)
    uc.mem_write(stack_base, b"\x00" * stack_size)
    uc.reg_write(UC_X86_REG_ESP, ESP)

    target_base = 0x00400000
    target_size = 0x00100000

    uc.mem_map(target_base, target_size, UC_PROT_ALL)
    uc.mem_write(target_base, b"\x00" * target_size)
    uc.mem_write(target_base, code)

    target_end = target_base + len(code)
    uc.emu_start(target_base, target_end, timeout=0, count=0)

    print("done")

    EAX = uc.reg_read(UC_X86_REG_EAX)
    print(EAX)


if __name__ == "__main__":
    main()

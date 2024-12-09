from unicorn import *
from unicorn.x86_const import *
from pwn import *

BIN = "./thaMilo-the_lock-level_2"


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    elf = ELF(BIN)
    entry_point = elf.entry

    for segment in elf.segments:
        if segment.header.p_type == "PT_LOAD":
            seg_start = segment.header.p_vaddr
            seg_size = segment.header.p_memsz
            seg_data = segment.data()

            seg_size_aligned = (seg_size + 0xFFF) & ~0xFFF

            uc.mem_map(seg_start, seg_size_aligned, UC_PROT_ALL)
            uc.mem_write(seg_start, seg_data)
            print(f"Mapped segment at 0x{seg_start:X} - Size: {seg_size_aligned:X}")

    stack_base = 0x7FFFFFF00000
    stack_size = 0x10000
    uc.mem_map(stack_base, stack_size, UC_PROT_ALL)
    uc.reg_write(UC_X86_REG_RSP, stack_base + stack_size // 2)
    print(f"Stack mapped at 0x{stack_base:X} - Size: {stack_size:X}")

    try:
        print(f"Starting emulation at 0x{entry_point:X}")
        uc.emu_start(entry_point, entry_point + 0x1000)
    except UcError as e:
        print(f"Emulation error: {e}")


if __name__ == "__main__":
    main()


# from unicorn import *
# from unicorn.x86_const import *
# from pwn import *

# BIN = "./thaMilo-the_lock-level_2"


# def main():
#     uc = Uc(UC_ARCH_X86, UC_MODE_64)

#     stack_base = 0x10000000
#     stack_size = 0x010000000
#     ESP = stack_base + (stack_size // 2)

#     uc.mem_map(stack_base, stack_size)
#     uc.mem_write(stack_base, b"\x00" * stack_size)
#     uc.reg_write(UC_X86_REG_ESP, ESP)

#     target_base = 0x40000000
#     target_size = 0x10000000

#     code = ""
#     with open(BIN, "rb") as fp:
#         code = fp.read()

#     uc.mem_map(target_base, target_size, UC_PROT_ALL)
#     uc.mem_write(target_base, b"\x00" * target_size)
#     uc.mem_write(target_base, code)

#     target_end = target_base + len(code)

#     uc.emu_start(target_base, target_end, timeout=0, count=0)
#     print("done")


# if __name__ == "__main__":
#     main()

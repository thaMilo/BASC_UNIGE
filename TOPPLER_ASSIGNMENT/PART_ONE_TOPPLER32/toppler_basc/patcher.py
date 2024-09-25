from pwn import asm, ELF

if __name__ == "__main__":
    elf = ELF("./toppler32")

    # infinite lives
    lifes_left_function = elf.symbols["_Z13pts_lifesleftv"]
    patch_code = asm("mov al, 1; ret")
    elf.write(lifes_left_function, patch_code)

    # infinite time

    time_update_address = 0x0804C4C9
    new_instruction = asm("ret")
    elf.write(time_update_address, new_instruction)

    # no collisions
    collisions_address = 0x0805CB01
    new_instruction = asm("ret")
    elf.write(collisions_address, new_instruction)

    # no dropping of 1 layer
    # drown_address = 0x0805C012
    # new_instruction = asm("nop")
    # elf.write(drown_address, new_instruction)

    # drown_address = 0x0805C05B
    # new_instruction = asm("nop")
    # elf.write(drown_address, new_instruction)

    drown_address = 0x0805C060
    new_instruction = asm("jmp 0x0805C014")
    elf.write(drown_address, new_instruction)

    elf.save("./toppler_patched")

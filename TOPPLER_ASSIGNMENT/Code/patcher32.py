from pwn import asm, ELF

if __name__ == "__main__":
    elf = ELF("./toppler32")

    # infinite lives
    lifes_left_function = elf.symbols["_Z13pts_lifesleftv"]
    patch_code = asm("mov al, 1; ret")
    elf.write(lifes_left_function, patch_code)

    # infinite time
    time_update_address = 0x0804C4C9
    patch_code = asm("ret")
    elf.write(time_update_address, patch_code)

    # no collisions
    collisions_address = 0x0805CB01
    patch_code = asm("ret")
    elf.write(collisions_address, patch_code)

    # no balls and no robots
    jumping_address = 0x08056751
    patch_code = asm("ret")
    elf.write(jumping_address, patch_code)

    jumping_address = 0x08056879
    patch_code = asm("ret")
    elf.write(jumping_address, patch_code)
   
    elf.save("./toppler_patched")

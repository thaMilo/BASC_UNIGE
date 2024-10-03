from pwn import asm, ELF

if __name__ == "__main__":
    elf = ELF("./toppler32")

    # infinite lives
    lifes_left_address = 0x08056417
    patch_code = asm("ret")
    elf.write(lifes_left_address, patch_code)

    # infinite time
    time_update_address = 0x0804C4C9
    patch_code = asm("ret")
    elf.write(time_update_address, patch_code)

    # no collisions
    collisions_address = 0x0805CB01
    patch_code = asm("ret")
    elf.write(collisions_address, patch_code)

    # no balls and no robots
    robots_address = 0x08056a4a
    patch_code = asm("ret")
    elf.write(robots_address, patch_code)
   
    elf.save("./toppler_patched")

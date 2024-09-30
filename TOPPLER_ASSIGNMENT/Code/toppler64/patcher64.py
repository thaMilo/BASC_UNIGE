from pwn import asm, ELF

if __name__ == "__main__":
    elf = ELF("./toppler64")

    # # infinite lives
    # lifes_left_function = elf.symbols["_Z13pts_lifesleftv"]
    # patch_code = asm("mov al, 1; ret")
    # elf.write(lifes_left_function, patch_code)
    
    # infinite lives
    time_update_address = 0x00414008
    patch_code = asm("nop")
    elf.write(time_update_address, patch_code)
    
    # infinite time
    time_update_address = 0x004063b2
    patch_code = asm("ret")
    elf.write(time_update_address, patch_code)

    # no enemies
    collisions_address = 0x414d9e
    patch_code = asm("ret")
    elf.write(collisions_address, patch_code)
   
    elf.save("./toppler_patched")

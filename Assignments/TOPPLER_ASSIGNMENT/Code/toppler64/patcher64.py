from pwn import *

if __name__ == "__main__":
    elf = ELF("./toppler64")
    context.update(arch='amd64')
  
    # infinite lives
    lives_address = 0x414008
    patch_code = asm("nop")
    elf.write(lives_address, patch_code)
    
    # infinite time
    time_address = 0x4063b2
    patch_code = asm("ret")
    elf.write(time_address, patch_code)

    # no enemies
    robots_address = 0x414d9e
    patch_code = asm("ret")
    elf.write(robots_address, patch_code)

    # no collisions
    collisions_address = 0x41e119
    patch_code = asm("ret")
    elf.write(collisions_address, patch_code)

    elf.save("./toppler_patched")

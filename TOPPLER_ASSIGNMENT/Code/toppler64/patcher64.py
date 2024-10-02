from pwn import *

if __name__ == "__main__":
    elf = ELF("./toppler64")
    context.update(arch='amd64')
  
    # lives do not decrease
    time_update_address = 0x414008
    patch_code = asm("nop")
    elf.write(time_update_address, patch_code)
    
    # infinite time
    time_update_address = 0x4063b2
    patch_code = asm("ret")
    elf.write(time_update_address, patch_code)

    # no enemies
    collisions_address = 0x414d9e
    patch_code = asm("ret")
    elf.write(collisions_address, patch_code)


    # starting with more lives than 3
    collisions_address = 0x403e8f
    patch_code = asm("mov dword ptr[rax+0x40], 0x9")
    elf.write(collisions_address, patch_code)
         
    collisions_address = 0x404291
    patch_code = asm("nop")
    elf.write(collisions_address, patch_code)
   
    elf.save("./toppler_patched")

from pwn import *

if __name__ == "__main__":
    elf = ELF('./toppler32')
    
    # infinite lives patch
    lifes_left_function = elf.symbols["_Z13pts_lifesleftv"]
    patch_code = asm('mov al, 1; ret')
    elf.write(lifes_left_function, patch_code)

    # time doesn't pass
    time_update_address = 0x0804c4c9
    new_instruction = asm('ret')
    elf.write(time_update_address, new_instruction)
    
    elf.save('./toppler_patched')

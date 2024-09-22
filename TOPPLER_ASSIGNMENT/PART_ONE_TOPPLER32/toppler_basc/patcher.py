from pwn import *

if __name__ == "__main__":
    elf = ELF('./toppler32')
    
    # infinite lives patch
    lifes_left_function = elf.symbols["_Z13pts_lifesleftv"]
    patch_code = asm('mov al, 1; ret')
    elf.write(lifes_left_function, patch_code)
    elf.save('./toppler_patched')

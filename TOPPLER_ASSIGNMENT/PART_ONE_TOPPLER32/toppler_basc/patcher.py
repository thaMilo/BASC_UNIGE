from pwn import *

if __name__ == "__main__":
    elf = ELF('./toppler32')
    # target_address = elf.symbols['vulnerable_function']
    # new_bytes = asm('ret')  # This assembles a 'ret' instruction
    # elf.write(target_address, new_bytes)
    # elf.save('./patched_binary')
    print("Binary patched successfully!")

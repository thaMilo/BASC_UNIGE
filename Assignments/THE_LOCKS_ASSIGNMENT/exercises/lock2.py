from unicorn import *
from unicorn.x86_const import *
from pwn import *


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)


if __name__ == "__main__":
    main()


# from unicorn import *
# from unicorn.x86_const import *
# from pwn import *
# import os

# PAGE_SIZE = 0x100000
# CODE_START = 0x100000
# STACK_START = 0x8000
# STACK_SIZE = PAGE_SIZE * 2
# DATA_START = 0x6000
# DATA_SIZE = PAGE_SIZE * 2

# PASSWORD_DECODE_FUNC =
# PASSWORD_CHECK_FUNC =
# PASSWORD_ADDRESS =

# binary_path = "thaMilo-the_lock-level_2"
# binary_code = open(binary_path, "rb").read()
# binary_size = len(binary_code)

# CODE_SIZE = ((binary_size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE

# mu = Uc(UC_ARCH_X86, UC_MODE_64)

# try:
#     mu.mem_map(CODE_START, CODE_SIZE)
#     mu.mem_map(DATA_START, DATA_SIZE)
#     mu.mem_map(STACK_START, STACK_SIZE)
#     mu.mem_write(CODE_START, binary_code)
#     mu.reg_write(UC_X86_REG_RSP, STACK_START + STACK_SIZE - 8)

# except UcError as e:
#     print(f"[!] Memory Mapping Error: {e}")
#     exit(1)


# def hook_code(mu, address, size, user_data):
#     if address == PASSWORD_DECODE_FUNC:
#         print(f"[+] Password decoding function called at {hex(address)}")
#     elif address == PASSWORD_CHECK_FUNC:
#         password = mu.mem_read(PASSWORD_ADDRESS, 0x19).decode("latin-1").strip("\x00")
#         print(f"[+] Extracted Password: {password}")
#         mu.emu_stop()


# mu.hook_add(UC_HOOK_CODE, hook_code)

# try:
#     print("[*] Starting emulation...")
#     mu.emu_start(CODE_START, CODE_START + binary_size)
# except UcError as e:
#     print(f"[!] Emulation Error: {e}")

# try:
#     extracted_password = (
#         mu.mem_read(PASSWORD_ADDRESS, 0x19).decode("latin-1").strip("\x00")
#     )
#     print(f"[+] Final Extracted Password: {extracted_password}")

#     # Automate exploitation using pwntools
#     print("[*] Automating exploitation...")
#     p = process("thaMilo-the_lock-level_2")
#     p.sendline(extracted_password)
#     result = p.recvall().decode()
#     print(f"[+] Program Output:\n{result}")
# except UcError as e:
#     print(f"[!] Memory Read Error: {e}")

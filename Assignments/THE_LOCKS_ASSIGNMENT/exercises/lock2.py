from unicorn import *
from unicorn.x86_const import *
from pwn import *

CODE = 0x10000000
CODE_SIZE = 0x30000000
STACK = 0x60000000
STACK_SIZE = 0x10000000


def hook_code(mu, address, size, user_data):
    # print(f"|--[  0x{address:x}  ]--[  {size}B  ]--|")

    if address == CODE + 0x11DE:  # Adjust based on actual function address
        mu.reg_write(UC_X86_REG_RDI, CODE + 0x16510)
    if address == 0x100010CF:
        mu.reg_write(UC_X86_REG_RIP, CODE + 0x1620)

    if address == 0x10001632:
        mu.reg_write(UC_X86_REG_RIP, CODE + 0x1733)


def init_mu():
    with open("./thaMilo-the_lock-level_2", "rb") as f:
        code = f.read()
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # setting up the stack
        mu.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        mu.reg_write(UC_X86_REG_RSP, STACK + (STACK_SIZE // 2))
        # setting up the code
        mu.mem_map(CODE, CODE_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        mu.mem_write(CODE, code)
        mu.hook_add(UC_HOOK_CODE, hook_code)
        return mu


if __name__ == "__main__":
    mu = init_mu()
    mu.emu_start(CODE + 0x10B0, CODE + 0x1751)
    print("DECODED PASSWORD : " + mu.mem_read(CODE + 0x16510, 25).decode("latin1"))

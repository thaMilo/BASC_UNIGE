from unicorn import *
from unicorn.x86_const import *
from pwn import *

CODE = 0x10000000
CODE_SIZE = 0x30000000
STACK = 0x60000000
STACK_SIZE = 0x10000000


def hook_code(mu, address, size, user_data):
    # 0x11DE offset of the decode function
    if address == CODE + 0x11DE:
        # 0x16510 offset of the password
        # The password's address had to be put in the rdi register manually
        # since we are only emulating part of the binary
        mu.reg_write(UC_X86_REG_RDI, CODE + 0x16510)


def init_mu():
    with open("./thaMilo-the_lock-level_2", "rb") as f:
        code = f.read()
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        mu.reg_write(UC_X86_REG_RSP, STACK + (STACK_SIZE // 2))
        mu.mem_map(CODE, CODE_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        mu.mem_write(CODE, code)
        mu.hook_add(UC_HOOK_CODE, hook_code)
        return mu


if __name__ == "__main__":
    mu = init_mu()
    # 0x1733 offset of the call to the decode function
    # 0x1751 offset of the line right after the call to decode dunction
    mu.emu_start(CODE + 0x1733, CODE + 0x1751)
    print("DECODED PASSWORD : " + mu.mem_read(CODE + 0x16510, 25).decode("latin1"))

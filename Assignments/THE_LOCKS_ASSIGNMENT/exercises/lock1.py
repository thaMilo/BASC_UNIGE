from pwn import *

p = process("./thaMilo-the_lock-level_1")

gdb.attach(
    p,
    """
    break clear
    continue
""",
)

password = b"a"
p.sendline(password)
p.interactive()

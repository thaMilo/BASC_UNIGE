# level_1

For the first level I first wanted to see what was going inside using Ghidra

```c
undefined4 main(void)
{
  char *pcVar1;
  size_t sVar2;
  int iVar3;
  char acStack_115 [257];
  size_t local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setvbuf(_stdin,(char *)0x0,2,0);
  setvbuf(_stdout,(char *)0x0,2,0);
  setvbuf(_stderr,(char *)0x0,2,0);
  logo();
  puts(
      "This program hides \x1b[0;32ma secret flag\x1b[0m in a virtual-safe protected by a \x1b[0;33m super-secret-password\x1b[0m (it\'s so good that \x1b[1;37ma lot of people use it!\x1b[0m) and  does the following:"
      );
  printf("\x1b[0;36m1)\x1b[0m decodes the password in memory (function at address: \x1b[0;35m%p\x1b[ 0m)\n"
         ,decode);
  printf("\x1b[0;36m2)\x1b[0m checks whether you know the password; if you do, the flag is printed ( using function at address: \x1b[0;35m%p)\n"
         ,print_flag);
  printf("\x1b[0;36m3)\x1b[0m overwrites the password in memory with zeroes (function at address: \x 1b[0;35m%p\x1b[0m)\n"
         ,clear);
  puts("\x1b[0;36m4)\x1b[0m exits");
  printf("The \x1b[0;33maddress of super-secret-password is random\x1b[0m (this time it is \x1b[0;35 m%p\x1b[0m), but it will be passed, as the first argument, to some functions. If you could only st op time and read the password before it\'s too late...\n\n"
         ,my_super_password);
  decode(my_super_password,0xc);
  printf("Please \x1b[0;31menter the password\x1b[0m: ");
  pcVar1 = fgets(acStack_115 + 1,0x100,_stdin);
  if (pcVar1 == (char *)0x0) {
    exit(1);
  }
  sVar2 = strlen(acStack_115 + 1);
  local_14 = sVar2;
  if (acStack_115[sVar2] == '\n') {
    local_14 = sVar2 - 1;
    acStack_115[sVar2] = '\0';
  }
  iVar3 = strcmp(acStack_115 + 1,my_super_password);
  if (iVar3 == 0) {
    printf("\x1b[0;33m\nWow! You got it, congratulations.\n\x1b[0m");
    print_flag(acStack_115 + 1,local_14);
  }
  else {
    puts("\nNice try... however, it\'s wrong. Try again.");
  }
  clear(my_super_password,0xd);
  return 0;
}
```

I noticed immediately that the program called the **decode** function before prompting the user to insert the password.
So as the bin suggested when the **clear function** was called I could read the decoded password because it was passed as the first argument.
Setting a break-point to that function and giving a random string as password was enough to lock-pick the first level.

![](./imgs/py_script_lock1.png)

Using "residentevil" as password I was able to get the first flag

```
BASC{Y0u_int3rc3pt3d_stRcMp_didnt_U---thaMilo-8NUmLrFh}
```

Automating this with python resulted in the following script

```python
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
```

# level_2

Running file on level_2 revealed that the elf was pie and stripped so I couldn't rely on functions' name to analyse it but just as hinted in the README I used unicorn to emulate the binary.

Unicorn allows to emulate only some parts of the chosen binary and since I knew that right after the call to the decode function the clear password could be read at offset **0x16510** I decided to emulate only that.

In order to decode the password I had to put manually its address in the RDI register so that the function could reference it correctly in the body.


```python
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
```

Doing so granted me the password and consequently the flag

```
DECODED PASSWORD : 123456789123_lovelovelove
```

```
Wow! You got it, congratulations.
Here is your flag:
BASC{Br3akP0int5_and_3mul4t10n_R_us3fUl---thaMilo-Q8rGk6EE}
```










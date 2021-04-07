---
layout: post
title: "HackCTF strncmp"
author: "Ph4nt0m"
categories: [WriteUp, Reversing]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Reversing]
---

# strncmp

## Source

```c
int __fastcall check(int a1, const char **a2)
{
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = atoi(a2[1]);
  if ( v3 * (v3 - 14) == -49 )
    key = v3;
  else
    key = 0;
  return main(a1, a2, a2);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+20h] [rbp-50h]
  char v5[28]; // [rsp+40h] [rbp-30h]
  unsigned __int64 v6; // [rsp+68h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  qmemcpy(v5, "OfdlDSA|3tXb32~X3tX@sX`4tXtz", sizeof(v5));
  puts("Enter your input:");
  __isoc99_scanf("%s", &v4);
  if ( !strcmp_(&v4, v5) )
    puts("Good game");
  else
    puts("Always dig deeper");
  return 0;
}

int __fastcall strcmp_(const char *a1, const char *a2)
{
  int v3; // [rsp+14h] [rbp-1Ch]
  int i; // [rsp+18h] [rbp-18h]
  int j; // [rsp+1Ch] [rbp-14h]

  v3 = 0;
  for ( i = 0; i <= 21; ++i )
    v3 = (v3 + 1) ^ 0x17;
  for ( j = 0; j < strlen(a1); ++j )
    a1[j] ^= key;
  return strncmp(a1, a2, 28uLL);
}
```

## Solve

플래그를 찾아야 하는 문제인데 단순하지는 않은 문제이다. 먼저 check는 main함수 이전에 Call을한다. 거기서 key값이 세팅되고 이후 메인함수에서 strcmp_함수가 실행되어 값을 비교한다.

```bash
  v3 = atoi(a2[1]);
  if ( v3 * (v3 - 14) == -49 )
    key = v3;
  else
    key = 0;
```

이 부분에서 if문의 v3값을 구하면 key값이 결정되는데 2차 방정식이라 한다.

```bash
x^2 - 14x + 49 = 0
(x - 7)(x - 7) = 0
x = 7
```

까먹었다....라고 글을 쓰다 풀었다. 하지만 반복문을 돌리기로 했다.

```bash
string = "OfdlDSA|3tXb32~X3tX@sX`4tXtz"
data = []
v3 = 0

for i in range(100):
	for j in range(len(string)):
		data.append(chr(ord(string[j]) ^ i))
	print "Key : %d Flag : %s"%(i,"".join(data))
	data = []
```

물론 방금 값을 구했으니 그걸로 짠 코드도 있다.

```bash
string = "OfdlDSA|3tXb32~X3tX@sX`4tXtz"
data = []

for i in range(len(string)):
	data.append(chr(ord(string[i]) ^ 7))
print "".join(data)
```

```bash
➜  reversing git:(master) ✗ python strncmp2.py
HackCTF{Flag}
```

생각지도못한 수학식이 나와 당황했다.
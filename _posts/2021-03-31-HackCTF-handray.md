---
layout: post
title: "HackCTF handray"
author: "Ph4nt0m"
categories: [WriteUp, Reversing]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Reversing]
---

# handray

## Source

```c
push   rbp
mov    rbp,rsp
sub    rsp,0x10
mov    DWORD PTR [rbp-0x4],0x0
cmp    DWORD PTR [rbp-0x4],0x1

jne    0x40058d <main+103>
mov    DWORD PTR [rbp-0x8],0x0
jmp    0x400571 <main+75>

mov    eax,DWORD PTR [rbp-0x8]
cdqe
movzx  eax,BYTE PTR [rax+0x6010e0]
mov    edx,eax
mov    eax,DWORD PTR [rbp-0x8]
cdqe
mov    eax,DWORD PTR [rax*4+0x601060]
add    eax,edx
mov    edx,eax
mov    eax,DWORD PTR [rbp-0x8]
cdqe
mov    BYTE PTR [rax+0x6010e0],dl
add    DWORD PTR [rbp-0x8],0x1
cmp    DWORD PTR [rbp-0x8],0x1e
jle    0x400544 <main+30>

mov    esi,0x6010e0
mov    edi,0x400638
mov    eax,0x0
call   0x400400 <printf@plt>
jmp    0x40059c <main+118>

mov    edi,0x400648
mov    eax,0x0
call   0x400400 <printf@plt>
mov    eax,0x0
leave
ret
```

## Solve

안티 Hex-ray를 건 것 같은데 어디다 걸었는지는 모르겠다.

문제는 생각보다 간단했다 전부 Handray로 C로 만들려 했으나 초반 바이트패치로

```c
mov    DWORD PTR [rbp-0x4],0x0
cmp    DWORD PTR [rbp-0x4],0x1
```

이 부분에서 비교값을 0으로 패치해버리니 그 다음은 그냥 플래그 출력이더라.

그래서 따로 핸드레이 없이 플래그를 얻었다.

```bash
➜  reversing git:(master) ✗ ./handray
flag is HackCTF{Flag}
```
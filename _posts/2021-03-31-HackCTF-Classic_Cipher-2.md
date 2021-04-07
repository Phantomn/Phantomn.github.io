---
layout: post
title: "HackCTF Classic Cipher - 2"
author: "Ph4nt0m"
categories: [WriteUp, Crypto]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Crypto]
---

# Classic Cipher - 2

## Source

```c
Hint : Key is Number
➜  crypto git:(master) ✗ cat ╣о┴ж.txt
This is simple transposition cipher
key is "python"
Ciphertext is hreCp1_ev_s117nr_ys17eer132n_5

```

## Solve

난 이 문제를 보고 디코드겠거니 생각하고 여러 디코더를 돌렸다. 하지만 모두 실패였다.

알고보니 전치암호 라는 것이었다.

힌트에서 준 것은 "python"

6글자이며 알파벳 순서대로 번호를 매기면

+------------------+
| p | y | t | h | o | n |
+------------------+
| 4 | 6 | 5 | 1 | 3 | 2 |
+------------------+

이렇게 된다.

이제 대상 문자열을 6개씩 자른다.

hreCp1 _ev_s1 17nr_y s17eer 132n_5

그 다음 465132 순서대로 문자열을 배치한다.

C1pher _1s_ve ry_1n7 eres71 n5_123

C1pher_1s_very_in7eres71n5_123

이렇게 또 하나 암호학을 배웠다
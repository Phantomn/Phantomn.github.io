---
layout: post
title: "HackCTF Reversing Me"
author: "Ph4nt0m"
categories: [WriteUp, Reversing]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Reversing]
---

# Reversing Me

## Source

```c
#include <stdio.h>
#include <string.h>

int main() {
	int i;
	char *serial = "H`cjCUFzhdy^stcbers^D1_x0t_jn1w^r2vdrre^3o9hndes1o9>}";
	char enter[54];
	printf("키를 입력하시게 : ");
	scanf("%s", enter);
	if (strlen(enter) == strlen(serial)) {
		for (i = 0; i < strlen(serial) && (enter[i] ^ (i % 2)) == serial[i]; i++);
		if (i - 1 == strlen(enter))
			printf("정답일세!\n");
	}
	else
		printf("그건 아닐세...\n");
		exit(0);

}
```

## Solve

소스가 그지같이 되어 있지만 핵심적으로 문자열을 변환시키는 부분은 이 부분이다.

```c
for (i = 0; i < strlen(serial) && (enter[i] ^ (i % 2)) == serial[i]; i++);
```

따라서 간단히 xor하는 소스를 짜면 플래그가 나온다.

```python
string = "H`cjCUFzhdy^stcbers^D1_x0t_jn1w^r2vdrre^3o9hndes1o9>}"
data = ""
for i in range(len(string)):
	data += chr(ord(string[i]) ^ (i % 2))

print data
```
---
layout: post
title: "HackCTF Classic Cipher - 1"
author: "Ph4nt0m"
categories: [WriteUp, Crypto]
date: 2021-03-31 17:00
tag: [WriteUp, HackCTF, Crypto]
---

# Classic Cipher - 1

## Source

```c
Hint : [::-1]
?y4zl4J_d0ur_b0f_0K zp nhsm
```

## Solve

우선 힌트를 가지고 해당 텍스트를 반대로 출력해봤다.

```python
string = ""
with open("Cipher.txt", "rb") as f:
	string = f.read()
print string[::-1]
f.close()
```

```c
mshn pz K0_f0b_ru0d_J4lz4y?
```

무슨 물음같은데 정공법대로 Caesar 부터 돌린다.

```c
import string

def sub_Encrypt(input, key):
	data = []

	for ch in input:
		if ch.isalpha():
			tmp = ch.lower()
			tmp = ord(tmp)
			tmp -= ord('a')
			tmp -= (key % 26)
			tmp = Alpha[tmp]

			if ch.islower():
				ch = tmp.lower()
			else:
				ch = tmp.upper()
		data.append(ch)
	return data

Alpha = list(string.ascii_lowercase)

try:
	message = input("Input Message >> ")
	for i in range(0, 26):
		key = i
		data = sub_Encrypt(message, key)
		print ("Key : %d String : %s"%(i,"".join(data)))

except EOFError:
    print("EOFError occurred")

except ValueError:
    print("ValueError occurred")
```

어느 블로그에서 참조했으며 일부 수정했다. 그리고 아까의 텍스트를 넣고 26번 반복해서 돌렸다.

```c
Key : 0 String : mshn pz K0_f0b_ru0d_J4lz4y?
Key : 1 String : lrgm oy J0_e0a_qt0c_I4ky4x?
Key : 2 String : kqfl nx I0_d0z_ps0b_H4jx4w?
Key : 3 String : jpek mw H0_c0y_or0a_G4iw4v?
Key : 4 String : iodj lv G0_b0x_nq0z_F4hv4u?
Key : 5 String : hnci ku F0_a0w_mp0y_E4gu4t?
Key : 6 String : gmbh jt E0_z0v_lo0x_D4ft4s?
Key : 7 String : flag is D0_y0u_kn0w_C4es4r?
Key : 8 String : ekzf hr C0_x0t_jm0v_B4dr4q?
Key : 9 String : djye gq B0_w0s_il0u_A4cq4p?
Key : 10 String : cixd fp A0_v0r_hk0t_Z4bp4o?
Key : 11 String : bhwc eo Z0_u0q_gj0s_Y4ao4n?
Key : 12 String : agvb dn Y0_t0p_fi0r_X4zn4m?
Key : 13 String : zfua cm X0_s0o_eh0q_W4ym4l?
Key : 14 String : yetz bl W0_r0n_dg0p_V4xl4k?
Key : 15 String : xdsy ak V0_q0m_cf0o_U4wk4j?
Key : 16 String : wcrx zj U0_p0l_be0n_T4vj4i?
Key : 17 String : vbqw yi T0_o0k_ad0m_S4ui4h?
Key : 18 String : uapv xh S0_n0j_zc0l_R4th4g?
Key : 19 String : tzou wg R0_m0i_yb0k_Q4sg4f?
Key : 20 String : synt vf Q0_l0h_xa0j_P4rf4e?
Key : 21 String : rxms ue P0_k0g_wz0i_O4qe4d?
Key : 22 String : qwlr td O0_j0f_vy0h_N4pd4c?
Key : 23 String : pvkq sc N0_i0e_ux0g_M4oc4b?
Key : 24 String : oujp rb M0_h0d_tw0f_L4nb4a?
Key : 25 String : ntio qa L0_g0c_sv0e_K4ma4z?
```
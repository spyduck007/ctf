---
title: Reduced Dimension
date: 2025-01-27
tags:
  - crypto
  - 0xL4ugh-CTF-v5
---

**Challenge:** Reduced Dimension
**Category:** Crypto
**Flag:** `0xL4ugh{M4t_Qu4t3rn1on_By_Zwique}`

---

## My initial read / first impressions

We are provided with a Python script `task.py` and the output of a run. The challenge implements a variation of RSA encryption, but instead of operating on simple integers, it operates on 4x4 matrices.

Looking closely at the `get_quaternion_matrix` function, the matrices represent **Quaternions**. A quaternion `Q = a_0 + a_1 i + a_2 j + a_3 k` is represented as a matrix in the code. The encryption process is:

1.  Generate two strong primes `p` and `q`, and `n = p * q`.
2.  Encode the flag `m` into four coefficients:
    -   `a0 = m`
    -   `a1 = m + 3p + 7q`
    -   `a2 = m + 11p + 13q`
    -   `a3 = m + 17p + 19q`
3.  Construct the matrix `A` from these coefficients.
4.  Compute `C = A^e mod n` (matrix exponentiation).
5.  Output the first row of the resulting matrix `C`.

The challenge is to recover `m` (the flag) given `n`, `e`, and the ciphertext row.

## The Vulnerability

Standard RSA relies on the difficulty of factoring `n`. However, in this challenge, the coefficients `a1`, `a2`, `a3` are constructed using linear combinations of `m`, `p`, and `q`. This structure leaks information about the prime factors.

Let's look at the coefficients modulo `p`:
-   `a1 = m + 7q mod p`
-   `a2 = m + 13q mod p`
-   `a3 = m + 19q mod p`

Notice that `a1`, `a2`, and `a3` form an **arithmetic progression** with a common difference of `6q`.
Specifically:
`a1 + a3 = (m + 7q) + (m + 19q) = 2m + 26q = 2(m + 13q) = 2 * a2`

So, `2 * a2 - a1 - a3 = 0 mod p`.

It turns out this linear relationship between the input coefficients propagates to the ciphertext components in a way that allows us to recover `p`. By taking the components of the ciphertext row `c0, c1, c2, c3` (where `c1, c2, c3` are negated in the matrix representation), we can compute:

`gcd(2 * c2 - c1 - c3, n)`

If this relationship holds, this GCD operation will reveal the prime factor `p`.

## The Logic

Once we have factored `n` into `p` and `q`, we can decrypt the message using the Chinese Remainder Theorem (CRT). We need to solve the RSA equation `Q^e = C` modulo `p` and modulo `q`.

### Quaternion RSA Decryption

Modulo a prime `p`, the encryption effectively takes place in a specific ring. The quaternion `Q` is of the form `scalar + vector`. Because we are essentially powering a single element, all intermediate values commute. This allows us to simplify the problem significantly.

Instead of dealing with 4x4 matrices, we can work with the eigenvalues. The eigenvalues of a quaternion matrix corresponding to `q = s + v` are `s ± √(-|v|^2)`.

1.  Calculate the "vector norm squared" of the ciphertext: `V_sq = c1^2 + c2^2 + c3^2`.
2.  The eigenvalues of the ciphertext matrix are `lambda_C = c0 +/- √(-V_sq)`.
3.  We are looking for the eigenvalues of the plaintext matrix `lambda_M`. The relationship is standard RSA: `lambda_M^e = lambda_C`.
4.  We solve for `lambda_M` by computing the `d`-th power of `lambda_C`, where `d` is the modular inverse of `e`.
    -   If `-V_sq` is a quadratic residue modulo `p`, we work in `GF(p)`.
    -   If not, we work in the extension field `GF(p^2)`.
5.  Once we have the plaintext eigenvalues `mu1, mu2`, the message `m` (the scalar part `a0`) is simply `(mu1 + mu2) / 2`.

## Constructing the Solver

I wrote a script to:
1.  Extract the ciphertext components.
2.  Factor `n` using the GCD vulnerability derived from the arithmetic progression of the coefficients.
3.  Implement a custom `decrypt_scalar` function that solves the RSA instance in the appropriate quadratic ring (either integers mod p or a degree-2 extension).
4.  Combine the results from `mod p` and `mod q` using CRT to recover the flag.

### Solution Script

```python
import math
from Crypto.Util.number import long_to_bytes, inverse

def decrypt_scalar(c0, c1, c2, c3, p, e):
    Vsq = (c1*c1 + c2*c2 + c3*c3) % p
    neg_Vsq = (-Vsq) % p
    
    leg = pow(neg_Vsq, (p - 1) // 2, p)
    
    roots = []
    is_split = False
    
    if leg == 0:
        roots = [0]
        is_split = True
    elif leg == 1:
        if p % 4 == 3:
            r = pow(neg_Vsq, (p + 1) // 4, p)
        else:
            s = p - 1
            r_val = 0
            while s % 2 == 0:
                s //= 2
                r_val += 1
            z = 2
            while pow(z, (p - 1) // 2, p) != p - 1:
                z += 1
            m_val = r_val
            c_val = pow(z, s, p)
            t_val = pow(neg_Vsq, s, p)
            R_val = pow(neg_Vsq, (s + 1) // 2, p)
            while t_val != 1:
                if t_val == 0:
                    R_val = 0
                    break
                tt = t_val
                i = 0
                for k in range(1, m_val):
                    tt = (tt * tt) % p
                    if tt == 1:
                        i = k
                        break
                b_val = pow(c_val, 1 << (m_val - i - 1), p)
                m_val = i
                c_val = (b_val * b_val) % p
                t_val = (t_val * c_val) % p
                R_val = (R_val * b_val) % p
            r = R_val
        roots = [r]
        is_split = True
    else:
        is_split = False
        
    m_val = 0
    if is_split:
        r = roots[0]
        lam1 = (c0 + r) % p
        lam2 = (c0 - r) % p
        d = inverse(e, p - 1)
        mu1 = pow(lam1, d, p)
        mu2 = pow(lam2, d, p)
        m_val = (mu1 + mu2) * inverse(2, p) % p
    else:
        D = neg_Vsq
        order = p * p - 1
        d = inverse(e, order)
        
        def mul2(u, v):
            real = (u[0]*v[0] + u[1]*v[1]*D) % p
            imag = (u[0]*v[1] + u[1]*v[0]) % p
            return (real, imag)
        
        def pow2(base, exp):
            res = (1, 0)
            while exp > 0:
                if exp % 2 == 1:
                    res = mul2(res, base)
                base = mul2(base, base)
                exp //= 2
            return res
            
        res = pow2((c0, 1), d)
        m_val = res[0]
        
    return m_val

# Parameters from challenge output
n = 24436555811992972366076806922530312273907496823566498825278523886197470905017391954938641972382127780163747562797956038193398654235644409459287830339446234525262072627164429789264587184451084484976035579016063031028571643546268940916664832350416704133070528632744931737357768415126788528052461206333395794164406084571633391115829776964808677724703621221154710591190375698378697896449037181113710774632252351521950724961537615755537875194862156989318761303971336544564950137455452434307027177388197740176937447577518701185717201408469263753367188476145954061480542913006467287367140336404472235624010067372903582272729
e = 65537
ciphertext_row = [7645133316138320672920829866179304735182212690210047500676759675676422841305242219428671895825721777886336067123230090334404443239249744649348019800170870076772170648917374424307951430757942474104583441027037157499352780211088515553775367980514698077272400388982174956856115745318060191675644580097459087877103744768611124967141106979760409192285920050555016687019974731108717211479671838777445410222040882405240324940267527783747870861280181437508731620415299917485800707003438326195859384666421699977525718115984628571014356722832203980578905816041544254774832610446558646617081820383024594943509109272533930838708, 15115864622351599035162706206257324674672546729754571030515410021905207212154731966558659435218498028437041608389247596685777775075531974586762001822195044830215779677969600204017249097853619421972862952306880626946718048703037486579156521083427871219972900601347265611525515981798763462306348832427757653091251117371763790691703299928013908976268558111890052847761824740201601000159794443256033087429920731339521534477358144537370658535238347192547096515188805816620173560028595429243354057894242958704409904709847929320587768434722670465044376198153825572537650025403520767434960328371498100779394191999106392405505, 13745229990855433471733323096856618171809729836071048905352245517395661673128741357306382928377040374671176807926741135701004188571412113925163459038871795016583126047331363592533678987966281886904921753115792048974820789657695172533157583206166353580229326903802517936396022419823884208200013314323762420208768560108045572583904747823741147655693248507409489075089305887965790292485140729487526433929859183972759579430813209494595211145046105006826362941878536200003370316700559144884743367020754865964581608047339157411175462078984500914717760473129611002520677145892778242279106724152108492680282436100305414987989, 13075867308307993713881388617739767319783540136821062304673039023416514479073968404704931053707431722417113432221377192698845939724954608884902350188774482318948356490572584570493016148272003096623369096838093349374805909370089074902960407209272664510740999775809485842810426515913298045223326669961556520541238694804400787951685561362702557941491071370737013429166029262325140106903158536926574942320103807698268441557280143112008091660020312242173901777414105294912109492658141997518018221759802285312329937197750464541705293605084821535959702107937728040393887374381496534531147546227981215469580847563998832887560]

C0 = ciphertext_row[0]
C1 = (-ciphertext_row[1]) % n
C2 = (-ciphertext_row[2]) % n
C3 = (-ciphertext_row[3]) % n

p = math.gcd(2*C2 - C1 - C3, n)
q = n // p

m_p = decrypt_scalar(C0 % p, C1 % p, C2 % p, C3 % p, p, e)
m_q = decrypt_scalar(C0 % q, C1 % q, C2 % q, C3 % q, q, e)

inv_q_p = inverse(q, p)
inv_p_q = inverse(p, q)
m = (m_p * q * inv_q_p + m_q * p * inv_p_q) % n

print(f"Flag: {long_to_bytes(m)}")
```
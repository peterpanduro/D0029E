# Lab 3 - RSA Public-Key Encryption and Signature

## Task 1: Calculate the private key

### Step 1: Given values

Let p, q, and e be three prime numbers. Let n = p\*q. We will use (e, n) as the public key.

    p = F7E75FDC469067FFDC4E847C51F452DF
    q = E85CED54AF57E53E092113E62F436F4F
    e = 0D88C3
    d = ? (private key)

### Step 2: Theory

$n = p \cdot q$

$t​ = (​p​ - 1) \cdot (​q​ - 1)$

$t = 329520679814142392965336341297134588638 * 308863399973593539130925275387286220622$
= E103ABD94892E3E74AFD724BF28E78348D52298BD687C44DEB3A81065A7981A4

$d = (e \cdot mod \cdot t)^{-t}$ (inversen av e $\cdot$ mod $\cdot$ t)
​
$d$ = 24212225287904763939160097464943268930139828978795606022583874367720623008491

### Step 3: Code

```c
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
  char *hex_str = BN_bn2hex(a);
  char *dec_str = BN_bn2dec(a);
  printf("%s \n hex: %s \n dec: %s\n", msg, hex_str, dec_str);
  OPENSSL_free(hex_str);
  OPENSSL_free(dec_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *t = BN_new();
  BIGNUM *d = BN_new();

  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  // n = p * q
  BN_mul(n, p, q, ctx);

  //t = (p-1) * (q-1)
  BIGNUM *p2 = BN_new();
  BIGNUM *q2 = BN_new();
  BIGNUM *z = BN_new();
  BN_hex2bn(&z, "1");
  BN_sub(p2, p, z);
  BN_sub(q2, q, z);
  BN_mul(t, p2, q2, ctx);

  // Inverse
  BN_mod_inverse(d, e, t, ctx);

  printBN("t = ", t);
  printBN("d = ", d);
}

```

### Step 4: Verify

```console
$ ./a.out
[…]
d =
 hex: 3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB
 dec: 24212225287904763939160097464943268930139828978795606022583874367720623008491
```

## Task 2: Encrypt a message

### Step 1: Given values

```console
 $ python -c ’print("A top secret!".encode("hex"))’
 4120746f702073656372657421
```

    n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
    e = 010001 (this hex value equals to decimal 65537)
    M = 4120746f702073656372657421
    d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D

### Step 2: Code

```c
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
  char *hex_str = BN_bn2hex(a);
  char *dec_str = BN_bn2dec(a);
  printf("%s \n hex: %s \n dec: %s\n", msg, hex_str, dec_str);
  OPENSSL_free(hex_str);
  OPENSSL_free(dec_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *e = BN_new();
  BIGNUM *M = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *res = BN_new();

  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e, "010001");
  BN_hex2bn(&M, "4120746f702073656372657421");

  BN_mod_exp(res, M, e, n, ctx);

  printBN("res=", res);
}
```

### Step 3: Result

```console
$ gcc decrypt.c -lcrypto
$ ./a.out
res=
 hex: 6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC
 dec: 50518525371929684556329211359721949099156057889496242376979402393388933577436
```

## Task 3: Decrypting a Message

### Step 1: Given values

    n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
    e = 010001 (this hex value equals to decimal 65537)
    M = 4120746f702073656372657421
    d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D

### Step 2: Code

```c
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
  char *hex_str = BN_bn2hex(a);
  char *dec_str = BN_bn2dec(a);
  printf("%s \n hex: %s \n dec: %s\n", msg, hex_str, dec_str);
  OPENSSL_free(hex_str);
  OPENSSL_free(dec_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *c = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *res = BN_new();

  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  BN_mod_exp(res, c, d, n, ctx);

  printBN("res=", res);
}
```

### Step 3: Result

```console
$ gcc decrypt.c -lcrypto
$ ./a.out
res=
 hex: 50617373776F72642069732064656573
 dec: 106844234083377704326275866149693777267
$ $ python -c 'print("50617373776F72642069732064656573".decode("hex"))'
Password is dees
```

## Task 4: Signing a Message

```
$ python -c 'print("I owe you $2000.".encode("hex"))'
49206f776520796f752024323030302e
$ python -c 'print("I owe you $3000.".encode("hex"))'
49206f776520796f752024333030302e
```

```c
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
  char *hex_str = BN_bn2hex(a);
  char *dec_str = BN_bn2dec(a);
  printf("%s \n hex: %s \n dec: %s\n", msg, hex_str, dec_str);
  OPENSSL_free(hex_str);
  OPENSSL_free(dec_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *c1 = BN_new();
  BIGNUM *c2 = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *res1 = BN_new();
  BIGNUM *res2 = BN_new();

  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&c1, "49206f776520796f752024323030302e");
  BN_hex2bn(&c2, "49206f776520796f752024333030302e");
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  BN_mod_exp(res1, c1, d, n, ctx);
  BN_mod_exp(res2, c2, d, n, ctx);

  printBN("c1 = ", res1);
  printBN("c2 = ", res2);
}
```

```console
$ gcc signing.c -lcrypto
$ ./a.out
c1 =
 hex: 55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB
 dec: 38737955862331189402498387291363292989447215164396465065684612292997465629899
c2 =
 hex: BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822
 dec: 85377692333201951919213855180904627562313128428164207106465609485406786574370
```

### Question 1: Please make a slight change to the message M, such as changing $2000 to $3000, and sign the modified message. Compare both signatures and describe what you observe

Just like a hased value the sign changes dramatically even if the message is almost identical.

## Task 5: Verifying a Signature

```console
$ python -c 'print("Launch a missile.".encode("hex"))'
4c61756e63682061206d697373696c652e
```

    M = 4c61756e63682061206d697373696c652e
    S1 = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
    S2 = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F
    e = 010001 (this hex value equals to decimal 65537)
    n = AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115

```c
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
  char *hex_str = BN_bn2hex(a);
  char *dec_str = BN_bn2dec(a);
  printf("%s \n hex: %s \n dec: %s\n", msg, hex_str, dec_str);
  OPENSSL_free(hex_str);
  OPENSSL_free(dec_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *M = BN_new();
  BIGNUM *S1 = BN_new();
  BIGNUM *S2 = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *res1 = BN_new();
  BIGNUM *res2 = BN_new();

  BN_hex2bn(&M, "4c61756e63682061206d697373696c652e");
  BN_hex2bn(&S1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
  BN_hex2bn(&S2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&e, "010001");

  BN_mod_exp(res1, S1, e, n, ctx);
  BN_mod_exp(res2, S2, e, n, ctx);

  printBN("res1 = ", res1);
  printBN("res2 = ", res2);
}
```

```console
$ gcc verify.c -lcrypto
$ a.out
res1 =
 hex: 4C61756E63682061206D697373696C652E
 dec: 25991004739255778713631969737248063907118
res2 =
 hex: 91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294
 dec: 65710982802337676312353566637294969595512391135201560281913984954792299643540
```

When the uncorrupted signature is used, the result is identical with the message. When just a byte is corrupted, the result is vastly different from the message.

## Task 6: Manually Verifying an X.509 Certificate

### Step 1: Get Certificates

```console
$ openssl s_client -connect www.google.com:443 -showcerts
```

This creates a long output including two certificates. These two certificates is copied into individual files names `c0.pem`and `c1.pem`.

### Step 2: Get n

```console
$ openssl x509 -in c1.pem -noout -modulus
Modulus=D018CF45D48BCDD39CE440EF7EB4DD69211BC9CF3C8E4C75B90F3119843D9E3C29EF500D10936F0580809F2AA0BD124B02E13D9F581624FE309F0B747755931D4BF74DE1928210F651AC0CC3B222940F346B981049E70B9D8339DD20C61C2DEFD1186165E7238320A82312FFD2247FD42FE7446A5B4DD75066B0AF9E426305FBE01CC46361AF9F6A33FF6297BD48D9D37C1467DC75DC2E69E8F86D7869D0B71005B8F131C23B24FD1A3374F823E0EC6B198A16C6E3CDA4CD0BDBB3A4596038883BAD1DB9C68CA7531BFCBCD9A4ABBCDD3C61D7931598EE81BD8FE264472040064ED7AC97E8B9C05912A1492523E4ED70342CA5B4637CF9A33D83D1CD6D24AC07
```

### Step 3: Get e

```console
$ openssl x509 -in c1.pem -noout -text
Certificate:
[…]
    Exponent: 65537 (0x10001)
[…]
```

### Step 4: Get signature from servers certificate

```console
$ openssl x509 -in c0.pem -text -noout
[…]
Signature Algorithm: sha256WithRSAEncryption
    c1:64:04:67:02:ff:7e:f5:93:c9:02:74:e1:53:ec:e1:8e:a6:
    d7:84:64:8a:b8:95:d8:f6:e8:9d:a7:86:b1:fa:d6:0a:60:f5:
    be:e7:b6:25:34:85:e0:23:55:52:7a:08:92:5b:33:bd:c3:cc:
    c2:77:b4:fb:b2:f5:10:8d:93:5a:3e:af:a2:16:ab:0c:92:2c:
    b3:d3:a1:9b:bc:ca:dd:3e:e9:f7:17:6d:3b:94:8b:50:38:1d:
    96:51:b6:0b:2b:e8:1f:5a:e7:50:f9:ad:e0:1f:f0:0e:4d:d3:
    15:34:38:85:26:9f:8f:58:51:22:d0:05:78:fc:d7:eb:77:62:
    e5:36:8e:68:13:ca:ac:7f:f9:f2:a7:91:fd:54:7d:12:03:d8:
    0e:3a:13:c8:f0:73:48:00:a6:5f:f5:df:bd:0c:70:f4:c9:90:
    bd:b7:6a:d8:ef:ce:d9:18:3b:99:a0:6d:f5:d8:69:5c:e0:e9:
    2f:a0:b1:77:0e:15:5e:15:5f:df:36:c6:9c:d3:c0:4b:0f:df:
    0c:d1:d9:d1:a3:b0:35:a9:19:2d:20:be:9f:87:4b:5e:da:34:
    cc:d5:b1:87:ca:e3:e7:c4:27:b5:16:19:ec:b5:a0:5a:d7:6e:
    91:22:a0:fe:a5:90:4e:b5:eb:23:bf:4e:94:1a:9e:e6:e2:93:
    e2:e2:ee:2f
```

c164046702ff7ef593c90274e153ece18ea6d784648ab895d8f6e89da786b1fad60a60f5bee7b6253485e02355527a08925b33bdc3ccc277b4fbb2f5108d935a3eafa216ab0c922cb3d3a19bbccadd3ee9f7176d3b948b50381d9651b60b2be81f5ae750f9ade01ff00e4dd315343885269f8f585122d00578fcd7eb7762e5368e6813caac7ff9f2a791fd547d1203d80e3a13c8f0734800a65ff5dfbd0c70f4c990bdb76ad8efced9183b99a06df5d8695ce0e92fa0b1770e155e155fdf36c69cd3c04b0fdf0cd1d9d1a3b035a9192d20be9f874b5eda34ccd5b187cae3e7c427b51619ecb5a05ad76e9122a0fea5904eb5eb23bf4e941a9ee6e293e2e2ee2f

### Step 5: Extract the body of the server’s certificate.

```console
$ openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout
$ sha256sum c0_body.bin
e1d8e1d34888654603b5e778f9fb9b3bc468b2f0e136f2d062222e45cbc0fd16  c0_body.bin
```

### Step 6: Verify the signature

```c
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
  char *hex_str = BN_bn2hex(a);
  char *dec_str = BN_bn2dec(a);
  printf("%s \n hex: %s \n dec: %s\n", msg, hex_str, dec_str);
  OPENSSL_free(hex_str);
  OPENSSL_free(dec_str);
}

int main() {
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *S = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *res = BN_new();

  BN_hex2bn(&S, "c164046702ff7ef593c90274e153ece18ea6d784648ab895d8f6e89da786b1fad60a60f5bee7b6253485e02355527a08925b33bdc3ccc277b4fbb2f5108d935a3eafa216ab0c922cb3d3a19bbccadd3ee9f7176d3b948b50381d9651b60b2be81f5ae750f9ade01ff00e4dd315343885269f8f585122d00578fcd7eb7762e5368e6813caac7ff9f2a791fd547d1203d80e3a13c8f0734800a65ff5dfbd0c70f4c990bdb76ad8efced9183b99a06df5d8695ce0e92fa0b1770e155e155fdf36c69cd3c04b0fdf0cd1d9d1a3b035a9192d20be9f874b5eda34ccd5b187cae3e7c427b51619ecb5a05ad76e9122a0fea5904eb5eb23bf4e941a9ee6e293e2e2ee2f");
  BN_hex2bn(&n, "00D018CF45D48BCDD39CE440EF7EB4DD69211BC9CF3C8E4C75B90F3119843D9E3C29EF500D10936F0580809F2AA0BD124B02E13D9F581624FE309F0B747755931D4BF74DE1928210F651AC0CC3B222940F346B981049E70B9D8339DD20C61C2DEFD1186165E7238320A82312FFD2247FD42FE7446A5B4DD75066B0AF9E426305FBE01CC46361AF9F6A33FF6297BD48D9D37C1467DC75DC2E69E8F86D7869D0B71005B8F131C23B24FD1A3374F823E0EC6B198A16C6E3CDA4CD0BDBB3A4596038883BAD1DB9C68CA7531BFCBCD9A4ABBCDD3C61D7931598EE81BD8FE264472040064ED7AC97E8B9C05912A1492523E4ED70342CA5B4637CF9A33D83D1CD6D24AC07");
  BN_hex2bn(&e, "010001");

  BN_mod_exp(res, S, e, n, ctx);

  printBN("res = ", res);
}
```

```console
$ gcc verify.c -lcrypto
$ a.out
res =
 hex: 01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D060960864801650304020105000420E1D8E1D34888654603B5E778F9FB9B3BC468B2F0E136F2D062222E45CBC0FD16
 dec: 986236757547332986472011617696226561292849812918563355472727826767720188564083584387121625107510786855734801053524719833194566624465665316622563244215340671405971599343902468620306327831715457360719532421388780770165778156818229863337344187575566725786793391480600129482653072861971002459947277805295727097226389568776499707662505334062639449916265137796823793276300221537201727072401742985542559596685092673521228140822200236743113743661549252453726123450722876929538747702356573783116197523966334991563351853851212597377279504828784772525628173047032585396779950988773165851268553877346295512077838778250624278
```

The last bytes matches the hash from step 5.

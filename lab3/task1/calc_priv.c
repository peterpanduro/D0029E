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

  //t = (p-1)*(q-1)
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

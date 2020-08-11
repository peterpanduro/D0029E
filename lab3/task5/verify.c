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

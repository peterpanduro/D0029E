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

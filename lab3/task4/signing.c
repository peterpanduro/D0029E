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

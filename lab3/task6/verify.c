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

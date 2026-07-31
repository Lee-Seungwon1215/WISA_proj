/* OpenSSL 3.5 ML-KEM/ML-DSA production-API functional smoke. */
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int kem_smoke(const char *algorithm)
{
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *enc_secret = NULL;
  unsigned char *dec_secret = NULL;
  size_t ciphertext_len = 0;
  size_t enc_secret_len = 0;
  size_t dec_secret_len = 0;
  int ok = 0;

  key = EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
  if (key == NULL)
  {
    goto done;
  }
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0 ||
      EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_len, NULL,
                           &enc_secret_len) <= 0)
  {
    goto done;
  }
  ciphertext = OPENSSL_malloc(ciphertext_len);
  enc_secret = OPENSSL_malloc(enc_secret_len);
  if (ciphertext == NULL || enc_secret == NULL ||
      EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, enc_secret,
                           &enc_secret_len) <= 0)
  {
    goto done;
  }

  EVP_PKEY_CTX_free(ctx);
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0 ||
      EVP_PKEY_decapsulate(ctx, NULL, &dec_secret_len, ciphertext,
                           ciphertext_len) <= 0)
  {
    goto done;
  }
  dec_secret = OPENSSL_malloc(dec_secret_len);
  if (dec_secret == NULL ||
      EVP_PKEY_decapsulate(ctx, dec_secret, &dec_secret_len, ciphertext,
                           ciphertext_len) <= 0 ||
      enc_secret_len != dec_secret_len ||
      memcmp(enc_secret, dec_secret, enc_secret_len) != 0)
  {
    goto done;
  }

  printf("%s ok ciphertext=%zu secret=%zu\n", algorithm, ciphertext_len,
         enc_secret_len);
  ok = 1;

done:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  OPENSSL_free(ciphertext);
  OPENSSL_free(enc_secret);
  OPENSSL_free(dec_secret);
  return ok;
}

static int signature_smoke(const char *algorithm)
{
  static const unsigned char message[] =
      "ctkat/openssl-3.5/production-api-smoke/v1";
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *ctx = NULL;
  unsigned char *signature = NULL;
  size_t signature_len = 0;
  int ok = 0;

  key = EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
  ctx = EVP_MD_CTX_new();
  if (key == NULL || ctx == NULL ||
      EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL) <= 0 ||
      EVP_DigestSign(ctx, NULL, &signature_len, message,
                     sizeof(message) - 1) <= 0)
  {
    goto done;
  }
  signature = OPENSSL_malloc(signature_len);
  if (signature == NULL ||
      EVP_DigestSign(ctx, signature, &signature_len, message,
                     sizeof(message) - 1) <= 0 ||
      EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL) <= 0 ||
      EVP_DigestVerify(ctx, signature, signature_len, message,
                       sizeof(message) - 1) <= 0)
  {
    goto done;
  }

  printf("%s ok signature=%zu\n", algorithm, signature_len);
  ok = 1;

done:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  OPENSSL_free(signature);
  return ok;
}

int main(void)
{
  static const char *kem_algorithms[] = {
      "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
  static const char *signature_algorithms[] = {
      "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
  size_t i;

  if (strncmp(OpenSSL_version(OPENSSL_VERSION), "OpenSSL 3.5.7 ", 14) != 0)
  {
    fprintf(stderr, "unexpected OpenSSL: %s\n",
            OpenSSL_version(OPENSSL_VERSION));
    return 1;
  }
  puts("OpenSSL 3.5.7 exact-release");

  for (i = 0; i < sizeof(kem_algorithms) / sizeof(kem_algorithms[0]); i++)
  {
    if (!kem_smoke(kem_algorithms[i]))
    {
      return 2;
    }
  }
  for (i = 0;
       i < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]); i++)
  {
    if (!signature_smoke(signature_algorithms[i]))
    {
      return 3;
    }
  }
  return 0;
}

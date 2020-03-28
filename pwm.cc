#include <cstdio>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <readpassphrase.h>


BIO *bio_err = NULL;

int main(const int argc, const char *argv[]) {
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    fprintf(stderr, "failed to initialise bio_err\n");
    exit(1);
  }

  printf("OK, that's it\n");
}

/**
 * Attempt to decrypt the contents of filename.
 *
 * buf should be large enough to hold the decrypted contents.
 * bufsiz is both an input parameter and an output parameter.
 *
 * If buf is too small or if buf is NULL, the required size
 * will be returned in bufsiz.
 */
int decrypt(const char *in_filename, char *buf, size_t *bufsiz) {
  static const char magic[] = "Salted__";
  char mbuf[sizeof magic - 1];
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];
  BIO *rbio = NULL;
  BIO *in = NULL;
  EVP_CIPHER_CTX *ctx = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    ERR_print_errors(bio_err);
    return -1;
  }

  if (in_filename == NULL) {
    fprintf(stderr, "NULL filenames not allowed.\n");
    return -1;
  }

  if (BIO_read_filename(in, in_filename) <= 0) {
    perror(in_filename);
    return -1;
  }

  if (readpassphrase("Master passphrase: ", key, sizeof(key), 0) == NULL) {
    perror("failed to read passphrase");
    return -1;
  }
  // TODO: explicit_bzero(key, sizeof(key)) asap

  return 0;
}

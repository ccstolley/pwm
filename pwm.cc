#include <cstdio>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <readpassphrase.h>

int decrypt(const char *in_filename, char *buf, int *bufsiz);

BIO *bio_err = NULL;

int main(const int argc, const char *argv[]) {
  char buf[65536];
  int bufsiz = sizeof buf;
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    fprintf(stderr, "failed to initialise bio_err\n");
    exit(1);
  }

  if (decrypt(argv[1], buf, &bufsiz) == 0) {
    printf("Shiz '%s'\n", buf);
  }
  printf("done\n");
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
int decrypt(const char *in_filename, char *buf, int *bufsiz) {
  static const char magic[] = "Salted__";
  char mbuf[sizeof magic - 1];
  char key[EVP_MAX_KEY_LENGTH];
  unsigned char dkey[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];

  BIO *in = NULL, *benc = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    ERR_print_errors(bio_err);
    return -1;
  }

  if (in_filename == NULL) {
    BIO_printf(bio_err, "NULL filenames not allowed.\n");
    return -1;
  }

  if (BIO_read_filename(in, in_filename) <= 0) {
    perror(in_filename);
    return -1;
  }

  if (BIO_read(in, mbuf, sizeof mbuf) != sizeof mbuf ||
      BIO_read(in, (unsigned char *)salt, sizeof salt) != sizeof salt) {
    BIO_printf(bio_err, "error reading input file\n");
    return -1;
  }

  if (std::memcmp(mbuf, magic, sizeof magic - 1)) {
    BIO_printf(bio_err, "bad magic number\n");
    return -1;
  }

  if (readpassphrase("Master passphrase: ", key, sizeof(key), 0) == NULL) {
    perror("failed to read passphrase");
    return -1;
  }

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt, (unsigned char *)key,
                     strlen(key), 1, dkey, iv) == 0) {
    ERR_print_errors(bio_err);
    perror("failed to derive key and iv");
    return -1;
  }
  explicit_bzero(key, sizeof(key));

  if ((benc = BIO_new(BIO_f_cipher())) == NULL) {
    ERR_print_errors(bio_err);
    return -1;
  }

  BIO_get_cipher_ctx(benc, &ctx);

  if (!EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, false)) {
    ERR_print_errors(bio_err);
    perror("failed to init cipher");
    return -1;
  }

  int inl = BIO_read(in, buf, *bufsiz);
  if (inl <= 0)
    return -1;

  printf("OK: '%s'\n", key);

  return 0;
}

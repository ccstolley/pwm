#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <readpassphrase.h>
#include <string>
#include <sstream>

bool decrypt(const char *in_filename, std::string &data);
std::string trim(const std::string &s);
struct ent {
  std::string name;
  std::string meta;
  std::string password;
};
BIO *bio_err = NULL;

int main(const int argc, const char *argv[]) {
  std::string data;
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    fprintf(stderr, "failed to initialise bio_err\n");
    exit(1);
  }

  if (decrypt(argv[1], data)) {
    printf("Shiz '%s'\n", data.c_str());
  }

  printf("done\n");
}

struct ent find(const std::string &needle, const std::string &haystack) {

  struct ent entry {};
  std::stringstream ss{haystack};

  return entry;
}

std::string trim(const std::string &s) {
  auto front = std::find_if_not(s.begin(), s.end(), std::isspace);
  if (front == s.begin())
    return s;
  return std::string(
      front,
      std::find_if_not(s.rbegin(), std::string::const_reverse_iterator(front),
                       std::isspace)
          .base());
}

/**
 * Decrypt the contents of filename and store it in data.
 */
bool decrypt(const char *in_filename, std::string &data) {
  static const char magic[] = "Salted__";
  char buf[255];
  char mbuf[sizeof magic - 1];
  char key[EVP_MAX_KEY_LENGTH];
  unsigned char dkey[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];
  bool status = false;

  BIO *in = NULL, *benc = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    goto end;
  }

  if (in_filename == NULL) {
    BIO_printf(bio_err, "NULL filenames not allowed.\n");
    goto end;
  }

  if (BIO_read_filename(in, in_filename) <= 0) {
    perror(in_filename);
    goto end;
  }

  if (BIO_read(in, mbuf, sizeof mbuf) != sizeof mbuf ||
      BIO_read(in, (unsigned char *)salt, sizeof salt) != sizeof salt) {
    BIO_printf(bio_err, "error reading input file\n");
    goto end;
  }

  if (std::memcmp(mbuf, magic, sizeof magic - 1)) {
    BIO_printf(bio_err, "bad magic number\n");
    goto end;
  }

  if (readpassphrase("Master passphrase: ", key, sizeof(key), 0) == NULL) {
    perror("failed to read passphrase");
    goto end;
  }

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt, (unsigned char *)key,
                     strlen(key), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }
  explicit_bzero(key, sizeof(key));

  if ((benc = BIO_new(BIO_f_cipher())) == NULL) {
    goto end;
  }

  BIO_get_cipher_ctx(benc, &ctx);

  if (!EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, false)) {
    perror("failed to init cipher");
    goto end;
  }

  in = BIO_push(benc, in);

  for (;;) {
    int inl = BIO_read(in, buf, sizeof buf);
    if (inl <= 0) {
      break;
    }
    data.append(buf, inl);
  }

  status = true;

end:
  ERR_print_errors(bio_err);
  BIO_free_all(in);
  return status;
}

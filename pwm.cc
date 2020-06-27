#include "pwm.h"

static const char MAGIC[] = "Salted__";
BIO *bio_err = NULL;

void bail(const std::string &msg) {
  fprintf(stderr, "%s\n", msg.c_str());
  exit(1);
}

#ifndef TESTING
static const char STORE_PATH[] =
    "/home/stolley//mystuff/personal/pwm/stolley.txt.enc";

int main(const int argc, const char *argv[]) {
  std::string data;
  std::string key;
  struct ent entry;
  bool update = false;

  if (strcmp("pwmupdate", basename(argv[0])) == 0) {
    update = true;
  }
  if (!update && argc < 2) {
    bail("Specify a search string.");
  }

  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    bail("failed to initialise bio_err");
  }

  key = readpass();
  if (decrypt(std::string(STORE_PATH), key, &data)) {
    if (update) {
      const char *pwm_tmp_val = getenv("PWM_TMP");
      std::string tmpfile;
      if (pwm_tmp_val == nullptr) {
        tmpfile = STORE_PATH;
        tmpfile += ".tmp";
      } else {
        tmpfile = pwm_tmp_val;
      }
      if (!dump_to_file(data, tmpfile)) {
        bail("failed to write temp file.");
      }
      std::string cmd("vi -S -c 'set recdir= backup=' ");
      cmd += tmpfile;
      if (system(cmd.c_str()) != 0) {
        bail("problem with system()");
      }
      save_backup(STORE_PATH);
      if (!encrypt(STORE_PATH, key, readfile(tmpfile))) {
        bail("re-encrypt failed! backup saved.");
      }
      explicit_bzero(&key[0], key.size());
      if (!wipefile(tmpfile)) {
        bail("failed to wipe file.");
      }
    } else {
      explicit_bzero(&key[0], key.size());
      if (find(argv[1], data, &entry)) {
        fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
        printf("%s\n", entry.password.c_str());
        return 0;
      }
      fprintf(stderr, "Not found.\n");
    }
  } else {
    fprintf(stderr, "Decrypt failed\n");
  }
  return 1;
}
#endif // TESTING

bool save_backup(const char *filename) {
  std::string bak(filename);
  bak += ".bak";
  return std::rename(filename, bak.c_str()) == 0;
}

std::string readfile(const std::string &filename) {
  std::ifstream in(filename, std::ios::binary | std::ios::ate);
  auto sz = in.tellg();
  in.seekg(0);
  std::string dat(sz, '\0');
  in.read(&dat[0], dat.size());
  if (in.good() && in.gcount() == sz) {
    in.close();
    return dat;
  }
  bail("Failed to read file");
  return nullptr;
}

bool wipefile(const std::string &filename) {
  char buf[64];
  std::ifstream::pos_type sz = 0;
  {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    sz = in.tellg();
  }
  std::ofstream out(filename, std::ios::binary);
  while (sz > out.tellp()) {
    arc4random_buf(buf, sizeof(buf));
    out.write(buf, sizeof(buf));
  }
  out.flush();
  if (!out.good()) {
    return false;
  }
  out.close();
  std::remove(filename.c_str());
  return true;
}

bool dump_to_file(const std::string &data, const std::string &filename) {
  umask(077); // rw by owner only

  std::ofstream out(filename);
  if (!out) {
    bail("Unable to create temp file.");
  }
  out.write(data.c_str(), sizeof(char) * data.size());
  return out.good();
}

bool find(const std::string &needle, const std::string &haystack,
          struct ent *entry) {
  std::stringstream linestream{haystack};
  std::stringstream costream{};
  int i = 0;

  for (std::string line; std::getline(linestream, line); i++) {
    if (needle != line.substr(0, needle.size())) {
      continue;
    }
    auto fields = split(line, ":");
    if (fields.size() < 2) {
      fprintf(stderr, "warning: missing data on line %d\n", i);
      continue;
    }
    entry->name = fields[0];
    auto data = split(fields[1], " ");
    if (data.size() == 1) {
      entry->password = data[0];
    } else {
      entry->meta = data[0]; // typically username
      entry->password = data[data.size() - 1];
    }
    return true;
  }
  return false;
}

std::vector<std::string> split(const std::string &s,
                               const std::string &delimiter) {
  size_t start = 0;
  size_t end = 0;
  std::string token;
  std::vector<std::string> rv;
  while ((end = s.find(delimiter, start)) != std::string::npos) {
    token = trim(s.substr(start, end - start));
    if (!token.empty()) {
      rv.push_back(trim(token));
    }
    start = end + delimiter.size();
  }
  if (start < s.size()) {
    token = trim(s.substr(start));
    if (!token.empty()) {
      rv.push_back(token);
    }
  }
  return rv;
}

std::string trim(const std::string &s) {
  auto front = std::find_if_not(
      s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); });
  if (front == s.end()) {
    return "";
  }
  return std::string(
      front,
      std::find_if_not(s.rbegin(), std::string::const_reverse_iterator(front),
                       [](unsigned char c) { return std::isspace(c); })
          .base());
}

std::string readpass() {
  std::string key(EVP_MAX_KEY_LENGTH, '\0');
  if (readpassphrase("passphrase: ", &key[0], key.size(), 0) == NULL) {
    bail("failed to read passphrase");
  }
  return key;
}

/**
 * Decrypt the contents of filename and store it in data.
 */
bool decrypt(const std::string &in_filename, const std::string &key,
             std::string *data) {
  char buf[255];
  char mbuf[sizeof MAGIC - 1];
  unsigned char dkey[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];

  BIO *in = NULL;
  BIO *benc = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    goto end;
  }

  if (in_filename.empty()) {
    BIO_printf(bio_err, "NULL filenames not allowed.\n");
    goto end;
  }

  if (BIO_read_filename(in, in_filename.c_str()) <= 0) {
    perror(in_filename.c_str());
    goto end;
  }

  if (BIO_read(in, mbuf, sizeof mbuf) != sizeof mbuf ||
      BIO_read(in, reinterpret_cast<unsigned char *>(salt), sizeof salt) !=
          sizeof salt) {
    BIO_printf(bio_err, "error reading input file\n");
    goto end;
  }

  if (std::memcmp(mbuf, MAGIC, sizeof MAGIC - 1) != 0) {
    BIO_printf(bio_err, "bad magic number\n");
    goto end;
  }

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<const unsigned char *>(key.c_str()),
                     strlen(key.c_str()), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }

  if ((benc = BIO_new(BIO_f_cipher())) == NULL) {
    goto end;
  }

  BIO_get_cipher_ctx(benc, &ctx);

  if (EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, 0) != 1) {
    perror("failed to init cipher");
    goto end;
  }

  in = BIO_push(benc, in);

  for (;;) {
    int inl = BIO_read(in, buf, sizeof buf);
    if (ERR_get_error() != 0) {
      goto end;
    } else if (inl <= 0) {
      break;
    }
    data->append(buf, inl);
  }

  BIO_free_all(in);
  return true;

end:
  ERR_print_errors(bio_err);
  BIO_free_all(in);
  return false;
}

/**
 * Encrypt the contents of data and store it in filename.
 */
bool encrypt(const std::string &out_filename, const std::string &key,
             const std::string &data) {
  unsigned char dkey[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];

  BIO *out = NULL;
  BIO *benc = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  out = BIO_new(BIO_s_file());
  if (out == NULL) {
    goto end;
  }

  if (out_filename.empty()) {
    BIO_printf(bio_err, "NULL filenames not allowed.\n");
    goto end;
  }

  if (BIO_write_filename(out, const_cast<char *>(out_filename.c_str())) <= 0) {
    perror(out_filename.c_str());
    goto end;
  }

  arc4random_buf(salt, sizeof(salt));

  if (BIO_write(out, MAGIC, sizeof MAGIC - 1) != sizeof MAGIC - 1 ||
      BIO_write(out, reinterpret_cast<unsigned char *>(salt), sizeof salt) !=
          sizeof salt) {
    BIO_printf(bio_err, "error writing output file\n");
    goto end;
  }

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<const unsigned char *>(key.c_str()),
                     strlen(key.c_str()), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }

  if ((benc = BIO_new(BIO_f_cipher())) == NULL) {
    goto end;
  }

  BIO_get_cipher_ctx(benc, &ctx);

  if (EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, 1) != 1) {
    perror("failed to init cipher");
    goto end;
  }

  out = BIO_push(benc, out);

  if (BIO_write(out, data.c_str(), data.size()) !=
          static_cast<int>(data.size()) ||
      ERR_get_error() != 0) {
    perror("failed to write data to BIO");
    goto end;
  }
  if (BIO_flush(out) != 1) {
    perror("failed to flush BIO");
    goto end;
  }

  BIO_free_all(out);
  return true;

end:
  ERR_print_errors(bio_err);
  BIO_free_all(out);
  return false;
}

#include "pwm.h"

static const char MAGIC[] = "Salted__";
BIO *bio_err = NULL;

void bail(const std::string &msg) {
  fprintf(stderr, "%s\n", msg.c_str());
  exit(1);
}

#ifndef TESTING
static const char DEFAULT_STORE_PATH[] =
    "/home/stolley/mystuff/personal/pwm/stolley.txt.enc";

int main(const int argc, const char *argv[]) {
  std::string data;
  std::string key;
  std::string store_path(DEFAULT_STORE_PATH);
  struct ent entry;
  bool update = false;

  if(const char* env_store = std::getenv("PWM_STORE")) {
    store_path = env_store;
  }
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
  if (decrypt(readfile(store_path), key, &data)) {
    if (update) {
      std::string tmpstore;
      if (const char *env_tmp = std::getenv("PWM_TMP")) {
        tmpstore = env_tmp;
      } else {
        tmpstore = store_path;
        tmpstore += ".tmp";
      }
      if (!dump_to_file(data, tmpstore)) {
        bail("failed to write temp file.");
      }
      data.clear();
      std::string cmd("vi -S -c 'set recdir= backup=' ");
      cmd += tmpstore;
      if (system(cmd.c_str()) != 0) {
        bail("problem with system()");
      }
      save_backup(store_path);
      if (!encrypt(readfile(tmpstore), key, &data)) {
        bail("re-encrypt failed! backup saved.");
      }
      explicit_bzero(&key[0], key.size());
      if (!wipefile(tmpstore)) {
        bail("failed to wipe file.");
      }
      if (!dump_to_file(data, store_path)) {
        bail("failed to write new store.");
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

bool save_backup(const std::string &filename) {
  std::string bak(filename);
  bak += ".bak";
  return std::rename(filename.c_str(), bak.c_str()) == 0;
}

std::string readfile(const std::string &filename) {
  std::ifstream in(filename, std::ios::binary | std::ios::ate);
  if (!in) {
    bail("failed to open file");
  }
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
 * Decrypt ciphertext with key and store it in plaintext.
 */
bool decrypt(const std::string &ciphertext, const std::string &key,
             std::string *plaintext) {
  unsigned char dkey[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];
  int sz = 0;
  const int hdrsz = sizeof(MAGIC) + sizeof(salt) - 1;
  std::string s(ciphertext.size(), '\0');

  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    goto end;
  }

  if (ciphertext.substr(0, strlen(MAGIC)) != std::string(MAGIC)) {
    perror("invalid magic string");
    goto end;
  }
  ciphertext.copy(reinterpret_cast<char *>(salt), sizeof(salt),
                  sizeof(MAGIC) - 1);

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<const unsigned char *>(key.c_str()),
                     strlen(key.c_str()), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }

  if (EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, 0) != 1) {
    perror("failed to init cipher");
    goto end;
  }

  sz = static_cast<int>(s.size());
  if (EVP_CipherUpdate(
          ctx, reinterpret_cast<unsigned char *>(&s[0]), &sz,
          reinterpret_cast<const unsigned char *>(&ciphertext[hdrsz]),
          static_cast<int>(ciphertext.size() - hdrsz)) != 1) {
    perror("CipherUpdate() failed");
    goto end;
  }

  plaintext->append(s, 0, sz);

  if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(&s[0]), &sz) !=
      1) {
    perror("CipherFinal() failed");
    goto end;
  }

  plaintext->append(s, 0, sz);

  EVP_CIPHER_CTX_free(ctx);
  return true;

end:
  EVP_CIPHER_CTX_free(ctx);
  return false;
}

/**
 * Encrypt plaintext with key and store it in ciphertext.
 */
bool encrypt(const std::string &plaintext, const std::string &key,
             std::string *ciphertext) {
  unsigned char dkey[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];
  int sz = 0;
  std::string s(plaintext.size() + EVP_MAX_IV_LENGTH, '\0');

  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    goto end;
  }

  arc4random_buf(salt, sizeof(salt));

  ciphertext->append(MAGIC);
  ciphertext->append(reinterpret_cast<const char *>(salt), sizeof(salt));

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<const unsigned char *>(key.c_str()),
                     strlen(key.c_str()), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }

  if (EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, 1) != 1) {
    perror("failed to init cipher");
    goto end;
  }

  sz = static_cast<int>(s.size());
  if (EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(&s[0]), &sz,
                       reinterpret_cast<const unsigned char *>(&plaintext[0]),
                       static_cast<int>(plaintext.size())) != 1) {
    perror("CipherUpdate() failed");
    goto end;
  }

  ciphertext->append(s, 0, sz);

  if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(&s[0]), &sz) !=
      1) {
    perror("CipherFinal() failed");
    goto end;
  }

  ciphertext->append(s, 0, sz);

  EVP_CIPHER_CTX_free(ctx);
  return true;

end:
  EVP_CIPHER_CTX_free(ctx);
  return false;
}

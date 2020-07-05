#include "pwm.h"

static const char MAGIC[] = "Salted__";

[[noreturn]] static void bail(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}

#ifndef TESTING
static BIO *bio_err = nullptr;
static const char DEFAULT_STORE_PATH[] =
    "/home/stolley/mystuff/personal/pwm/stolley.txt.enc";

int main(int argc, char **argv) {
  std::string data;
  std::string key;
  struct ent entry;
  bool update_flag = false;
  bool edit_flag = false;
  int ch;

  while ((ch = getopt(argc, argv, "eu:")) != -1) {
    switch (ch) {
    case 'u':
      update_flag = true;
      entry.name = optarg;
      break;
    case 'e':
      edit_flag = true;
      break;
    default:
      bail("usage: %s [-e | -u name [meta]] [pattern]", argv[0]);
    }
  }
  argc -= optind;
  argv += optind;

  if (update_flag && edit_flag) {
    bail("-u and -e can't be combined");
  }

  if (!edit_flag && !update_flag && argc == 0) {
    bail("must specify a search string.");
  }

  std::string store_path(DEFAULT_STORE_PATH);
  if (const char *env_store = std::getenv("PWM_STORE")) {
    store_path = env_store;
  }

  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    bail("failed to initialise bio_err");
  }

  key = readpass();
  if (decrypt(readfile(store_path), key, &data)) {
    if (edit_flag) {
      edit(data, key, store_path);
    } else if (update_flag) {
      for (int i = 0; i < argc; i++) {
        if (i > 0) {
          entry.meta += " ";
        }
        entry.meta += argv[i]; // typically username
      }
      entry.password = random_str(15);
      std::string newdata;
      if (!update(data, entry, newdata)) {
        bail("update failed.");
      }
      data.clear();

      save_backup(store_path);
      if (!encrypt(newdata, key, &data)) {
        bail("re-encrypt failed! backup saved.");
      }
      if (!dump_to_file(data, store_path)) {
        bail("failed to write updated store.");
      }
      fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
      printf("%s\n", entry.password.c_str());
      return 0;
    } else {
      explicit_bzero(&key[0], key.size());
      if (find(argv[0], data, &entry)) {
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

bool edit(std::string &data, const std::string &key,
          const std::string &store_path) {
  std::string tmpstore;
  if (const char *env_tmp = std::getenv("PWM_TMP")) {
    tmpstore = env_tmp;
  } else {
    tmpstore = store_path + ".tmp";
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
  if (!wipefile(tmpstore)) {
    bail("failed to wipe file.");
  }
  if (!dump_to_file(data, store_path)) {
    bail("failed to write new store.");
  }
  return true;
}

bool update(const std::string &data, const struct ent &newent,
            std::string &revised) {
  std::stringstream linestream{data};
  std::stringstream editstream{};
  bool found = false;

  for (std::string line; std::getline(linestream, line);) {
    struct ent entry;
    if (newent.name == line.substr(0, newent.name.size()) &&
        parse_entry(line, &entry)) {
      fprintf(stderr, "[old] %s: %s\n", entry.name.c_str(),
              entry.password.c_str());
      if (found) {
        fprintf(stderr, "error: multiple matches for '%s' found.\n",
                newent.name.c_str());
        return false;
      }
      found = true;
      if (!newent.meta.empty()) {
        entry.meta = newent.meta;
      }
      entry.password = newent.password;
      std::string s{dump_entry(entry)};
      editstream.write(s.c_str(), s.size());
      continue;
    }
    editstream.write((line + "\n").c_str(), line.size() + 1);
  }
  if (!found) {
    // add
    std::string s{dump_entry(newent)};
    editstream.write(s.c_str(), s.size());
  }
  revised = editstream.str();
  return true;
}

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
  std::string dat(static_cast<unsigned long>(sz), '\0');
  in.read(&dat[0], static_cast<long>(dat.size()));
  if (in.good() && in.gcount() == sz) {
    in.close();
    return dat;
  }
  bail("Failed to read file");
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
  out.write(data.c_str(), static_cast<long>(sizeof(char) * data.size()));
  return out.good();
}

bool find(const std::string &needle, const std::string &haystack,
          struct ent *entry) {
  std::stringstream linestream{haystack};
  int i = 0;

  for (std::string line; std::getline(linestream, line); i++) {
    if (needle != line.substr(0, needle.size())) {
      continue;
    }
    if (parse_entry(line, entry)) {
      return true;
    }
    fprintf(stderr, "warning: missing data on line %d\n", i);
  }
  return false;
}

bool parse_entry(const std::string &line, struct ent *entry) {
  auto fields = split(line, ":");
  if (fields.size() < 2) {
    fprintf(stderr, "malformed entry '%s'", line.c_str());
    return false;
  }
  entry->name = fields[0];
  auto data = split(fields[1], " ");
  if (data.size() == 1) {
    entry->password = data[0];
  } else {
    entry->meta.clear();
    for (size_t i = 0; i < data.size() - 1; i++) {
      if (i > 0) {
        entry->meta += " ";
      }
      entry->meta += data[i]; // typically username
    }
    entry->password = data[data.size() - 1];
  }
  return true;
}

std::string dump_entry(const struct ent &entry) {
  std::string s(entry.name);
  return s + ": " + (entry.meta.empty() ? "" : entry.meta + " ") +
         entry.password + "\n";
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
                     static_cast<int>(strlen(key.c_str())), 1, dkey, iv) == 0) {
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

  plaintext->append(s, 0, static_cast<unsigned long>(sz));

  if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(&s[0]), &sz) !=
      1) {
    perror("CipherFinal() failed");
    goto end;
  }

  plaintext->append(s, 0, static_cast<unsigned long>(sz));

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
                     static_cast<int>(strlen(key.c_str())), 1, dkey, iv) == 0) {
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

  ciphertext->append(s, 0, static_cast<unsigned long>(sz));

  if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(&s[0]), &sz) !=
      1) {
    perror("CipherFinal() failed");
    goto end;
  }

  ciphertext->append(s, 0, static_cast<unsigned long>(sz));

  EVP_CIPHER_CTX_free(ctx);
  return true;

end:
  EVP_CIPHER_CTX_free(ctx);
  return false;
}

std::string random_str(size_t sz) {
  std::string s;
  s.reserve(sz);
  char buf[64];
  while (s.size() < sz) {
    arc4random_buf(buf, sizeof(buf));
    for (char c : buf) {
      if (s.size() == sz) {
        break;
      }
      if (std::isalnum(c) || (c && std::strchr(",.-$%", c))) {
        s.push_back(c);
      }
    }
  }
  return s;
}

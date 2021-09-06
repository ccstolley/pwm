#include "pwm.h"

inline constexpr std::string_view MAGIC{"Salted__"};

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
static std::string default_store_path() {
  const char *home = std::getenv("HOME");
  if (home == nullptr) {
    home = "";
  }
  std::string path{home};
  path += "/.pwmstore";
  return path;
}

[[noreturn]] static void usage() {
  bail("usage: pwm [-d | -u name [meta]] | -r name | [pattern]");
}

[[nodiscard]] static bool is_read_only() { return std::getenv("PWM_READONLY"); }

int main(int argc, char **argv) {
  std::string data;
  std::string key;
  struct ent entry;
  bool update_flag = false;
  bool remove_flag = false;
  bool dump_flag = false;
  int ch;

  while ((ch = getopt(argc, argv, "du:r:")) != -1) {
    switch (ch) {
    case 'r':
      remove_flag = true;
      entry.name = optarg;
      break;
    case 'u':
      update_flag = true;
      entry.name = optarg;
      break;
    case 'd':
      dump_flag = true;
      break;
    default:
      usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (is_read_only() && (remove_flag || update_flag)) {
    bail("Write operations are disabled.");
  }

  if ((update_flag ? 1 : 0) + (dump_flag ? 1 : 0) + (remove_flag ? 1 : 0) > 1) {
    fprintf(stderr, "pwm: -u -d and -r can't be combined\n");
    usage();
  }

  if (!remove_flag && !dump_flag && !update_flag && argc == 0) {
    fprintf(stderr, "pwm: must specify a search string.\n");
    usage();
  }

  if (update_flag || remove_flag) {
    if (pledge("stdio tty fattr cpath rpath wpath", NULL) != 0) {
      bail("pledge(2) failed at %d.", __LINE__);
    }
  } else {
    if (pledge("stdio tty rpath fattr", NULL) != 0) {
      bail("pledge(2) failed at %d.", __LINE__);
    }
  }

  std::string store_path;
  if (const char *env_store = std::getenv("PWM_STORE")) {
    store_path = env_store;
  } else {
    store_path = default_store_path();
  }

  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    bail("failed to initialise bio_err");
  }

  auto ciphertext = read_file(store_path);
  if (ciphertext.empty()) {
    if (!update_flag) {
      bail("missing or corrupt store: %s", store_path.c_str());
    }
    fprintf(stderr, "Initializing new password store.\n");
    key = readpass("set root passphrase: ");
    if (key != readpass(" confirm passphrase: ")) {
      bail("passwords didn't match.");
    }
  } else {
    check_perms(store_path);
    key = readpass("passphrase: ");
    if (!decrypt(ciphertext, key, data)) {
      fprintf(stderr, "Decrypt failed\n");
      return 1;
    }
  }
  if (dump_flag) {
    explicit_bzero(&key[0], key.size());
    dump(data);
  } else if (update_flag || remove_flag) {
    for (int i = 0; i < argc; i++) {
      if (i > 0) {
        entry.meta += " ";
      }
      entry.meta += argv[i]; // typically username
    }
    entry.password = random_str(15);
    std::string newdata;
    if (!update(data, entry, newdata, remove_flag)) {
      bail("%s failed.", remove_flag ? "remove" : "update");
    }
    data.clear();

    save_backup(store_path);
    if (!encrypt(newdata, key, data)) {
      bail("re-encrypt failed! backup saved.");
    }
    explicit_bzero(&key[0], key.size());
    if (!dump_to_file(data, store_path)) {
      bail("failed to write updated store.");
    }
    if (update_flag) {
      fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
      printf("%s\n", entry.password.c_str());
    } else {
      fprintf(stderr, "\n%s: removed\n", entry.name.c_str());
    }
  } else {
    explicit_bzero(&key[0], key.size());
    if (find(argv[0], data, entry)) {
      fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
      printf("%s\n", entry.password.c_str());
    } else {
      fprintf(stderr, "Not found.\n");
    }
  }
  return 0;
}
#endif // TESTING

bool dump(const std::string &data) {
  std::stringstream linestream{data};
  for (std::string line; std::getline(linestream, line);) {
    fprintf(stderr, "%s\n", line.c_str());
  }
  return true;
}

bool update(const std::string &data, const struct ent &newent,
            std::string &revised, bool remove) {
  std::stringstream linestream{data};
  std::stringstream editstream{};
  bool found = false;
  bool exact = false;

  for (std::string line; std::getline(linestream, line);) {
    struct ent entry;
    if (newent.name == line.substr(0, newent.name.size()) &&
        parse_entry(line, entry)) {
      if (found) {
        if (!exact) {
          fprintf(stderr, "error: '%s' also matches '%s'.\n",
                  entry.name.c_str(), newent.name.c_str());
          return false;
        }
      } else {
        fprintf(stderr, "[old] %s: %s\n", entry.name.c_str(),
                entry.password.c_str());
        exact = newent.name == entry.name;
        found = true;
        if (remove) {
          continue;
        }
        if (!newent.meta.empty()) {
          entry.meta = newent.meta;
        }
        entry.password = newent.password;
        std::string s{dump_entry(entry)};
        editstream.write(s.c_str(), s.size());
        continue;
      }
    }
    editstream.write((line + "\n").c_str(), line.size() + 1);
  }
  if (!found) {
    if (remove) {
      return false;
    }
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

void check_perms(const std::string &path) {
  struct stat sb;
  if (stat(path.c_str(), &sb) == -1) {
    bail("no such file: %s", path.c_str());
  }
  if ((sb.st_mode & S_IRWXG) || (sb.st_mode & S_IRWXO)) {
    if (0 != chmod(path.c_str(), S_IRUSR|S_IWUSR)) {
      bail("%s\n   must be read/writeable by owner only.", path.c_str());
    }
    chmod((path + ".bak").c_str(), S_IRUSR|S_IWUSR); // best effort
  }
}

std::string read_file(const std::string &filename) {
  std::ifstream in(filename, std::ios::binary | std::ios::ate);
  if (!in) {
    return "";
  }
  auto sz = in.tellg();
  in.seekg(0);
  std::string dat(sz, '\0');
  in.read(&dat[0], static_cast<long>(dat.size()));
  if (in.good() && in.gcount() == sz) {
    in.close();
    return dat;
  }
  bail("Failed to read file");
}

std::string sort_data(const std::string &data) {
  std::vector<std::string> datav;
  std::stringstream linestream{data};

  for (std::string line; std::getline(linestream, line);) {
    datav.push_back(line);
  }
  std::sort(datav.begin(), datav.end(),
            [](const std::string &a, const std::string &b) {
              return a.substr(0, a.find(':')) < b.substr(0, b.find(':'));
            });

  std::ostringstream outs;
  std::copy(datav.begin(), datav.end(),
            std::ostream_iterator<std::string>(outs, "\n"));
  return outs.str();
}

bool dump_to_file(const std::string &data, const std::string &filename) {
  umask(077); // rw by owner only

  std::ofstream out(filename);
  if (!out) {
    return false;
  }
  out.write(data.c_str(), static_cast<long>(sizeof(char) * data.size()));
  return out.good();
}

bool find(const std::string &needle, const std::string &haystack,
          struct ent &entry) {
  std::stringstream linestream{haystack};
  int i = 0;
  bool found = false;
  bool exact = false;
  struct ent match;

  for (std::string line; std::getline(linestream, line); i++) {
    if (needle != line.substr(0, needle.size()) || !parse_entry(line, match)) {
      continue;
    }
    if (found) {
      if (!exact) {
        fprintf(stderr, "error: '%s' also matches '%s'.\n", match.name.c_str(),
                needle.c_str());
        return false;
      }
    } else {
      exact = needle == match.name;
      found = true;
      entry = match;
    }
  }
  return found;
}

bool parse_entry(const std::string &line, struct ent &entry) {
  auto fields = split(line, ":");
  if (fields.size() < 2) {
    fprintf(stderr, "malformed entry '%s'\n", line.c_str());
    return false;
  }
  entry.name = fields[0];
  auto data = split(fields[1], " ");
  if (data.size() == 1) {
    entry.password = data[0];
  } else {
    entry.meta.clear();
    for (size_t i = 0; i < data.size() - 1; i++) {
      if (i > 0) {
        entry.meta += " ";
      }
      entry.meta += data[i]; // typically username
    }
    entry.password = data[data.size() - 1];
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

std::string readpass(const std::string &prompt) {
  char key[EVP_MAX_KEY_LENGTH] = {0};
  if (readpassphrase(prompt.c_str(), key, sizeof(key), 0) == NULL) {
    bail("failed to read passphrase");
  }
  return {key};
}

/**
 * Decrypt ciphertext with key and store it in plaintext.
 */
bool decrypt(const std::string &ciphertext, const std::string &key,
             std::string &plaintext) {
  unsigned char dkey[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char salt[PKCS5_SALT_LEN];
  int sz = 0;
  const int hdrsz = MAGIC.size() + sizeof(salt);
  std::string s(ciphertext.size(), '\0');

  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    goto end;
  }

  if (ciphertext.substr(0, MAGIC.size()) != MAGIC) {
    perror("invalid magic string");
    goto end;
  }
  ciphertext.copy(reinterpret_cast<char *>(salt), sizeof(salt), MAGIC.size());

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<const unsigned char *>(key.data()),
                     key.size(), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }

  if (EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, 0) != 1) {
    perror("failed to init cipher");
    goto end;
  }

  sz = s.size();
  if (EVP_CipherUpdate(
          ctx, reinterpret_cast<unsigned char *>(s.data()), &sz,
          reinterpret_cast<const unsigned char *>(&(ciphertext.data()[hdrsz])),
          ciphertext.size() - hdrsz) != 1) {
    perror("CipherUpdate() failed");
    goto end;
  }

  plaintext.append(s, 0, sz);

  if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(s.data()),
                         &sz) != 1) {
    perror("CipherFinal() failed");
    goto end;
  }

  plaintext.append(s, 0, sz);
  plaintext = sort_data(plaintext);

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
             std::string &ciphertext) {
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

  ciphertext.append(MAGIC);
  ciphertext.append(reinterpret_cast<const char *>(salt), sizeof(salt));

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<const unsigned char *>(key.data()),
                     key.size(), 1, dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }

  if (EVP_CipherInit_ex(ctx, cipher, NULL, dkey, iv, 1) != 1) {
    perror("failed to init cipher");
    goto end;
  }

  sz = s.size();
  if (EVP_CipherUpdate(
          ctx, reinterpret_cast<unsigned char *>(s.data()), &sz,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          plaintext.size()) != 1) {
    perror("CipherUpdate() failed");
    goto end;
  }

  ciphertext.append(s, 0, sz);

  if (EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(s.data()),
                         &sz) != 1) {
    perror("CipherFinal() failed");
    goto end;
  }

  ciphertext.append(s, 0, sz);

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
      if (std::isalnum(c) || (c && std::strchr(",.-$%", c) != nullptr)) {
        s.push_back(c);
      }
    }
  }
  return s;
}

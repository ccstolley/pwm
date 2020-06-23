#include "pwm.h"

const char *STORE_PATH = "/home/stolley//mystuff/personal/pwm/stolley.txt.enc";
BIO *bio_err = NULL;

void bail(std::string msg) {
  fprintf(stderr, "%s\n", msg.c_str());
  exit(1);
}

#ifndef TESTING
int main(const int argc, const char *argv[]) {
  std::string data;
  struct ent entry;
  bool update = false;

  if (strcmp("pwmupdate", argv[0]) == 0) {
    update = true;
  }
  if (!update && argc < 2) {
    bail("Specify a search string.");
  }

  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  if (bio_err == NULL) {
    bail("failed to initialise bio_err");
  }

  if (decrypt(STORE_PATH, &data)) {
    if (update) {
      // TODO: dump data to tmp file
      // TODO: fork/exec vi to open tmp file
      // TODO: wait on vi pid
      // TODO: save old store file to .bak, encrypt tmp file and replace old
      // store file.
      pid_t pid = 0;
      if (pid == -1) {

      } else {
      }
    } else {
      if (find(argv[1], data, &entry)) {
        fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
        printf("%s\n", entry.password.c_str());
        return 0;
      } else {
        fprintf(stderr, "Not found.\n");
      }
    }
  } else {
    fprintf(stderr, "Decrypt failed\n");
  }
  return 1;
}
#endif // TESTING

bool dump_to_file(const std::string &data, const std::string &filename) {
  umask(077); // rw by owner only

  std::ofstream out(filename);
  if (!out) {
    bail("Unable to write data to temp file.");
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

/**
 * Decrypt the contents of filename and store it in data.
 */
bool decrypt(const char *in_filename, std::string *data) {
  static const char magic[] = "Salted__";
  char buf[255];
  char mbuf[sizeof magic - 1];
  char key[EVP_MAX_KEY_LENGTH];
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

  if (in_filename == NULL) {
    BIO_printf(bio_err, "NULL filenames not allowed.\n");
    goto end;
  }

  if (BIO_read_filename(in, in_filename) <= 0) {
    perror(in_filename);
    goto end;
  }

  if (BIO_read(in, mbuf, sizeof mbuf) != sizeof mbuf ||
      BIO_read(in, reinterpret_cast<unsigned char *>(salt), sizeof salt) !=
          sizeof salt) {
    BIO_printf(bio_err, "error reading input file\n");
    goto end;
  }

  if (std::memcmp(mbuf, magic, sizeof magic - 1) != 0) {
    BIO_printf(bio_err, "bad magic number\n");
    goto end;
  }

  if (readpassphrase("passphrase: ", key, sizeof(key), 0) == NULL) {
    perror("failed to read passphrase");
    goto end;
  }

  if (EVP_BytesToKey(cipher, EVP_sha256(), salt,
                     reinterpret_cast<unsigned char *>(key), strlen(key), 1,
                     dkey, iv) == 0) {
    perror("failed to derive key and iv");
    goto end;
  }
  explicit_bzero(key, sizeof(key));

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

#include "pwm.h"

inline constexpr std::string_view MAGIC{"Salted__"};
const int SALT_LENGTH = 32;
const int TAG_LENGTH = 16;
const int HDRSZ = MAGIC.size() + SALT_LENGTH + TAG_LENGTH;
const int PBKDF2_ITER_COUNT = 500000;

[[noreturn]] static void bail(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}

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
  bail("usage: pwm [-d | -C | -u <name> [<meta>...] | -r name | <pattern>\n\n"
       "options:\n"
       "  -C  change master password on existing store\n"
       "  -d  dump all passwords to stderr\n"
       "  -l  linger for passwordless queries in future invocations\n"
       "  -u  create/update password with <name> and optional <meta> data\n"
       "  -r  remove password with <name>\n");
}

[[nodiscard]] static bool is_read_only() {
  auto v = std::getenv("PWM_READONLY");
  return v != nullptr && strncmp(v, "0", 1) != 0;
}

[[nodiscard]] static bool is_linger_enabled() {
  auto v = std::getenv("PWM_LINGER");
  return v != nullptr && strncmp(v, "0", 1) != 0;
}

[[nodiscard]] static std::string get_store_path() {
  std::string store_path;
  if (const char *env_store = std::getenv("PWM_STORE")) {
    store_path = env_store;
  } else {
    store_path = default_store_path();
  }
  return store_path;
}

static bool socket_is_live(const std::string &path) {
  int sock;
  struct sockaddr_un sunaddr;

  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "%s", path.c_str());

  if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    return false;
  }

  if (connect(sock, reinterpret_cast<struct sockaddr *>(&sunaddr),
              sizeof(sunaddr)) == 0) {
    close(sock);
    return true;
  }
  return false;
}

static void sigpipe(__attribute__((unused)) int a) { bail("Received SIGPIPE"); }

/* serve master password to future invocations for a limited period of time */
using pollfd_t = struct pollfd;

static void linger(const std::string_view key) {
  close(fileno(stdin));
  pid_t pid = fork();
  if (pid != 0) {
    exit(0);
  }
  close(fileno(stdout));

  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);

  std::string path{"/tmp/pwm."};
  path += std::getenv("USER");
  int sock;
  struct sockaddr_un sunaddr;

  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "%s", path.c_str());

  if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    bail("Unable to create socket");
  }

  if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
    close(sock);
    bail("Unable to set FD_CLOEXEC on socket");
  }

  if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
    close(sock);
    bail("Unable to set NONBLOCK on socket");
  }

  if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
    if (!socket_is_live(path)) {
      unlink(path.c_str());
      if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
        bail("Unable to bind socket");
      }
    } else {
      // already lingering, so do nothing.
      return;
    }
  }

  if (listen(sock, 2) == -1) {
    bail("Unable to listen on socket %s", strerror(errno));
  }

  if (pledge("stdio inet", NULL) != 0) {
    bail("pledge(2) failed at %d.", __LINE__);
  }

  signal(SIGPIPE, sigpipe);

  while (true) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (now.tv_sec - start.tv_sec > 21600) {
      break;
    }

    pollfd_t fds{sock, POLLIN, 0};
    int rv = poll(&fds, 1, 5000);
    if (rv < 0) {
      bail("Failed to poll() sock");
    }
    if (rv == 0) {
      continue;
    }
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    int csock = accept(sock, (struct sockaddr *)&addr, &len);
    if (csock == -1) {
      bail("accept() failed %d %s", csock, strerror(errno));
    }
    char buf[32] = {0};

    pollfd_t cfd{csock, POLLIN, 0};
    if (poll(&cfd, 1, 2000) <= 0) {
      close(csock);
      continue;
    }

    ssize_t sz = read(csock, &buf, sizeof(buf));
    if (sz < 1) {
      close(csock);
      continue;
    }
    buf[sz] = '\0';
    if (strcmp(buf, "shutdown\n") == 0) {
      close(csock);
      break;
    }

    if (strcmp(buf, "hello\n") != 0) {
      close(csock);
      continue;
    }

    write(csock, key.data(), key.size());
    close(csock);
    clock_gettime(CLOCK_MONOTONIC, &start); // reset linger timer
  }
  close(sock);
}

struct cmd_flags get_flags(int argc, char *const *argv) {
  struct cmd_flags f;
  int ch;

  f.linger = is_linger_enabled();
  f.read_only = is_read_only();
  f.store_path = get_store_path();
  optind = opterr = 1; // for tests
  std::vector<std::string> args;

  while ((ch = getopt(argc, argv, "-Cdlur")) != -1) {
    switch (ch) {
    case 'r':
      f.remove = true;
      break;
    case 'u':
      f.update = true;
      break;
    case 'l':
      f.linger = true;
      break;
    case 'd':
      f.dump = true;
      break;
    case 'C':
      f.chpass = true;
      break;
    case '\1':
      // non-option arg
      args.push_back(optarg);
      break;
    default:
      usage();
    }
  }

  if (!args.empty()) {
    f.name = args.front();
  }
  for (unsigned int i = 1; i < std::size(args); i++) {
    if (!f.meta.empty()) {
      f.meta += " ";
    }
    f.meta += args[i];
  }

  // : is a field delim, so don't allow it in metadata
  if (!f.validate_meta()) {
    bail("Metadata cannot contain ':' characters.");
  }
  if (!f.validate_name()) {
    bail("Name cannot contain ':' characters.");
  }

  if (!f.validate_read_only()) {
    bail("Write operations are disabled.");
  }

  if (!f.validate_store_path()) {
    bail("PWM_STORE is undefined.");
  }
  if (!f.update) {
    check_perms(f.store_path);
  }

  if (!f.validate_options()) {
    fprintf(stderr, "pwm: command options can't be combined\n");
    usage();
  }

  if (!f.validate_search()) {
    fprintf(stderr, "pwm: must specify a search string.\n");
    usage();
  }
  return f;
}

int handle_search(const struct cmd_flags &f, struct ent &entry) {
  auto ciphertext = read_file(f.store_path);
  std::string data, dkeyiv, key;

  if (ciphertext.empty()) {
    bail("missing or corrupt store: %s", f.store_path.c_str());
  }
  dkeyiv = readpass_fromdaemon();
  if (dkeyiv.empty()) {
    key = readpass("passphrase: ");
    derive_key(ciphertext, key, dkeyiv);
    explicit_bzero(&key[0], key.size());
  }
  if (!decrypt(ciphertext, dkeyiv, data)) {
    fprintf(stderr, "Decrypt failed\n");
    return 1;
  }
  if (search(f.name, data, entry)) {
    if (entry.updated_at) {
      char buf[64];
      struct tm *t = localtime(&entry.updated_at);
      strftime(buf, sizeof(buf), "%F %T", t);
      fprintf(stderr, "\nupdated: %s\n", buf);
    }
    fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
    printf("%s\n", entry.password.c_str());
  } else {
    fprintf(stderr, "Not found.\n");
  }
  if (!dkeyiv.empty() && f.linger) {
    linger(dkeyiv);
  }
  return 0;
}

int handle_dump(const struct cmd_flags &f) {
  auto ciphertext = read_file(f.store_path);
  std::string data, dkeyiv, key;

  if (ciphertext.empty()) {
    bail("missing or corrupt store: %s", f.store_path.c_str());
  }
  dkeyiv = readpass_fromdaemon();
  if (dkeyiv.empty()) {
    key = readpass("passphrase: ");
    derive_key(ciphertext, key, dkeyiv);
    explicit_bzero(&key[0], key.size());
  }
  if (!decrypt(ciphertext, dkeyiv, data)) {
    fprintf(stderr, "Decrypt failed\n");
    return 1;
  }
  if (!dump(data)) {
    return 1;
  }
  if (f.linger && !dkeyiv.empty()) {
    linger(dkeyiv);
  }
  return 0;
}

int handle_chpass(const struct cmd_flags &f) {
  auto ciphertext = read_file(f.store_path);
  std::string data, dkeyiv, key;

  if (ciphertext.empty()) {
    bail("missing or corrupt store: %s", f.store_path.c_str());
  }
  dkeyiv = readpass_fromdaemon();
  if (dkeyiv.empty()) {
    key = readpass("passphrase: ");
    derive_key(ciphertext, key, dkeyiv);
    explicit_bzero(&key[0], key.size());
  }
  if (!decrypt(ciphertext, dkeyiv, data)) {
    fprintf(stderr, "Decrypt failed\n");
    return 1;
  }
  fprintf(stderr, "Resetting password for %s.\n", f.store_path.c_str());
  key = readpass("set root passphrase: ");
  if (key != readpass(" confirm passphrase: ")) {
    bail("passwords didn't match.");
  }
  if (!save_backup(f.store_path)) {
    bail("failed to save backup. aborting.");
  }
  std::string newdata;
  if (!encrypt(data, key, newdata)) {
    bail("re-encrypt failed! backup saved.");
  }
  explicit_bzero(&data[0], data.size());
  if (!dump_to_file(newdata, f.store_path)) {
    bail("failed to write updated store. backup saved.");
  }
  maybe_shutdown_daemon();
  fprintf(stderr,
          "\nMaster password updated.\n\nDelete the backup store\n"
          "  rm %s.bak\nif your old password was compromised.\n",
          f.store_path.c_str());

  if (f.linger && derive_key(newdata, key, dkeyiv)) {
    explicit_bzero(&key[0], key.size());
    linger(dkeyiv);
  }
  return 0;
}

int handle_update(const struct cmd_flags &f, struct ent &entry) {
  auto ciphertext = read_file(f.store_path);
  std::string data, dkeyiv, key;
  bool init_new = false;

  if (ciphertext.empty()) {
    fprintf(stderr, "Initializing new password store.\n");
    init_new = true;
    key = readpass("set root passphrase: ");
    if (key != readpass(" confirm passphrase: ")) {
      bail("passwords didn't match.");
    }
  } else {
    // can't use daemon because we need key to derive new dkeyiv
    key = readpass("passphrase: ");
    derive_key(ciphertext, key, dkeyiv);
    if (!decrypt(ciphertext, dkeyiv, data)) {
      fprintf(stderr, "Decrypt failed\n");
      return 1;
    }
  }
  entry.updated_at = time(nullptr);
  entry.password = random_str(15);
  std::string newdata;
  if (!update(data, entry, newdata, f.remove)) {
    bail("%s failed.", f.remove ? "remove" : "update");
  }
  data.clear();

  if (!init_new && !save_backup(f.store_path)) {
    bail("failed to save backup. aborting.");
  }
  if (!encrypt(newdata, key, data)) {
    bail("re-encrypt failed! backup saved.");
  }
  explicit_bzero(&newdata[0], newdata.size());
  if (!dump_to_file(data, f.store_path)) {
    bail("failed to write updated store.");
  }
  maybe_shutdown_daemon();
  if (f.update) {
    fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
    printf("%s\n", entry.password.c_str());
  } else {
    fprintf(stderr, "\n%s: removed\n", entry.name.c_str());
  }
  if (f.linger && derive_key(data, key, dkeyiv)) {
    explicit_bzero(&key[0], key.size());
    linger(dkeyiv);
  }
  return 0;
}

#ifndef TESTING
int main(int argc, char **argv) {
  struct ent entry;
  auto f = get_flags(argc, argv);
  entry.name = f.name;
  entry.meta = f.meta;

  if (f.uses_writeops() || f.linger) {
    if (pledge("proc unix inet stdio tty fattr cpath rpath wpath", NULL) != 0) {
      bail("pledge(2) failed at %d.", __LINE__);
    }
  } else {
    if (pledge("proc unix inet stdio tty rpath fattr", NULL) != 0) {
      bail("pledge(2) failed at %d.", __LINE__);
    }
  }

  if (f.is_search()) {
    return handle_search(f, entry);
  } else if (f.update || f.remove) {
    return handle_update(f, entry);
  } else if (f.dump) {
    return handle_dump(f);
  } else if (f.chpass) {
    return handle_chpass(f);
  }
  // should never happen
  usage();
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
        entry.updated_at = newent.updated_at;
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

[[nodiscard]] bool save_backup(const std::string &filename) {
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
    if (0 != chmod(path.c_str(), S_IRUSR | S_IWUSR)) {
      bail("%s\n   must be read/writeable by owner only.", path.c_str());
    }
    chmod((path + ".bak").c_str(), S_IRUSR | S_IWUSR); // best effort
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

bool search(const std::string &needle, const std::string &haystack,
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
        fprintf(stderr, "error: '%s' matches '%s' and '%s'\n", needle.c_str(),
                match.name.c_str(), entry.name.c_str());
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
  entry.updated_at = 0;
  if (data.size() == 1) {
    entry.password = data[0];
  } else {
    entry.meta.clear();
    for (size_t i = 0; i < data.size() - 2; i++) {
      if (i > 0) {
        entry.meta += " ";
      }
      entry.meta += data[i]; // typically username
    }
    try {
      entry.updated_at = std::stol(data[data.size() - 2]);
      if (entry.updated_at < 1601877323 || entry.updated_at > 2401877323) {
        entry.updated_at = 0;
        throw std::out_of_range("invalid time value");
      }
    } catch (std::logic_error &e) {
      entry.meta += (entry.meta.empty() ? "" : " ") + data[data.size() - 2];
    }
    entry.password = data[data.size() - 1];
  }
  return true;
}

std::string dump_entry(const struct ent &entry) {
  std::string s(entry.name);
  return s + ": " + (entry.meta.empty() ? "" : entry.meta + " ") +
         (entry.updated_at ? std::to_string(entry.updated_at) + " " : "") +
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

bool maybe_shutdown_daemon() {
  struct sockaddr_un sunaddr;
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "/tmp/pwm.%s",
           std::getenv("USER"));
  int sock;

  if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    return false;
  }

  if (connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
    return false;
  }
  const char *cmd = "shutdown\n";
  if (write(sock, cmd, strlen(cmd)) < 1) {
    close(sock);
    return false;
  }
  close(sock);
  return true;
}

std::string readpass_fromdaemon() {
  struct sockaddr_un sunaddr;
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "/tmp/pwm.%s",
           std::getenv("USER"));
  int sock;

  if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    return "";
  }

  if (connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
    return "";
  }
  const char *greeting = "hello\n";
  if (write(sock, greeting, strlen(greeting)) < 1) {
    close(sock);
    return "";
  }
  std::string key(EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH, '\0');
  if (read(sock, &key.data()[0], key.size()) < 1) {
    close(sock);
    return "";
  }
  close(sock);
  return key;
}

std::string readpass(const std::string &prompt) {
  char key[EVP_MAX_KEY_LENGTH] = {0};

  if (readpassphrase(prompt.c_str(), key, sizeof(key), 0) == NULL) {
    bail("failed to read passphrase");
  }
  return {key};
}

/**
 * derive encryption key from salt + master key.
 */
bool derive_key(const std::string &ciphertext, const std::string &key,
                std::string &dkeyiv) {

  dkeyiv.resize(EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH);

  if (ciphertext.size() < HDRSZ) {
    fprintf(stderr, "error: corrupt password store.\n");
    return false;
  }

  if (ciphertext.substr(0, MAGIC.size()) != MAGIC) {
    perror("invalid magic string");
    return false;
  }

  std::string salt = ciphertext.substr(MAGIC.size(), SALT_LENGTH);
  if (PKCS5_PBKDF2_HMAC(
          key.c_str(), key.size(),
          reinterpret_cast<unsigned char *>(salt.data()), SALT_LENGTH,
          PBKDF2_ITER_COUNT, EVP_sha256(), dkeyiv.size(),
          reinterpret_cast<unsigned char *>(dkeyiv.data())) != 1) {
    perror("failed to derive key and iv");
    return false;
  }
  return true;
}

/**
 * Decrypt ciphertext with derived key and store it in plaintext.
 */
bool decrypt(const std::string &ciphertext, const std::string &dkeyiv,
             std::string &plaintext) {
  unsigned char salt[SALT_LENGTH];
  char tag[TAG_LENGTH];
  int sz = 0;
  std::string s(ciphertext.size(), '\0');
  EvpCipherContext ctx;
  const EVP_CIPHER *cipher = EVP_aes_256_gcm();

  if (ciphertext.size() < HDRSZ) {
    fprintf(stderr, "error: corrupt password store.\n");
    return false;
  }

  if (ciphertext.substr(0, MAGIC.size()) != MAGIC) {
    perror("invalid magic string");
    return false;
  }
  ciphertext.copy(reinterpret_cast<char *>(salt), sizeof(salt), MAGIC.size());
  ciphertext.copy(tag, sizeof(tag), MAGIC.size() + sizeof(salt));

  if (EVP_CipherInit_ex(ctx.get(), cipher, NULL,
                        reinterpret_cast<const unsigned char *>(dkeyiv.data()),
                        reinterpret_cast<const unsigned char *>(dkeyiv.data()) +
                            EVP_MAX_KEY_LENGTH,
                        0) != 1) {
    perror("failed to init cipher");
    return false;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, tag) !=
      1) {
    perror("failed to set GCM tag");
    return false;
  }

  sz = s.size();
  if (EVP_CipherUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(s.data()), &sz,
          reinterpret_cast<const unsigned char *>(&(ciphertext.data()[HDRSZ])),
          ciphertext.size() - HDRSZ) != 1) {
    perror("CipherUpdate() failed");
    return false;
  }

  plaintext.append(s, 0, sz);

  if (EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(s.data()),
                         &sz) != 1) {
    perror("CipherFinal() failed");
    return false;
  }

  plaintext.append(s, 0, sz);
  plaintext = sort_data(plaintext);

  return true;
}

/**
 * Encrypt plaintext with key and store it in ciphertext.
 */
bool encrypt(const std::string &plaintext, const std::string &key,
             std::string &ciphertext) {
  unsigned char dkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
  unsigned char salt[SALT_LENGTH];
  int sz = 0;
  std::string s(plaintext.size() + 1000, '\0');
  std::string tmp;

  EvpCipherContext ctx;
  const EVP_CIPHER *cipher = EVP_aes_256_gcm();

  arc4random_buf(salt, sizeof(salt));

  ciphertext.append(MAGIC);
  ciphertext.append(reinterpret_cast<const char *>(salt), sizeof(salt));

  if (PKCS5_PBKDF2_HMAC(key.c_str(), key.size(), salt, sizeof(salt),
                        PBKDF2_ITER_COUNT, EVP_sha256(), sizeof(dkeyiv),
                        dkeyiv) != 1) {
    perror("failed to derive key and iv");
    return false;
  }

  if (EVP_CipherInit_ex(ctx.get(), cipher, NULL, dkeyiv,
                        dkeyiv + EVP_MAX_KEY_LENGTH, 1) != 1) {
    perror("failed to init cipher");
    return false;
  }

  sz = s.size();
  if (EVP_CipherUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(s.data()), &sz,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          plaintext.size()) != 1) {
    perror("CipherUpdate() failed");
    return false;
  }

  tmp.append(s, 0, sz);

  if (EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(s.data()),
                         &sz) != 1) {
    perror("CipherFinal() failed");
    return false;
  }

  tmp.append(s, 0, sz);

  char tag[TAG_LENGTH];
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, &tag) !=
      1) {
    perror("GCM get tag failed");
    return false;
  }

  // ciphertext must contain MAGIC+SALT+TAG in header, but tag is
  // only available after all data has been processed.

  ciphertext.append(tag, TAG_LENGTH);
  ciphertext.append(tmp);

  return true;
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

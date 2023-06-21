#include <algorithm>
#include <cassert>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <libgen.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <poll.h>
#include <readpassphrase.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#include "portable.h"

static bool save_backup(const std::string &filename);
static std::string readpass(const std::string &prompt);
static std::string readpass_fromdaemon();

bool dump_to_file(const std::string &data, const std::string &filename);
bool derive_key(const std::string &ciphertext, const std::string &key,
                std::string &dkeyiv);
bool encrypt(const std::string &plaintext, const std::string &key,
             std::string &ciphertext);
bool decrypt(const std::string &ciphertext, const std::string &dkeyiv,
             std::string &plaintext);
std::string trim(const std::string &s);
std::string read_file(const std::string &filename);
std::vector<std::string> split(const std::string &s,
                               const std::string &delimiter);
bool find(const std::string &needle, const std::string &haystack,
          struct ent &entry);
bool dump(const std::string &data);
bool update(const std::string &data, const struct ent &newent,
            std::string &revised, bool remove);
bool parse_entry(const std::string &line, struct ent &entry);
std::string dump_entry(const struct ent &entry);
std::string random_str(size_t sz);
std::string sort_data(const std::string &data);
void check_perms(const std::string &path);

struct ent {
  std::string name;
  std::string meta;
  std::string password;
  time_t updated_at;
  bool operator==(const ent &rhs) const {
    return (name == rhs.name && meta == rhs.meta && password == rhs.password);
  }
  void clear() {
    name.clear();
    meta.clear();
    password.clear();
    updated_at = 0;
  }
};

struct EvpCipherContext {
  EVP_CIPHER_CTX *get() const { return ctx_; }

  EvpCipherContext() {
    ctx_ = EVP_CIPHER_CTX_new();
    assert(ctx_ != nullptr);
  }
  ~EvpCipherContext() { EVP_CIPHER_CTX_free(ctx_); }

private:
  EVP_CIPHER_CTX *ctx_;
};

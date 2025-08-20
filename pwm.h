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
#ifndef __OpenBSD__
#include "portable.h"
#endif

static bool save_backup(const std::string &filename);
static std::string readpass(const std::string &prompt);
static std::string readpass_fromdaemon();
static bool maybe_shutdown_daemon();

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
bool search(const std::string &needle, const std::string &haystack,
            struct ent &entry);
bool dump(const std::string &data);
bool update(const std::string &data, const struct ent &newent,
            std::string &revised, bool remove);
bool parse_entry(const std::string &line, struct ent &entry);
std::string dump_entry(const struct ent &entry);
std::string random_str(size_t sz);
std::string sort_data(const std::string &data);
void check_perms(const std::string &path);
struct cmd_flags get_flags(int argc, char *const *argv);
bool handle_search(const struct cmd_flags &f, struct ent &entry);
bool handle_dump(const struct cmd_flags &f);
bool handle_chpass(const struct cmd_flags &f);
bool handle_update(const struct cmd_flags &f, struct ent &entry);

struct ent {
  std::string name;
  std::string meta;
  std::string password;
  time_t updated_at = 0;
  bool operator==(const ent &rhs) const {
    return (name == rhs.name && meta == rhs.meta && password == rhs.password);
  }
  void clear() {
    name.clear();
    meta.clear();
    password.clear();
    updated_at = 0;
  }

  std::string to_string() const {
    std::string s;
    s = "[name=" + name + "] [updated_at=" + std::to_string(updated_at) +
        "] [password=" + password + "]";
    if (!meta.empty())
      s += " [meta=" + meta + "]";
    return s;
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

struct cmd_flags {
  std::string name;
  std::string meta;
  std::string store_path;
  std::string key;      // for testing only
  std::string newkey;   // for testing only
  std::string password; // for testing only
  bool chpass = false;
  bool readpass = false;
  bool dump = false;
  int linger = 0; // 0 means disabled
  bool remove = false;
  bool read_only = false;
  bool update = false;

  bool validate_name() { return name.find(":") == name.npos; }
  bool validate_meta() { return meta.find(":") == meta.npos; }
  bool validate_read_only() { return !read_only || !uses_writeops(); }
  bool validate_options() { return (update + dump + remove + chpass) <= 1; }
  bool validate_search() { return !name.empty() || dump || chpass; }
  bool validate_store_path() { return !store_path.empty(); }

  bool uses_writeops() const { return remove || update || chpass; }
  bool is_search() const { return !uses_writeops() && !dump; }

  std::string to_string() const {
    std::string s;
    s += "name: " + name + "\n";
    s += "meta: " + meta + "\n";
    s += "store_path: " + store_path + "\n";
    s += "chpass: " + std::to_string(chpass) + "\n";
    s += "dump: " + std::to_string(dump) + "\n";
    s += "linger: " + std::to_string(linger) + "\n";
    s += "remove: " + std::to_string(remove) + "\n";
    s += "read_only: " + std::to_string(read_only) + "\n";
    s += "update: " + std::to_string(update) + "\n";
    s += "is_search: " + std::to_string(is_search()) + "\n";
    s += "uses_writeops: " + std::to_string(uses_writeops()) + "\n";
    return s;
  }
};

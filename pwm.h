#include <algorithm>
#include <iterator>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <libgen.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <readpassphrase.h>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <portable.h>

static bool save_backup(const std::string &filename);
static std::string readpass(const std::string &prompt);

bool dump_to_file(const std::string &data, const std::string &filename);
bool encrypt(const std::string &plaintext, const std::string &key,
             std::string &ciphertext);
bool decrypt(const std::string &ciphertext, const std::string &key,
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
void check_perms(const char *path);

struct ent {
  std::string name;
  std::string meta;
  std::string password;
  bool operator==(const ent &rhs) const {
    return (name == rhs.name && meta == rhs.meta && password == rhs.password);
  }
  void clear() {
    name.clear();
    meta.clear();
    password.clear();
  }
};

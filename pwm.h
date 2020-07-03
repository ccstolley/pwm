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

static bool save_backup(const std::string &filename);
static bool wipefile(const std::string &filename);
static std::string readpass();

bool dump_to_file(const std::string &data, const std::string &filename);
bool encrypt(const std::string &plaintext, const std::string &key,
             std::string *ciphertext);
bool decrypt(const std::string &ciphertext, const std::string &key,
             std::string *plaintext);
std::string trim(const std::string &s);
std::string readfile(const std::string &filename);
std::vector<std::string> split(const std::string &s,
                               const std::string &delimiter);
bool find(const std::string &needle, const std::string &haystack,
          struct ent *entry);
bool edit(std::string &data, const std::string &key,
          const std::string &store_path);
bool update(const std::string &data, const struct ent &newent,
            std::string &revised);
bool parse_entry(const std::string &line, struct ent *entry);
std::string dump_entry(const struct ent &entry);
std::string random_str(size_t sz);

struct ent {
  std::string name;
  std::string meta;
  std::string password;
  bool operator==(const ent &rhs) {
    return (name == rhs.name && meta == rhs.meta && password == rhs.password);
  }
};

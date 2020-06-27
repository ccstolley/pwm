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
#include <vector>

bool dump_to_file(const std::string &data, const std::string &filename);
bool save_backup(const char *filename);
bool encrypt(const std::string &out_filename, const std::string &key,
             const std::string &data);
bool decrypt(const std::string &in_filename, const std::string &key,
             std::string *data);
std::string trim(const std::string &s);
bool wipefile(const std::string &filename);
std::string readpass();
std::string readfile(const std::string &filename);
std::vector<std::string> split(const std::string &s,
                               const std::string &delimiter);
bool find(const std::string &needle, const std::string &haystack,
          struct ent *entry);
struct ent {
  std::string name;
  std::string meta;
  std::string password;
};

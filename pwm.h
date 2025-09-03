#include <algorithm>
#include <arpa/inet.h>
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

class Storage {
public:
  struct Entry {
    std::string name;
    time_t updated_at = 0;
    std::string password;
    std::string meta;

    bool operator==(const Entry &rhs) const {
      return (name == rhs.name && meta == rhs.meta &&
              password == rhs.password && updated_at == rhs.updated_at);
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

  Storage(const std::string &data) : _data(data) {}

  // Serialize by encoding the length (network order, msb first) in 2 bytes
  // (uint16_t), then dumping length bytes, then another length byte pair and so
  // on until you reach the end of the record, which is identified by two zero
  // length bytes or null bytes. Ex: 0x0 0x5 'c' 'o' 'l' 'i' 'n' 0x0 0xa '1' '7'
  // '5' '6' '3' '1' '1' '5' '9' '4' 0x0 0x3 'c' 'a' 't' 0x0 0x0
  std::string static serialize(const Entry &ent) {
    std::ostringstream ss;
    encodeField(ss, ent.name);
    encodeField(ss, std::to_string(ent.updated_at));
    encodeField(ss, ent.password);

    if (!ent.meta.empty()) {
      encodeField(ss, ent.meta);
    }
    encodeEOR(ss);
    return ss.str();
  }

  bool static deserialize(std::string_view &raw, Entry &ent) {
    if (bool ok = decodeField(raw, ent.name); !ok) {
      return false;
    }

    std::string updated;
    if (bool ok = decodeField(raw, updated); !ok) {
      return false;
    }
    ent.updated_at = std::stol(updated);

    if (bool ok = decodeField(raw, ent.password); !ok) {
      return false;
    }

    if (decodeLength(raw) != 0) {
      if (bool ok = decodeField(raw, ent.meta); !ok) {
        return false;
      }
      assert(decodeLength(raw) == 0);
    }
    raw.remove_prefix(2); // skip over EOR bytes
    return true;
  }

  bool next(Entry &ent) { return deserialize(_data, ent); }

  std::string static trim(const std::string &s) {
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

  std::vector<std::string> static split(const std::string &s,
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
  bool static parse_entry(const std::string &line, Storage::Entry &entry) {
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

  bool static deserialize_old(std::string_view &raw, Entry &ent) {
    auto eor = raw.find('\n');
    if (eor == raw.npos) {
      return false;
    }
    std::string line{raw.substr(0, eor)};
    raw.remove_prefix(eor + 1);
    return parse_entry(line, ent);
  }

private:
  bool static decodeField(std::string_view &raw, std::string &field) {
    if (raw.size() < 2)
      return false;
    auto len = decodeLength(raw);
    raw.remove_prefix(2);
    if (len > raw.size()) {
      return false;
    }
    field = raw.substr(0, len);
    raw.remove_prefix(len);
    return true;
  }

  uint16_t static decodeLength(std::string_view raw) {
    return ntohs(*reinterpret_cast<const uint16_t *>(raw.substr(0, 2).data()));
  }

  void static encodeEOR(std::ostringstream &ss) {
    uint16_t zero = htons(0);
    ss.write(reinterpret_cast<char *>(&zero), sizeof(uint16_t));
  }

  void static encodeField(std::ostringstream &ss, const std::string &str) {
    uint16_t length = htons(str.size());
    assert(length != 0);
    ss.write(reinterpret_cast<char *>(&length), sizeof(uint16_t));
    ss.write(str.data(), str.size());
  }

  std::string_view _data;
};

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
std::string read_file(const std::string &filename);
bool search(const std::string &needle, const std::string &haystack,
            Storage::Entry &entry);
bool dump(const std::string &data);
bool update(const std::string &data, const Storage::Entry &newent,
            std::string &revised, bool remove);
std::string dump_entry(const Storage::Entry &entry);
std::string random_str(size_t sz);
std::string sort_data(const std::string &data);
void check_perms(const std::string &path);
struct cmd_flags get_flags(int argc, char *const *argv);
bool handle_search(const struct cmd_flags &f, Storage::Entry &entry);
bool handle_dump(const struct cmd_flags &f);
bool handle_chpass(const struct cmd_flags &f);
bool handle_update(const struct cmd_flags &f, Storage::Entry &entry);

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

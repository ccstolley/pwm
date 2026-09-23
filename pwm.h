#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <csignal>
#include <cstdint>
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
#include <openssl/hmac.h>
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
    assert(!ent.name.empty());
    assert(!ent.password.empty());
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

  bool next(Entry &ent) {
    ent.clear();
    return deserialize(_data, ent);
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
    assert(!str.empty());
    uint16_t length = htons(str.size());
    ss.write(reinterpret_cast<char *>(&length), sizeof(uint16_t));
    ss.write(str.data(), str.size());
  }

  std::string_view _data;
};

/*
 * Store layout, version 1 ("PWMKEY01").
 *
 * A random 32 byte master key (MK) encrypts the store body. The header holds a
 * list of key slots, each an independently wrapped copy of MK, so that any one
 * enrolled factor is sufficient to open the store (OR semantics, like LUKS
 * keyslots). Exactly one password slot is always present; zero or more FIDO2
 * slots may be enrolled alongside it.
 *
 *   magic        8   "PWMKEY01"
 *   version      1   STORE_VERSION
 *   fido_salt   32   store wide hmac-secret salt (see note below)
 *   slot_count   1
 *   slots      var   slot_count serialized slots
 *   body_nonce  12
 *   body_tag    16
 *   body       var   AES-256-GCM(MK), AAD = every header byte before body_nonce
 *
 * Each slot serializes as:
 *
 *   type         1   SLOT_PASSWORD or SLOT_FIDO2
 *   payload_len  2   length of everything below
 *   wrap_nonce  12
 *   wrap_tag    16
 *   wrapped_mk  32   AES-256-GCM(KEK) of MK, AAD = type byte + extra
 *   extra      var   SLOT_PASSWORD: salt[32] iter[4]
 *                    SLOT_FIDO2:    cred_id_len[2] cred_id label_len[2] label
 *
 * The body's AAD covers the whole slot table, so stripping, reordering or
 * splicing in slots fails the body tag rather than silently downgrading which
 * factors the store will accept.
 *
 * fido_salt is store wide rather than per slot on purpose. A FIDO2 assertion
 * fixes its hmac salt before the call, so per slot salts would make it
 * impossible to satisfy several enrolled credentials with a single assertion
 * (and therefore a single touch). One shared salt still yields a distinct
 * secret per credential, because the authenticator mixes in a per-credential
 * random value.
 *
 * INVARIANT: every wrap writes a freshly generated random nonce, with no
 * exceptions. Reusing a (KEK, nonce) pair across different plaintexts leaks the
 * XOR of both master keys and the GCM authentication subkey. Reusing a slot's
 * *salt* is fine and is in fact required: rotating MK has to wrap the new MK
 * under each surviving slot's existing KEK, and a FIDO2 KEK can only be
 * recomputed with that token in hand.
 */
inline constexpr std::string_view MAGIC_V1{"PWMKEY01"};
inline constexpr uint8_t STORE_VERSION = 1;
inline constexpr uint8_t SLOT_PASSWORD = 1;
inline constexpr uint8_t SLOT_FIDO2 = 2;
inline constexpr int MK_LENGTH = 32;
inline constexpr int GCM_NONCE_LENGTH = 12;
inline constexpr int FIDO_SALT_LENGTH = 32;
inline constexpr int FIDO_SECRET_LENGTH = 32;
inline constexpr size_t MAX_SLOTS = 32;
inline constexpr size_t MAX_LABEL = 128;
inline constexpr std::string_view FIDO_KEK_INFO{"pwm fido2 slot v1"};
inline constexpr std::string_view FIDO_RP_ID{"pwm"};

struct KeySlot {
  uint8_t type = SLOT_PASSWORD;
  std::string wrap_nonce;
  std::string wrap_tag;
  std::string wrapped_mk;
  // SLOT_PASSWORD
  std::string salt;
  uint32_t iter = 0;
  // SLOT_FIDO2
  std::string cred_id;
  std::string label;

  bool is_password() const { return type == SLOT_PASSWORD; }
  bool is_fido() const { return type == SLOT_FIDO2; }
  std::string describe(size_t idx) const;
};

struct StoreHeader {
  std::string fido_salt;
  std::vector<KeySlot> slots;
  std::string aad;     // header bytes bound into the body tag
  size_t body_off = 0; // offset of body_nonce within the ciphertext
};

struct DataStore {
  std::string mk;
  StoreHeader hdr;
  std::string data;
  bool legacy = false; // v0 "Salted__" store, upgraded on the next write

  ~DataStore() {
    explicit_bzero(&mk[0], mk.size());
    explicit_bzero(&data[0], data.size());
  }
};

static bool save_backup(const std::string &filename);
static std::string readpass(const std::string &prompt);
static std::pair<uid_t, gid_t> get_sock_ident(int sock);

bool dump_to_file(const std::string &data, const std::string &filename);
bool derive_key(const std::string &ciphertext, const std::string &key,
                std::string &dkeyiv);
bool encrypt(const std::string &plaintext, const std::string &key,
             std::string &ciphertext);
bool decrypt(const std::string &ciphertext, const std::string &dkeyiv,
             std::string &plaintext);

/* v1 keyslot store */
bool is_v1_store(const std::string &ciphertext);
bool parse_header(const std::string &ciphertext, StoreHeader &hdr);
std::string serialize_header(const StoreHeader &hdr);
bool password_kek(const std::string &password, const std::string &salt,
                  uint32_t iter, std::string &kek);
bool fido_kek(const std::string &secret, const std::string &fido_salt,
              std::string &kek);
bool wrap_mk(const std::string &kek, const std::string &mk, KeySlot &slot);
bool unwrap_mk(const std::string &kek, const KeySlot &slot, std::string &mk);
bool make_password_slot(const std::string &password, const std::string &mk,
                        KeySlot &slot);
bool encrypt_store(const std::string &plaintext, const StoreHeader &hdr,
                   const std::string &mk, std::string &ciphertext);
bool decrypt_store(const std::string &ciphertext, const std::string &mk,
                   std::string &plaintext);
bool unlock_store(const std::string &ciphertext, const struct CmdFlags &f,
                  std::string &mk, StoreHeader &hdr);
bool rotate_mk(const std::string &plaintext, const std::string &new_password,
               StoreHeader &hdr, std::string &mk, std::string &ciphertext,
               bool drop_missing = false);
bool write_store(const std::string &plaintext, const DataStore &ds,
                 const std::string &path);
bool handle_enroll(const struct CmdFlags &f);
bool handle_slots(const struct CmdFlags &f);
bool handle_deauth(const struct CmdFlags &f);

/* FIDO2 token access; stubs that fail cleanly when built without libfido2 */
bool fido_available();
bool fido_present();
bool fido_get_secret(const std::vector<KeySlot> &slots,
                     const std::string &fido_salt, std::string &secret,
                     std::string &cred_id);
bool fido_secret_for_cred(const std::string &cred_id,
                          const std::string &fido_salt, std::string &secret);
bool fido_enroll(const std::string &fido_salt, std::string &cred_id,
                 std::string &secret);
std::string read_file(const std::string &filename);
bool search(const std::string &needle, const std::string &haystack,
            Storage::Entry &entry);
bool dump(const std::string &data);
bool update(const std::string &data, const Storage::Entry &newent,
            std::string &revised, bool remove);
std::string dump_entry(const Storage::Entry &entry);
std::string random_str(size_t sz);
std::string random_bytes(size_t sz);
std::string sort_data(const std::string &data);
void check_perms(const std::string &path);
struct CmdFlags get_flags(int argc, char *const *argv);
bool handle_search(const struct CmdFlags &f, Storage::Entry &entry);
bool handle_dump(const struct CmdFlags &f);
bool handle_chpass(const struct CmdFlags &f);
bool handle_update(const struct CmdFlags &f, Storage::Entry &entry);

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

struct CmdFlags {
  std::string name;
  std::string meta;
  std::string store_path;
  std::string key;      // for testing only
  std::string newkey;   // for testing only
  std::string password; // for testing only
  std::string label;    // label for a newly enrolled security key
  bool chpass = false;
  bool readpass = false;
  bool dump = false;
  bool remove = false;
  bool read_only = false;
  bool update = false;
  bool enroll = false;         // -e  enroll a FIDO2 security key
  bool slots = false;          // -E  list enrolled key slots
  int deauth = -1;             // -R  remove key slot by index
  bool force_password = false; // -P  ignore any attached token
  bool drop_missing = false; // -F  re-key without a key that cannot be reached

  bool validate_read_only() { return !read_only || !uses_writeops(); }
  bool validate_options() {
    return (update + dump + remove + chpass + enroll + slots + (deauth >= 0)) <=
           1;
  }
  bool validate_search() {
    return !name.empty() || dump || chpass || enroll || slots || deauth >= 0;
  }
  bool validate_store_path() { return !store_path.empty(); }

  bool uses_writeops() const {
    return remove || update || chpass || enroll || deauth >= 0;
  }
  bool is_search() const { return !uses_writeops() && !dump && !slots; }

  std::string to_string() const {
    std::string s;
    s += "name: " + name + "\n";
    s += "meta: " + meta + "\n";
    s += "store_path: " + store_path + "\n";
    s += "chpass: " + std::to_string(chpass) + "\n";
    s += "dump: " + std::to_string(dump) + "\n";
    s += "remove: " + std::to_string(remove) + "\n";
    s += "read_only: " + std::to_string(read_only) + "\n";
    s += "update: " + std::to_string(update) + "\n";
    s += "enroll: " + std::to_string(enroll) + "\n";
    s += "slots: " + std::to_string(slots) + "\n";
    s += "deauth: " + std::to_string(deauth) + "\n";
    s += "force_password: " + std::to_string(force_password) + "\n";
    s += "drop_missing: " + std::to_string(drop_missing) + "\n";
    s += "is_search: " + std::to_string(is_search()) + "\n";
    s += "uses_writeops: " + std::to_string(uses_writeops()) + "\n";
    return s;
  }
};

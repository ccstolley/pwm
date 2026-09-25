#include "pwm.h"

inline constexpr std::string_view MAGIC{"Salted__"};
const int SALT_LENGTH = 32;
const int TAG_LENGTH = 16;
const int HDRSZ = MAGIC.size() + SALT_LENGTH + TAG_LENGTH;
const int PBKDF2_ITER_COUNT = 500000;

#if defined(HAVE_FIDO2) && !defined(TESTING)
#include <fido.h>
#endif

[[noreturn]] static void bail(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}

[[nodiscard]] static std::string store_path() {
  std::string store_path;
  if (const char *env_store = std::getenv("PWM_STORE")) {
    store_path = env_store;
  } else {
    const char *home = std::getenv("HOME");
    if (home == nullptr) {
      home = "";
    }
    store_path = home;
    store_path += "/.pwmstore";
  }
  return store_path;
}

[[noreturn]] static void usage() {
  bail("usage: pwm [-d | -C | -e <label> | -l | -R <slot> | -u <name> "
       "[<meta>...] | "
       "-r name | <pattern>]\n\n"
       "options:\n"
       "  -C  change master password on existing store (rotates the master "
       "key)\n"
       "  -d  dump all passwords to stderr\n"
       "  -e  enroll a FIDO2 security key with <label>\n"
       "  -l  list enrolled key slots\n"
       "  -F  when re-keying, drop any security key that cannot be reached "
       "instead\n      of aborting\n"
       "  -P  ignore any attached security key and use the master password\n"
       "  -p  Read password from stdin instead of randomly generating one, "
       "implies -u\n"
       "  -R  remove enrolled key slot by number (rotates the master key)\n"
       "  -u  create/update password with <name> and optional <meta> data\n"
       "  -r  remove password with <name>\n");
}

[[nodiscard]] static bool is_read_only() {
  auto v = std::getenv("PWM_READONLY");
  return v != nullptr && strncmp(v, "0", 1) != 0;
}

struct CmdFlags get_flags(int argc, char *const *argv) {
  struct CmdFlags f;
  int ch;

  f.read_only = is_read_only();
  f.store_path = store_path();
  optind = opterr = 1; // for tests
  std::vector<std::string> args;

  while ((ch = getopt(argc, argv, "-Cdle:FPR:urp")) != -1) {
    switch (ch) {
    case 'r':
      f.remove = true;
      break;
    case 'e':
      f.enroll = true;
      f.label = optarg;
      break;
    case 'l':
      f.slots = true;
      break;
    case 'F':
      f.drop_missing = true;
      break;
    case 'P':
      f.force_password = true;
      break;
    case 'R':
      f.deauth = atoi(optarg);
      if (f.deauth < 0) {
        bail("pwm: -R takes a key slot number (see pwm -E).");
      }
      break;
    case 'u':
      f.update = true;
      break;
    case 'd':
      f.dump = true;
      break;
    case 'C':
      f.chpass = true;
      break;
    case 'p':
      f.readpass = true;
      f.update = true;
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

/* True if mk opens this store's body; used to sanity check a cached key. */
static bool mk_opens(const std::string &ciphertext, const std::string &mk) {
  std::string probe;
  bool ok = mk.size() == MK_LENGTH && decrypt_store(ciphertext, mk, probe);
  if (!probe.empty()) {
    explicit_bzero(&probe[0], probe.size());
  }
  return ok;
}

/*
 * Recover the master key from any one enrolled factor.
 *
 * A security key is tried first when one is attached, since that needs no
 * typing; otherwise, or if it fails, we fall back to the password. Note that
 * unwrapping is itself authenticated, so a successful unwrap already proves the
 * factor was right and no separate verification step is needed.
 */
bool unlock_store(const std::string &ciphertext, const struct CmdFlags &f,
                  std::string &mk, StoreHeader &hdr) {
  if (!parse_header(ciphertext, hdr)) {
    return false;
  }

  bool has_fido = std::any_of(hdr.slots.begin(), hdr.slots.end(),
                              [](const KeySlot &s) { return s.is_fido(); });
  if (has_fido && !f.force_password && fido_present()) {
    std::string secret, cred_id, kek;
    if (fido_get_secret(hdr.slots, hdr.fido_salt, secret, cred_id)) {
      bool derived = fido_kek(secret, hdr.fido_salt, kek);
      explicit_bzero(&secret[0], secret.size());
      if (derived) {
        for (const auto &slot : hdr.slots) {
          if (slot.is_fido() && slot.cred_id == cred_id &&
              unwrap_mk(kek, slot, mk)) {
            explicit_bzero(&kek[0], kek.size());
            return true;
          }
        }
        explicit_bzero(&kek[0], kek.size());
      }
      fprintf(stderr, "security key did not unlock the store; "
                      "falling back to the password.\n");
    }
  }

  std::string key = f.key.empty() ? readpass("passphrase: ") : f.key;
  for (const auto &slot : hdr.slots) {
    if (!slot.is_password()) {
      continue;
    }
    std::string kek;
    if (!password_kek(key, slot.salt, slot.iter, kek)) {
      continue;
    }
    bool ok = unwrap_mk(kek, slot, mk);
    explicit_bzero(&kek[0], kek.size());
    if (ok) {
      explicit_bzero(&key[0], key.size());
      return true;
    }
  }
  explicit_bzero(&key[0], key.size());
  fprintf(stderr, "No enrolled factor unlocked the store.\n");
  return false;
}

/*
 * Open the store at f.store_path.
 */
static bool open_store(const struct CmdFlags &f, DataStore &ds) {
  const auto ciphertext = read_file(f.store_path);

  if (ciphertext.empty()) {
    bail("missing or corrupt store: %s", f.store_path.c_str());
  }

  if (is_v1_store(ciphertext)) {
    if (!unlock_store(ciphertext, f, ds.mk, ds.hdr)) {
      return false;
    }
    if (!decrypt_store(ciphertext, ds.mk, ds.data)) {
      fprintf(stderr, "Decrypt failed\n");
      return false;
    }
    return true;
  }

  // Legacy v0 store: the "master key" is PBKDF2 output used directly as key+iv,
  // so there is no MK to cache or wrap until the store is upgraded on write.
  ds.legacy = true;
  std::string key = f.key.empty() ? readpass("passphrase: ") : f.key;
  std::string dkeyiv;
  bool ok = derive_key(ciphertext, key, dkeyiv) &&
            decrypt(ciphertext, dkeyiv, ds.data);
  // Retained so that the upgrade on the next write can build a password slot.
  ds.mk = key;
  explicit_bzero(&key[0], key.size());
  explicit_bzero(&dkeyiv[0], dkeyiv.size());
  if (!ok) {
    fprintf(stderr, "Decrypt failed\n");
  }
  return ok;
}

/*
 * Re-key the store: a brand new MK, the body re-encrypted under it, and the new
 * MK wrapped under every surviving slot. This is what makes removal and -C
 * actual revocation rather than bookkeeping -- without it, an older copy of the
 * store file plus the removed factor still opens.
 *
 * Every wrapping parameter is regenerated here: a new store-wide fido_salt, a
 * new PBKDF2 salt for the password slot, and a new nonce for every wrap. Each
 * surviving slot's KEK is therefore unrelated to the one it replaces, rather
 * than merely being reused under a fresh nonce.
 *
 * The cost is that a FIDO2 slot's secret has to be recomputed under the new
 * salt, so every enrolled key must be present and touched. A key that cannot be
 * reached aborts the whole operation and leaves the store untouched, unless
 * drop_missing is set, in which case it is removed from the store and has to be
 * re-enrolled later. (That escape hatch is what lets you remove the last slot
 * of a key you no longer have.)
 */
bool rotate_mk(const std::string &plaintext, const std::string &new_password,
               StoreHeader &hdr, std::string &mk, std::string &ciphertext,
               bool drop_missing) {
  std::string new_mk = random_bytes(MK_LENGTH);
  const std::string new_salt = random_bytes(FIDO_SALT_LENGTH);
  std::vector<KeySlot> kept;
  size_t dropped = 0;

  for (auto &slot : hdr.slots) {
    if (slot.is_password()) {
      KeySlot fresh;
      // make_password_slot() draws a new PBKDF2 salt of its own.
      if (!make_password_slot(new_password, new_mk, fresh)) {
        return false;
      }
      kept.push_back(fresh);
      continue;
    }

    fprintf(stderr, "\nRe-authorizing %s\n",
            slot.describe(kept.size()).c_str());
    std::string secret, kek;
    if (!fido_secret_for_cred(slot.cred_id, new_salt, secret)) {
      if (!drop_missing) {
        fprintf(stderr,
                "  could not reach that security key.\n"
                "  re-keying needs every enrolled key present, because each "
                "one\n  has to be re-wrapped under a fresh salt.\n\n"
                "  attach it and try again, or re-run with -F to drop it from "
                "the store.\n");
        return false;
      }
      fprintf(stderr, "  could not reach that security key; dropping it.\n"
                      "  re-enroll it later with: pwm -e\n");
      dropped++;
      continue;
    }
    bool derived = fido_kek(secret, new_salt, kek);
    explicit_bzero(&secret[0], secret.size());
    if (!derived || !wrap_mk(kek, new_mk, slot)) {
      explicit_bzero(&kek[0], kek.size());
      return false;
    }
    explicit_bzero(&kek[0], kek.size());
    kept.push_back(slot);
  }

  if (dropped > 0) {
    fprintf(stderr, "\nWarning: dropped %zu security key(s).\n", dropped);
  }
  hdr.fido_salt = new_salt;
  hdr.slots = kept;
  if (!encrypt_store(plaintext, hdr, new_mk, ciphertext)) {
    return false;
  }
  explicit_bzero(&mk[0], mk.size());
  mk = new_mk;
  return true;
}

/* Write the store back out under the existing MK, keeping a backup. */
bool write_store(const std::string &plaintext, const DataStore &ds,
                 const std::string &path) {
  std::string ciphertext;
  if (!encrypt_store(plaintext, ds.hdr, ds.mk, ciphertext)) {
    return false;
  }
  return dump_to_file(ciphertext, path);
}

bool handle_search(const struct CmdFlags &f, Storage::Entry &entry) {
  DataStore ds;

  if (!open_store(f, ds)) {
    return false;
  }
  std::string &data = ds.data;

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
  return true;
}

bool handle_dump(const struct CmdFlags &f) {
  DataStore ds;

  if (!open_store(f, ds)) {
    return false;
  }
  if (!dump(ds.data)) {
    return false;
  }
  return true;
}

bool handle_slots(const struct CmdFlags &f) {
  const auto ciphertext = read_file(f.store_path);
  StoreHeader hdr;

  if (ciphertext.empty()) {
    bail("missing or corrupt store: %s", f.store_path.c_str());
  }
  if (!is_v1_store(ciphertext)) {
    fprintf(stderr,
            "%s is an old format store with a single password and no "
            "key slots.\n  run 'pwm -C' to upgrade it.\n",
            f.store_path.c_str());
    return true;
  }
  // Listing which factors are enrolled reveals nothing secret, so this needs no
  // authentication of its own.
  if (!parse_header(ciphertext, hdr)) {
    return false;
  }
  fprintf(stderr, "enrolled key slots in %s:\n", f.store_path.c_str());
  for (size_t i = 0; i < hdr.slots.size(); i++) {
    fprintf(stderr, "  %s\n", hdr.slots[i].describe(i).c_str());
  }
  return true;
}

bool handle_enroll(const struct CmdFlags &f) {
  DataStore ds;

  if (!fido_available()) {
    fprintf(stderr, "this build has no security key support.\n");
    return false;
  }
  // Enrolling changes which factors open the store, so it always re-authorizes
  // against an existing factor.
  if (!open_store(f, ds)) {
    return false;
  }
  if (ds.legacy) {
    fprintf(stderr, "upgrading %s to the key slot format.\n",
            f.store_path.c_str());
    std::string password = ds.mk;
    ds.hdr.fido_salt = random_bytes(FIDO_SALT_LENGTH);
    ds.hdr.slots.clear();
    ds.mk = random_bytes(MK_LENGTH);
    KeySlot pw;
    if (!make_password_slot(password, ds.mk, pw)) {
      return false;
    }
    explicit_bzero(&password[0], password.size());
    ds.hdr.slots.push_back(pw);
  }
  if (ds.hdr.slots.size() >= MAX_SLOTS) {
    fprintf(stderr, "error: already at the %zu key slot limit.\n", MAX_SLOTS);
    return false;
  }

  KeySlot slot;
  std::string secret, kek;
  slot.type = SLOT_FIDO2;
  slot.label = f.label.substr(0, MAX_LABEL);
  if (!fido_enroll(ds.hdr.fido_salt, slot.cred_id, secret)) {
    return false;
  }
  for (const auto &s : ds.hdr.slots) {
    if (s.is_fido() && s.cred_id == slot.cred_id) {
      fprintf(stderr, "that security key is already enrolled.\n");
      return false;
    }
  }
  bool derived = fido_kek(secret, ds.hdr.fido_salt, kek);
  explicit_bzero(&secret[0], secret.size());
  if (!derived || !wrap_mk(kek, ds.mk, slot)) {
    explicit_bzero(&kek[0], kek.size());
    return false;
  }
  explicit_bzero(&kek[0], kek.size());
  ds.hdr.slots.push_back(slot);

  if (!save_backup(f.store_path)) {
    bail("failed to save backup. aborting.");
  }
  if (!write_store(ds.data, ds, f.store_path)) {
    bail("failed to write updated store. backup saved.");
  }
  explicit_bzero(&ds.data[0], ds.data.size());
  fprintf(stderr, "\nEnrolled %s\n",
          slot.describe(ds.hdr.slots.size() - 1).c_str());
  fprintf(stderr, "This key can now open the store on its own.\n");
  return true;
}

bool handle_deauth(const struct CmdFlags &f) {
  DataStore ds;
  const size_t idx = static_cast<size_t>(f.deauth);

  // Validate the slot against the (unauthenticated, and already public via -E)
  // header first, so a bad slot number costs no password typing.
  {
    const auto ciphertext = read_file(f.store_path);
    StoreHeader hdr;
    if (ciphertext.empty()) {
      bail("missing or corrupt store: %s", f.store_path.c_str());
    }
    if (!is_v1_store(ciphertext)) {
      fprintf(stderr, "%s has no key slots to remove.\n", f.store_path.c_str());
      return false;
    }
    if (!parse_header(ciphertext, hdr)) {
      return false;
    }
    if (idx >= hdr.slots.size()) {
      fprintf(stderr, "error: no key slot %zu (store has %zu).\n", idx,
              hdr.slots.size());
      return false;
    }
    if (hdr.slots[idx].is_password()) {
      fprintf(stderr, "error: refusing to remove the password slot; it is the "
                      "recovery path. use -C to change the password.\n");
      return false;
    }
  }

  if (!open_store(f, ds)) {
    return false;
  }

  fprintf(stderr, "Removing %s\n", ds.hdr.slots[idx].describe(idx).c_str());
  ds.hdr.slots.erase(ds.hdr.slots.begin() + idx);

  // Removal has to rotate MK, or an older copy of the store file plus the
  // removed key would still open. That means every *surviving* security key has
  // to be touched so the new MK can be wrapped under it.
  std::string password =
      f.key.empty() ? readpass("passphrase (to re-wrap the password slot): ")
                    : f.key;
  std::string ciphertext;
  if (!rotate_mk(ds.data, password, ds.hdr, ds.mk, ciphertext,
                 f.drop_missing)) {
    explicit_bzero(&password[0], password.size());
    fprintf(stderr, "failed to rotate the master key; store left untouched.\n");
    return false;
  }
  explicit_bzero(&password[0], password.size());

  if (!save_backup(f.store_path)) {
    bail("failed to save backup. aborting.");
  }
  if (!dump_to_file(ciphertext, f.store_path)) {
    bail("failed to write updated store. backup saved.");
  }
  explicit_bzero(&ds.data[0], ds.data.size());
  fprintf(stderr,
          "\nKey slot removed and master key rotated.\n\nDelete the backup "
          "store\n  rm %s.bak\nso the removed key cannot open it.\n",
          f.store_path.c_str());
  return true;
}

bool handle_chpass(const struct CmdFlags &f) {
  DataStore ds;

  if (!open_store(f, ds)) {
    return false;
  }
  fprintf(stderr, "Resetting password for %s.\n", f.store_path.c_str());
  std::string key;
  if (f.newkey.empty()) {
    key = readpass("set root passphrase: ");
    if (key != readpass(" confirm passphrase: ")) {
      bail("passwords didn't match.");
    }
  } else {
    key = f.newkey;
  }

  if (ds.legacy) {
    fprintf(stderr, "upgrading %s to the key slot format.\n",
            f.store_path.c_str());
    ds.hdr.fido_salt = random_bytes(FIDO_SALT_LENGTH);
    ds.hdr.slots.assign(1, KeySlot{});
    ds.mk = random_bytes(MK_LENGTH);
  }

  // -C always rotates MK, so that the old password cannot open even an older
  // copy of the store file.
  std::string ciphertext;
  if (!rotate_mk(ds.data, key, ds.hdr, ds.mk, ciphertext, f.drop_missing)) {
    explicit_bzero(&key[0], key.size());
    fprintf(stderr, "failed to re-key the store; store left untouched.\n");
    return false;
  }
  explicit_bzero(&key[0], key.size());

  if (!save_backup(f.store_path)) {
    bail("failed to save backup. aborting.");
  }
  if (!dump_to_file(ciphertext, f.store_path)) {
    bail("failed to write updated store. backup saved.");
  }
  explicit_bzero(&ds.data[0], ds.data.size());
  fprintf(stderr,
          "\nMaster password updated and master key rotated.\n\nDelete the "
          "backup store\n  rm %s.bak\nif your old password was compromised.\n",
          f.store_path.c_str());

  return true;
}

bool handle_update(const struct CmdFlags &f, Storage::Entry &entry) {
  DataStore ds;
  bool init_new = read_file(f.store_path).empty();

  if (init_new) {
    fprintf(stderr, "Initializing new password store.\n");
    std::string key = f.key;
    if (key.empty()) {
      key = readpass("set root passphrase: ");
      if (key != readpass(" confirm passphrase: ")) {
        bail("passwords didn't match.");
      }
    }
    ds.hdr.fido_salt = random_bytes(FIDO_SALT_LENGTH);
    ds.mk = random_bytes(MK_LENGTH);
    KeySlot pw;
    if (!make_password_slot(key, ds.mk, pw)) {
      bail("failed to derive a key from the passphrase.");
    }
    explicit_bzero(&key[0], key.size());
    ds.hdr.slots.push_back(pw);
  } else {
    if (!open_store(f, ds)) {
      return false;
    }
  }
  std::string &data = ds.data;
  entry.name = f.name;
  entry.meta = f.meta;
  entry.updated_at = time(nullptr);
  if (f.readpass) {
    if (!f.password.empty()) {
      // for tests
      entry.password = f.password;
    } else {
      entry.password = readpass("set passphrase: ");
    }
  } else {
    entry.password = random_str(15);
  }
  std::string newdata;
  if (!update(data, entry, newdata, f.remove)) {
    bail("%s failed.", f.remove ? "remove" : "update");
  }
  data.clear();

  if (ds.legacy) {
    // First write to an old format store upgrades it in place, carrying the
    // existing password over into the store's one password slot.
    fprintf(stderr, "upgrading %s to the key slot format.\n",
            f.store_path.c_str());
    std::string password = ds.mk;
    ds.hdr.fido_salt = random_bytes(FIDO_SALT_LENGTH);
    ds.hdr.slots.clear();
    ds.mk = random_bytes(MK_LENGTH);
    KeySlot pw;
    if (!make_password_slot(password, ds.mk, pw)) {
      bail("failed to upgrade the store.");
    }
    explicit_bzero(&password[0], password.size());
    ds.hdr.slots.push_back(pw);
  }

  if (!init_new && !save_backup(f.store_path)) {
    bail("failed to save backup. aborting.");
  }

  newdata = sort_data(newdata);
  if (!write_store(newdata, ds, f.store_path)) {
    bail("failed to write updated store.");
  }
  explicit_bzero(&newdata[0], newdata.size());
  if (f.update) {
    fprintf(stderr, "\n%s: %s\n", entry.name.c_str(), entry.meta.c_str());
    printf("%s\n", entry.password.c_str());
  } else {
    fprintf(stderr, "\n%s: removed\n", entry.name.c_str());
  }
  return true;
}

#ifndef TESTING
int main(int argc, char **argv) {
  Storage::Entry entry;
  auto f = get_flags(argc, argv);
  entry.name = f.name;
  entry.meta = f.meta;

  // libfido2 talks to /dev/fido/* on OpenBSD, which needs wpath even when the
  // store itself is only being read.
#ifdef HAVE_FIDO2
  const char *read_promises = "proc unix inet stdio tty rpath wpath fattr";
#else
  const char *read_promises = "proc unix inet stdio tty rpath fattr";
#endif
  if (f.uses_writeops()) {
    if (pledge("proc unix inet stdio tty fattr cpath rpath wpath", NULL) != 0) {
      bail("pledge(2) failed at %d.", __LINE__);
    }
  } else {
    if (pledge(read_promises, NULL) != 0) {
      bail("pledge(2) failed at %d.", __LINE__);
    }
  }

  if (f.is_search()) {
    return !handle_search(f, entry);
  } else if (f.update || f.remove) {
    return !handle_update(f, entry);
  } else if (f.dump) {
    return !handle_dump(f);
  } else if (f.chpass) {
    return !handle_chpass(f);
  } else if (f.enroll) {
    return !handle_enroll(f);
  } else if (f.slots) {
    return !handle_slots(f);
  } else if (f.deauth >= 0) {
    return !handle_deauth(f);
  }
  // should never happen
  usage();
  return 0;
}
#endif // TESTING

bool dump(const std::string &data) {
  Storage sto{data};

  for (Storage::Entry ent; sto.next(ent);) {
    fprintf(stderr, "%s\n", ent.to_string().c_str());
  }
  return true;
}

bool update(const std::string &data, const Storage::Entry &newent,
            std::string &revised, bool remove) {
  Storage sto{data};
  std::ostringstream editstream{};
  bool already_found = false;
  bool exact = false;

  for (Storage::Entry entry; sto.next(entry);) {
    if (newent.name == entry.name.substr(0, newent.name.size())) {
      if (already_found) {
        if (!exact) {
          fprintf(stderr, "error: '%s' also matches '%s'.\n",
                  entry.name.c_str(), newent.name.c_str());
          return false;
        }
      } else {
        fprintf(stderr, "[old] %s: %s\n", entry.name.c_str(),
                entry.password.c_str());
        exact = newent.name == entry.name;
        already_found = true;
        if (remove) {
          continue;
        }
        if (!newent.meta.empty()) {
          entry.meta = newent.meta;
        }
        if (!newent.password.empty()) {
          entry.password = newent.password;
        }
        entry.updated_at = newent.updated_at;
      }
    }
    std::string s{Storage::serialize(entry)};
    editstream.write(s.data(), s.size());
  }

  if (!already_found) {
    if (remove) {
      return false;
    }
    // add
    std::string s{Storage::serialize(newent)};
    editstream.write(s.data(), s.size());
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
  if (auto f = fopen(path.c_str(), "r"); f != nullptr) {
    struct stat sb;
    if (fstat(fileno(f), &sb) == -1) {
      fclose(f);
      bail("can't fstat file: %s", path.c_str());
    }
    if ((sb.st_mode & S_IRWXG) || (sb.st_mode & S_IRWXO)) {
      if (0 != fchmod(fileno(f), S_IRUSR | S_IWUSR)) {
        fclose(f);
        bail("%s\n   must be read/writeable by owner only.", path.c_str());
      }
      chmod((path + ".bak").c_str(), S_IRUSR | S_IWUSR); // best effort
    }
    fclose(f);
  } else {
    bail("no such file: %s", path.c_str());
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
  std::vector<Storage::Entry> datav;

  Storage sto{data};
  for (Storage::Entry ent; sto.next(ent);) {
    datav.push_back(ent);
  }
  std::sort(datav.begin(), datav.end(),
            [](const Storage::Entry &a, const Storage::Entry &b) {
              return a.name < b.name;
            });

  std::ostringstream outs;
  for (const auto &e : datav) {
    std::string s{Storage::serialize(e)};
    outs.write(s.data(), s.size());
  }
  return outs.str();
}

bool dump_to_file(const std::string &data, const std::string &filename) {
  umask(077); // rw by owner only

  std::ofstream out(filename, std::ios::binary);
  if (!out) {
    return false;
  }
  out.write(data.data(), static_cast<long>(sizeof(char) * data.size()));
  return out.good();
}

bool search(const std::string &needle, const std::string &haystack,
            Storage::Entry &entry) {
  bool found = false;
  bool exact = false;

  Storage sto{haystack};
  for (Storage::Entry match; sto.next(match);) {
    if (needle != match.name.substr(0, needle.size())) {
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

std::string dump_entry(const Storage::Entry &entry) {
  std::string s(entry.name);
  return s + ": " + (entry.meta.empty() ? "" : entry.meta + " ") +
         (entry.updated_at ? std::to_string(entry.updated_at) + " " : "") +
         entry.password + "\n";
}

std::string readpass(const std::string &prompt) {
  char key[EVP_MAX_KEY_LENGTH + 1] = {0};

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

  std::string s(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
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

  std::string s(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
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

/* ==================== v1 keyslot store ==================== */

std::string random_bytes(size_t sz) {
  std::string s(sz, '\0');
  arc4random_buf(&s[0], s.size());
  return s;
}

static void put_u16(std::string &out, uint16_t v) {
  uint16_t n = htons(v);
  out.append(reinterpret_cast<const char *>(&n), sizeof(n));
}

static void put_u32(std::string &out, uint32_t v) {
  uint32_t n = htonl(v);
  out.append(reinterpret_cast<const char *>(&n), sizeof(n));
}

/* Bounds checked cursor over a serialized store. */
struct Cursor {
  std::string_view buf;
  size_t pos = 0;
  bool ok = true;

  bool take(size_t n, std::string &out) {
    if (!ok || pos + n > buf.size()) {
      return ok = false;
    }
    out.assign(buf.substr(pos, n));
    pos += n;
    return true;
  }
  bool skip(size_t n) {
    if (!ok || pos + n > buf.size()) {
      return ok = false;
    }
    pos += n;
    return true;
  }
  bool u8(uint8_t &v) {
    std::string s;
    if (!take(1, s)) {
      return false;
    }
    v = static_cast<uint8_t>(s[0]);
    return true;
  }
  bool u16(uint16_t &v) {
    std::string s;
    if (!take(2, s)) {
      return false;
    }
    v = ntohs(*reinterpret_cast<const uint16_t *>(s.data()));
    return true;
  }
  bool u32(uint32_t &v) {
    std::string s;
    if (!take(4, s)) {
      return false;
    }
    v = ntohl(*reinterpret_cast<const uint32_t *>(s.data()));
    return true;
  }
  bool lenpfx(std::string &out) {
    uint16_t n = 0;
    return u16(n) && take(n, out);
  }
};

std::string KeySlot::describe(size_t idx) const {
  std::string s = "[" + std::to_string(idx) + "] ";
  if (is_password()) {
    return s + "password (pbkdf2, " + std::to_string(iter) + " iterations)";
  }
  s += "security key";
  if (!label.empty()) {
    s += " \"" + label + "\"";
  }
  // credential ids are long; a short prefix is enough to tell slots apart.
  s += " cred:";
  for (size_t i = 0; i < 6 && i < cred_id.size(); i++) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned char>(cred_id[i]));
    s += hex;
  }
  return s;
}

bool is_v1_store(const std::string &ciphertext) {
  return ciphertext.size() >= MAGIC_V1.size() &&
         ciphertext.compare(0, MAGIC_V1.size(), MAGIC_V1) == 0;
}

/* The bytes a slot's wrap is authenticated against: its type and its extra
 * fields. Binds a cred_id (or salt/iter) to the MK wrapped beside it. */
static std::string slot_aad(const KeySlot &slot) {
  std::string aad(1, static_cast<char>(slot.type));
  if (slot.is_password()) {
    aad += slot.salt;
    put_u32(aad, slot.iter);
  } else {
    put_u16(aad, slot.cred_id.size());
    aad += slot.cred_id;
    put_u16(aad, slot.label.size());
    aad += slot.label;
  }
  return aad;
}

static std::string serialize_slot(const KeySlot &slot) {
  std::string payload;
  payload += slot.wrap_nonce;
  payload += slot.wrap_tag;
  payload += slot.wrapped_mk;
  if (slot.is_password()) {
    payload += slot.salt;
    put_u32(payload, slot.iter);
  } else {
    put_u16(payload, slot.cred_id.size());
    payload += slot.cred_id;
    put_u16(payload, slot.label.size());
    payload += slot.label;
  }
  std::string out(1, static_cast<char>(slot.type));
  put_u16(out, payload.size());
  out += payload;
  return out;
}

std::string serialize_header(const StoreHeader &hdr) {
  std::string out{MAGIC_V1};
  out += static_cast<char>(STORE_VERSION);
  out += hdr.fido_salt;
  out += static_cast<char>(hdr.slots.size());
  for (const auto &slot : hdr.slots) {
    out += serialize_slot(slot);
  }
  return out;
}

bool parse_header(const std::string &ciphertext, StoreHeader &hdr) {
  Cursor c{ciphertext};
  hdr.slots.clear();

  if (!c.skip(MAGIC_V1.size()) || !is_v1_store(ciphertext)) {
    fprintf(stderr, "error: not a v1 password store.\n");
    return false;
  }
  uint8_t version = 0;
  if (!c.u8(version)) {
    fprintf(stderr, "error: corrupt password store (truncated header).\n");
    return false;
  }
  if (version != STORE_VERSION) {
    fprintf(stderr, "error: unsupported store version %u (expected %u).\n",
            version, STORE_VERSION);
    return false;
  }
  uint8_t count = 0;
  if (!c.take(FIDO_SALT_LENGTH, hdr.fido_salt) || !c.u8(count)) {
    fprintf(stderr, "error: corrupt password store (truncated header).\n");
    return false;
  }
  if (count == 0 || count > MAX_SLOTS) {
    fprintf(stderr, "error: corrupt password store (%u key slots).\n", count);
    return false;
  }

  for (uint8_t i = 0; i < count; i++) {
    KeySlot slot;
    uint16_t payload_len = 0;
    if (!c.u8(slot.type) || !c.u16(payload_len)) {
      fprintf(stderr, "error: corrupt key slot %u.\n", i);
      return false;
    }
    const size_t end = c.pos + payload_len;
    if (end > ciphertext.size()) {
      fprintf(stderr, "error: key slot %u overruns the store.\n", i);
      return false;
    }
    if (!c.take(GCM_NONCE_LENGTH, slot.wrap_nonce) ||
        !c.take(TAG_LENGTH, slot.wrap_tag) ||
        !c.take(MK_LENGTH, slot.wrapped_mk)) {
      fprintf(stderr, "error: corrupt key slot %u.\n", i);
      return false;
    }
    if (slot.type == SLOT_PASSWORD) {
      if (!c.take(SALT_LENGTH, slot.salt) || !c.u32(slot.iter)) {
        fprintf(stderr, "error: corrupt password slot %u.\n", i);
        return false;
      }
    } else if (slot.type == SLOT_FIDO2) {
      if (!c.lenpfx(slot.cred_id) || !c.lenpfx(slot.label)) {
        fprintf(stderr, "error: corrupt security key slot %u.\n", i);
        return false;
      }
    } else {
      fprintf(stderr, "error: unknown key slot type %u in slot %u.\n",
              slot.type, i);
      return false;
    }
    if (c.pos != end) {
      fprintf(stderr, "error: key slot %u has trailing garbage.\n", i);
      return false;
    }
    hdr.slots.push_back(slot);
  }

  hdr.body_off = c.pos;
  hdr.aad = ciphertext.substr(0, c.pos);
  if (ciphertext.size() < hdr.body_off + GCM_NONCE_LENGTH + TAG_LENGTH) {
    fprintf(stderr, "error: corrupt password store (truncated body).\n");
    return false;
  }
  return true;
}

/*
 * AES-256-GCM in one shot. nonce must be unique for every call made under a
 * given key; callers generate a fresh random one each time.
 */
static bool aead_seal(const std::string &key, const std::string &nonce,
                      const std::string &aad, const std::string &plaintext,
                      std::string &ciphertext, std::string &tag) {
  EvpCipherContext ctx;
  int sz = 0;

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                          NULL) != 1 ||
      EVP_EncryptInit_ex(
          ctx.get(), NULL, NULL,
          reinterpret_cast<const unsigned char *>(key.data()),
          reinterpret_cast<const unsigned char *>(nonce.data())) != 1) {
    fprintf(stderr, "failed to init cipher for seal\n");
    return false;
  }
  if (!aad.empty() &&
      EVP_EncryptUpdate(ctx.get(), NULL, &sz,
                        reinterpret_cast<const unsigned char *>(aad.data()),
                        aad.size()) != 1) {
    fprintf(stderr, "failed to add associated data\n");
    return false;
  }
  std::string out(plaintext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
  ciphertext.clear();
  if (EVP_EncryptUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &sz,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          plaintext.size()) != 1) {
    fprintf(stderr, "EncryptUpdate() failed\n");
    return false;
  }
  ciphertext.append(out, 0, sz);
  if (EVP_EncryptFinal_ex(
          ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &sz) != 1) {
    fprintf(stderr, "EncryptFinal() failed\n");
    return false;
  }
  ciphertext.append(out, 0, sz);

  tag.assign(TAG_LENGTH, '\0');
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LENGTH,
                          &tag[0]) != 1) {
    fprintf(stderr, "GCM get tag failed\n");
    return false;
  }
  return true;
}

static bool aead_open(const std::string &key, const std::string &nonce,
                      const std::string &aad, const std::string &ciphertext,
                      const std::string &tag, std::string &plaintext) {
  EvpCipherContext ctx;
  int sz = 0;

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                          NULL) != 1 ||
      EVP_DecryptInit_ex(
          ctx.get(), NULL, NULL,
          reinterpret_cast<const unsigned char *>(key.data()),
          reinterpret_cast<const unsigned char *>(nonce.data())) != 1) {
    fprintf(stderr, "failed to init cipher for open\n");
    return false;
  }
  if (!aad.empty() &&
      EVP_DecryptUpdate(ctx.get(), NULL, &sz,
                        reinterpret_cast<const unsigned char *>(aad.data()),
                        aad.size()) != 1) {
    fprintf(stderr, "failed to add associated data\n");
    return false;
  }
  std::string out(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, '\0');
  std::string tmp;
  if (EVP_DecryptUpdate(
          ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &sz,
          reinterpret_cast<const unsigned char *>(ciphertext.data()),
          ciphertext.size()) != 1) {
    return false;
  }
  tmp.append(out, 0, sz);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LENGTH,
                          const_cast<char *>(tag.data())) != 1) {
    fprintf(stderr, "failed to set GCM tag\n");
    return false;
  }
  // Fails on a bad key, a bad tag, or any tampering with the AAD.
  if (EVP_DecryptFinal_ex(
          ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &sz) != 1) {
    explicit_bzero(&tmp[0], tmp.size());
    return false;
  }
  tmp.append(out, 0, sz);
  plaintext = tmp;
  return true;
}

bool password_kek(const std::string &password, const std::string &salt,
                  uint32_t iter, std::string &kek) {
  kek.assign(MK_LENGTH, '\0');
  if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                        reinterpret_cast<const unsigned char *>(salt.data()),
                        salt.size(), iter, EVP_sha256(), kek.size(),
                        reinterpret_cast<unsigned char *>(&kek[0])) != 1) {
    fprintf(stderr, "failed to derive key from password\n");
    return false;
  }
  return true;
}

/*
 * Turn a token's hmac-secret output into a wrapping key. The secret is already
 * 32 uniformly random bytes, so no iterated KDF is needed or useful here; this
 * is HKDF-Extract, written with plain HMAC because OpenSSL and LibreSSL expose
 * HKDF itself through incompatible interfaces.
 */
bool fido_kek(const std::string &secret, const std::string &fido_salt,
              std::string &kek) {
  std::string msg = secret + std::string(FIDO_KEK_INFO);
  unsigned int len = 0;
  kek.assign(EVP_MAX_MD_SIZE, '\0');
  if (HMAC(EVP_sha256(),
           reinterpret_cast<const unsigned char *>(fido_salt.data()),
           fido_salt.size(),
           reinterpret_cast<const unsigned char *>(msg.data()), msg.size(),
           reinterpret_cast<unsigned char *>(&kek[0]), &len) == nullptr) {
    fprintf(stderr, "failed to derive key from security key secret\n");
    return false;
  }
  explicit_bzero(&msg[0], msg.size());
  kek.resize(MK_LENGTH);
  return true;
}

bool wrap_mk(const std::string &kek, const std::string &mk, KeySlot &slot) {
  if (mk.size() != MK_LENGTH) {
    fprintf(stderr, "refusing to wrap a master key of %zu bytes\n", mk.size());
    return false;
  }
  // INVARIANT: a fresh nonce on every wrap, even when the salt (and therefore
  // the KEK) is carried over from the slot being replaced.
  slot.wrap_nonce = random_bytes(GCM_NONCE_LENGTH);
  return aead_seal(kek, slot.wrap_nonce, slot_aad(slot), mk, slot.wrapped_mk,
                   slot.wrap_tag);
}

bool unwrap_mk(const std::string &kek, const KeySlot &slot, std::string &mk) {
  return aead_open(kek, slot.wrap_nonce, slot_aad(slot), slot.wrapped_mk,
                   slot.wrap_tag, mk);
}

bool make_password_slot(const std::string &password, const std::string &mk,
                        KeySlot &slot) {
  std::string kek;
  slot.type = SLOT_PASSWORD;
  slot.salt = random_bytes(SALT_LENGTH);
  slot.iter = PBKDF2_ITER_COUNT;
  if (!password_kek(password, slot.salt, slot.iter, kek)) {
    return false;
  }
  bool ok = wrap_mk(kek, mk, slot);
  explicit_bzero(&kek[0], kek.size());
  return ok;
}

bool encrypt_store(const std::string &plaintext, const StoreHeader &hdr,
                   const std::string &mk, std::string &ciphertext) {
  if (hdr.slots.empty() || hdr.slots.size() > MAX_SLOTS) {
    fprintf(stderr, "error: refusing to write %zu key slots.\n",
            hdr.slots.size());
    return false;
  }
  std::string header = serialize_header(hdr);
  std::string nonce = random_bytes(GCM_NONCE_LENGTH);
  std::string body, tag;

  if (!aead_seal(mk, nonce, header, plaintext, body, tag)) {
    return false;
  }
  ciphertext = header + nonce + tag + body;
  return true;
}

bool decrypt_store(const std::string &ciphertext, const std::string &mk,
                   std::string &plaintext) {
  StoreHeader hdr;
  if (!parse_header(ciphertext, hdr)) {
    return false;
  }
  const size_t body_start = hdr.body_off + GCM_NONCE_LENGTH + TAG_LENGTH;
  if (body_start > ciphertext.size()) {
    fprintf(stderr, "error: corrupt password store (truncated body).\n");
    return false;
  }

  const std::string nonce = ciphertext.substr(hdr.body_off, GCM_NONCE_LENGTH);
  const std::string tag =
      ciphertext.substr(hdr.body_off + GCM_NONCE_LENGTH, TAG_LENGTH);
  const std::string body =
      ciphertext.substr(hdr.body_off + GCM_NONCE_LENGTH + TAG_LENGTH);
  return aead_open(mk, nonce, hdr.aad, body, tag, plaintext);
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

/* ==================== FIDO2 security keys ==================== */

/*
 * Enrolled credentials are non-resident: the credential id lives in the store
 * header, not on the token, so a token holds no per-store state and its slot
 * count is unlimited. The secret behind each slot comes from the hmac-secret
 * extension, which returns a stable 32 bytes for a given (credential, salt)
 * pair and never leaves the device otherwise.
 */

#ifdef TESTING
/*
 * Tests run without hardware, so a simulated authenticator stands in. It
 * mimics the property the real thing provides: a stable secret per credential,
 * salted store-wide. Only compiled under -DTESTING.
 */
std::vector<std::pair<std::string, std::string>> g_fake_tokens;
bool g_fake_token_present = true;

static bool fake_secret(const std::string &cred_id, const std::string &salt,
                        std::string &secret) {
  for (const auto &[id, seed] : g_fake_tokens) {
    if (id != cred_id) {
      continue;
    }
    unsigned int len = 0;
    secret.assign(EVP_MAX_MD_SIZE, '\0');
    HMAC(EVP_sha256(), reinterpret_cast<const unsigned char *>(seed.data()),
         seed.size(), reinterpret_cast<const unsigned char *>(salt.data()),
         salt.size(), reinterpret_cast<unsigned char *>(&secret[0]), &len);
    secret.resize(FIDO_SECRET_LENGTH);
    return true;
  }
  return false;
}

bool fido_available() { return true; }
bool fido_present() { return g_fake_token_present && !g_fake_tokens.empty(); }

bool fido_secret_for_cred(const std::string &cred_id,
                          const std::string &fido_salt, std::string &secret) {
  return fido_present() && fake_secret(cred_id, fido_salt, secret);
}

bool fido_get_secret(const std::vector<KeySlot> &slots,
                     const std::string &fido_salt, std::string &secret,
                     std::string &cred_id) {
  if (!fido_present()) {
    return false;
  }
  for (const auto &slot : slots) {
    if (slot.is_fido() && fake_secret(slot.cred_id, fido_salt, secret)) {
      cred_id = slot.cred_id;
      return true;
    }
  }
  return false;
}

bool fido_enroll(const std::string &fido_salt, std::string &cred_id,
                 std::string &secret) {
  cred_id = random_bytes(32);
  g_fake_tokens.emplace_back(cred_id, random_bytes(32));
  return fake_secret(cred_id, fido_salt, secret);
}

#elif !defined(HAVE_FIDO2)

bool fido_available() { return false; }
bool fido_present() { return false; }

static void no_fido() {
  fprintf(stderr, "pwm was built without libfido2 support; rebuild with "
                  "HAVE_FIDO2 to use security keys.\n");
}

bool fido_get_secret(const std::vector<KeySlot> &, const std::string &,
                     std::string &, std::string &) {
  no_fido();
  return false;
}

bool fido_secret_for_cred(const std::string &, const std::string &,
                          std::string &) {
  no_fido();
  return false;
}

bool fido_enroll(const std::string &, std::string &, std::string &) {
  no_fido();
  return false;
}

#else // HAVE_FIDO2

// We never verify an attestation signature or an assertion signature against a
// relying party, so there is no meaningful client data to bind; a fixed value
// keeps the wire format stable.
static const unsigned char FIDO_CLIENTDATA[32] = {0};

struct FidoDev {
  fido_dev_t *dev = nullptr;
  bool opened = false;

  ~FidoDev() {
    if (dev != nullptr) {
      if (opened) {
        fido_dev_close(dev);
      }
      fido_dev_free(&dev);
    }
  }
  bool open(const char *path) {
    if ((dev = fido_dev_new()) == nullptr) {
      return false;
    }
    int r = fido_dev_open(dev, path);
    if (r != FIDO_OK) {
      fprintf(stderr, "failed to open %s: %s\n", path, fido_strerr(r));
      return false;
    }
    return opened = true;
  }
};

struct FidoAssert {
  fido_assert_t *a = fido_assert_new();
  ~FidoAssert() {
    if (a != nullptr) {
      fido_assert_free(&a);
    }
  }
};

struct FidoCred {
  fido_cred_t *c = fido_cred_new();
  ~FidoCred() {
    if (c != nullptr) {
      fido_cred_free(&c);
    }
  }
};

struct FidoDevList {
  fido_dev_info_t *list = nullptr;
  size_t n = 0;   // devices actually found
  size_t cap = 0; // devices allocated for

  explicit FidoDevList(size_t max = 8) {
    if ((list = fido_dev_info_new(max)) == nullptr) {
      return;
    }
    cap = max;
    if (fido_dev_info_manifest(list, max, &n) != FIDO_OK) {
      n = 0;
    }
  }
  ~FidoDevList() {
    if (list != nullptr) {
      // must match what fido_dev_info_new() allocated, not what was found
      fido_dev_info_free(&list, cap);
    }
  }
  const char *path(size_t i) const {
    return fido_dev_info_path(fido_dev_info_ptr(list, i));
  }
};

static bool fido_init_once() {
  static bool done = false;
  if (!done) {
    fido_init(0);
    done = true;
  }
  return true;
}

bool fido_available() { return true; }

// Enumerating devices needs no user interaction, so this is safe to call before
// deciding whether to prompt for a touch or fall back to the password.
bool fido_present() {
  fido_init_once();
  FidoDevList devs;
  return devs.n > 0;
}

static bool needs_pin(int r) {
  return r == FIDO_ERR_PIN_REQUIRED || r == FIDO_ERR_PIN_INVALID ||
         r == FIDO_ERR_UV_INVALID || r == FIDO_ERR_UV_BLOCKED ||
         r == FIDO_ERR_PIN_AUTH_INVALID;
}

/*
 * Run one assertion against a single device over an allow-list of credentials.
 * The device asserts whichever credential it actually holds, so a store with
 * several enrolled keys still costs exactly one touch. Returns FIDO_OK and
 * fills in secret/cred_id on success.
 */
static int assert_on_dev(fido_dev_t *dev, const std::vector<std::string> &creds,
                         const std::string &fido_salt, std::string &secret,
                         std::string &cred_id, std::string &pin) {
  FidoAssert as;
  int r;

  if (as.a == nullptr) {
    return FIDO_ERR_INTERNAL;
  }
  if ((r = fido_assert_set_clientdata_hash(
           as.a, FIDO_CLIENTDATA, sizeof(FIDO_CLIENTDATA))) != FIDO_OK ||
      (r = fido_assert_set_rp(as.a, std::string(FIDO_RP_ID).c_str())) !=
          FIDO_OK ||
      (r = fido_assert_set_extensions(as.a, FIDO_EXT_HMAC_SECRET)) != FIDO_OK ||
      (r = fido_assert_set_hmac_salt(
           as.a, reinterpret_cast<const unsigned char *>(fido_salt.data()),
           fido_salt.size())) != FIDO_OK) {
    fprintf(stderr, "failed to build assertion: %s\n", fido_strerr(r));
    return r;
  }
  for (const auto &id : creds) {
    if ((r = fido_assert_allow_cred(
             as.a, reinterpret_cast<const unsigned char *>(id.data()),
             id.size())) != FIDO_OK) {
      fprintf(stderr, "failed to add credential: %s\n", fido_strerr(r));
      return r;
    }
  }

  r = fido_dev_get_assert(dev, as.a, pin.empty() ? nullptr : pin.c_str());
  if (needs_pin(r) && fido_dev_has_pin(dev)) {
    pin = readpass("security key PIN: ");
    r = fido_dev_get_assert(dev, as.a, pin.c_str());
  }
  if (r != FIDO_OK) {
    return r;
  }
  if (fido_assert_count(as.a) < 1) {
    return FIDO_ERR_NO_CREDENTIALS;
  }

  const unsigned char *sec = fido_assert_hmac_secret_ptr(as.a, 0);
  size_t seclen = fido_assert_hmac_secret_len(as.a, 0);
  if (sec == nullptr || seclen != FIDO_SECRET_LENGTH) {
    fprintf(stderr, "security key did not return an hmac-secret; is the "
                    "extension supported?\n");
    return FIDO_ERR_UNSUPPORTED_EXTENSION;
  }
  secret.assign(reinterpret_cast<const char *>(sec), seclen);

  // Which credential answered tells us which slot to unwrap.
  const unsigned char *id = fido_assert_id_ptr(as.a, 0);
  size_t idlen = fido_assert_id_len(as.a, 0);
  if (id != nullptr && idlen > 0) {
    cred_id.assign(reinterpret_cast<const char *>(id), idlen);
  } else if (creds.size() == 1) {
    cred_id = creds.front();
  } else {
    fprintf(stderr, "security key did not identify which credential it used\n");
    return FIDO_ERR_INTERNAL;
  }
  return FIDO_OK;
}

static bool fido_assert_creds(const std::vector<std::string> &creds,
                              const std::string &fido_salt, std::string &secret,
                              std::string &cred_id) {
  fido_init_once();
  if (creds.empty()) {
    return false;
  }
  FidoDevList devs;
  if (devs.n == 0) {
    fprintf(stderr, "no security key found.\n");
    return false;
  }

  fprintf(stderr, "touch your security key...\n");
  bool unenrolled = false;
  for (size_t i = 0; i < devs.n; i++) {
    FidoDev fd;
    std::string pin;
    if (!fd.open(devs.path(i))) {
      continue;
    }
    int r = assert_on_dev(fd.dev, creds, fido_salt, secret, cred_id, pin);
    explicit_bzero(&pin[0], pin.size());
    if (r == FIDO_OK) {
      return true;
    }
    // A key that holds none of these credentials is not an error worth
    // reporting when several devices are attached; keep looking.
    if (r == FIDO_ERR_NO_CREDENTIALS) {
      unenrolled = true;
    } else {
      fprintf(stderr, "security key failed: %s\n", fido_strerr(r));
    }
  }
  if (unenrolled) {
    fprintf(stderr, "that security key is not enrolled in this store.\n");
  }
  return false;
}

bool fido_get_secret(const std::vector<KeySlot> &slots,
                     const std::string &fido_salt, std::string &secret,
                     std::string &cred_id) {
  std::vector<std::string> creds;
  for (const auto &slot : slots) {
    if (slot.is_fido()) {
      creds.push_back(slot.cred_id);
    }
  }
  return fido_assert_creds(creds, fido_salt, secret, cred_id);
}

bool fido_secret_for_cred(const std::string &cred_id,
                          const std::string &fido_salt, std::string &secret) {
  std::string got;
  return fido_assert_creds({cred_id}, fido_salt, secret, got);
}

bool fido_enroll(const std::string &fido_salt, std::string &cred_id,
                 std::string &secret) {
  fido_init_once();
  FidoDevList devs;
  if (devs.n == 0) {
    fprintf(stderr, "no security key found. insert one and try again.\n");
    return false;
  }
  if (devs.n > 1) {
    fprintf(stderr, "more than one security key attached; leave only the one "
                    "you want to enroll.\n");
    return false;
  }

  FidoDev fd;
  if (!fd.open(devs.path(0))) {
    return false;
  }
  if (!fido_dev_is_fido2(fd.dev)) {
    fprintf(stderr,
            "device is U2F only; FIDO2 with hmac-secret is required.\n");
    return false;
  }

  FidoCred cred;
  int r;
  const std::string user_id = random_bytes(32);
  if (cred.c == nullptr) {
    return false;
  }
  if ((r = fido_cred_set_type(cred.c, COSE_ES256)) != FIDO_OK ||
      (r = fido_cred_set_clientdata_hash(cred.c, FIDO_CLIENTDATA,
                                         sizeof(FIDO_CLIENTDATA))) != FIDO_OK ||
      (r = fido_cred_set_rp(cred.c, std::string(FIDO_RP_ID).c_str(), "pwm")) !=
          FIDO_OK ||
      (r = fido_cred_set_user(
           cred.c, reinterpret_cast<const unsigned char *>(user_id.data()),
           user_id.size(), "pwm", nullptr, nullptr)) != FIDO_OK ||
      (r = fido_cred_set_extensions(cred.c, FIDO_EXT_HMAC_SECRET)) != FIDO_OK ||
      // non-resident: the credential id is kept in the store header
      (r = fido_cred_set_rk(cred.c, FIDO_OPT_FALSE)) != FIDO_OK) {
    fprintf(stderr, "failed to build credential: %s\n", fido_strerr(r));
    return false;
  }

  fprintf(stderr, "touch your security key to enroll it...\n");
  std::string pin;
  r = fido_dev_make_cred(fd.dev, cred.c, nullptr);
  if (needs_pin(r) && fido_dev_has_pin(fd.dev)) {
    pin = readpass("security key PIN: ");
    r = fido_dev_make_cred(fd.dev, cred.c, pin.c_str());
  }
  if (r != FIDO_OK) {
    explicit_bzero(&pin[0], pin.size());
    fprintf(stderr, "enrollment failed: %s\n", fido_strerr(r));
    return false;
  }

  const unsigned char *id = fido_cred_id_ptr(cred.c);
  size_t idlen = fido_cred_id_len(cred.c);
  if (id == nullptr || idlen == 0) {
    explicit_bzero(&pin[0], pin.size());
    fprintf(stderr, "security key returned no credential id\n");
    return false;
  }
  cred_id.assign(reinterpret_cast<const char *>(id), idlen);

  /*
   * makeCredential enables hmac-secret but does not return a secret, so a
   * second operation is needed to learn the value we wrap the master key
   * under.
   *
   * It must run on the handle already open above. Going back through
   * fido_secret_for_cred() here would re-enumerate and re-open the same
   * authenticator while this handle is still held, and OpenBSD's fido(4)
   * allows only one opener: the probe in fido_dev_info_manifest() fails with
   * EBUSY, the device drops out of the manifest, and the assertion reports
   * that no security key is present without ever asking the key to blink.
   */
  fprintf(stderr, "touch again to read the key's secret...\n");
  std::string got;
  r = assert_on_dev(fd.dev, {cred_id}, fido_salt, secret, got, pin);
  explicit_bzero(&pin[0], pin.size());
  if (r != FIDO_OK) {
    fprintf(stderr, "could not read the security key's secret: %s\n",
            fido_strerr(r));
    return false;
  }
  return true;
}

#endif // HAVE_FIDO2

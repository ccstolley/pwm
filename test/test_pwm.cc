#include "pwm.h"
#include "utest.h"
#include <array>
#include <cstdio>
#include <random>
#include <set>
#include <stdlib.h>

using namespace std::string_literals;
using namespace std::string_view_literals;

UTEST_MAIN();

std::vector<Storage::Entry> deserializeAll(const std::string &s) {
  std::vector<Storage::Entry> v;
  std::string_view sv{s};
  for (Storage::Entry ent; Storage::deserialize(sv, ent);) {
    v.push_back(ent);
    ent.clear();
  }
  return v;
}

std::string serializeAll(const std::vector<Storage::Entry> &entries) {
  std::string dat;
  for (const auto &ent : entries) {
    dat += Storage::serialize(ent);
  }
  return dat;
}

UTEST(PWMTest, verifyDumpToFile) {
  std::string filename("atest.tmp");
  std::string data1("a ton\0of stuff to do\12\n\t\r\n");
  ASSERT_TRUE(dump_to_file(data1, filename));

  std::ifstream in(filename, std::ifstream::binary | std::ifstream::ate);
  auto size = in.tellg();
  ASSERT_EQ(static_cast<long long>(size), static_cast<long long>(data1.size()));

  std::string s(size, '\0');
  in.seekg(0);
  ASSERT_TRUE(in.read(&s[0], size));
  ASSERT_EQ(s, data1);
  remove(filename.c_str());

  EXPECT_FALSE(dump_to_file(data1, "sjiaser/dfais0asa"));
  EXPECT_FALSE(dump_to_file(data1, "/root/foobar"));
}

UTEST(PWMTest, verifyDecrypt) {
  unsigned char rawdata[] = {
      0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f, 0xcf, 0x55, 0x7a, 0xd7,
      0xe7, 0xb7, 0xf0, 0xc6, 0xd2, 0xa9, 0x61, 0x28, 0x25, 0x9a, 0x32, 0xe7,
      0x05, 0xb1, 0x19, 0x92, 0xc5, 0xc6, 0x71, 0x71, 0xc1, 0xb1, 0xe6, 0x5e,
      0x31, 0xe8, 0x4d, 0x88, 0x1b, 0xc1, 0xd4, 0x83, 0x0b, 0x1c, 0x78, 0xf7,
      0x11, 0x61, 0x23, 0x30, 0x11, 0x5b, 0x4c, 0x4f, 0xeb, 0xea, 0xcf, 0x9c,
      0xab, 0xa9, 0x65, 0x6d, 0x35, 0x1f, 0xc3, 0x45, 0x60};
  const std::string encdat(reinterpret_cast<const char *>(rawdata),
                           sizeof(rawdata));
  const std::string key("pwmtest");
  std::string s, dkeyiv;
  ASSERT_TRUE(derive_key(encdat, key, dkeyiv));
  ASSERT_TRUE(decrypt(encdat, dkeyiv, s));
  ASSERT_EQ(s, "a test crypt\n");
}

UTEST(PWMTest, verifyDecryptCorrupt) {
  const std::string encdat(
      "Salted__\x03\xd5\x9bN\x84\xa2z\x1d!\x1bn:\xde\xa6\x8b\xb5");
  const std::string key("pwmtest");
  std::string s;
  ASSERT_FALSE(decrypt(encdat, key, s));
}

UTEST(PWMTest, verifyEncrypt) {
  const std::string decdat("a test crypt\n");
  const std::string key("pwmtest");
  std::string s, r, dkeyiv;

  ASSERT_TRUE(encrypt(decdat, key, s));
  ASSERT_TRUE(derive_key(s, key, dkeyiv));
  ASSERT_TRUE(decrypt(s, dkeyiv, r));

  ASSERT_EQ(r, decdat);
}

UTEST(PWMTest, verifyFind) {
  std::vector<Storage::Entry> entries{
      {
          .name = "cat",
          .updated_at = 1757376741,
          .password = "four",
          .meta = "ë",
      },
      {
          .name = "dog",
          .updated_at = 0,
          .password = "three",
          .meta = "one two",
      },
      {
          .name = "dog2",
          .updated_at = 0,
          .password = "fourteen",
          .meta = "",
      },
      {
          .name = "fog2",
          .updated_at = 0,
          .password = "monkeydog",
          .meta = "",
      },
      {
          .name = "mouse",
          .updated_at = 1747376741,
          .password = "100..z()",
          .meta = "",
      },
      {
          .name = "Brown",
          .updated_at = 1747376841,
          .password = "( )",
          .meta = ":",
      },
  };
  auto dat = serializeAll(entries);

  Storage::Entry e;

  e.clear();
  EXPECT_TRUE(search("dog", dat, e));
  EXPECT_EQ(e.name, "dog");
  EXPECT_EQ(e.meta, "one two");
  EXPECT_EQ(0, e.updated_at);
  EXPECT_EQ(e.password, "three");

  e.clear();
  EXPECT_TRUE(search("cat", dat, e));
  EXPECT_EQ(e.name, "cat");
  EXPECT_EQ(e.meta, "ë");
  EXPECT_EQ(1757376741, e.updated_at);
  EXPECT_EQ(e.password, "four");

  e.clear();
  EXPECT_TRUE(search("mouse", dat, e));
  EXPECT_EQ(e.name, "mouse");
  EXPECT_EQ(e.meta, "");
  EXPECT_EQ(e.updated_at, 1747376741);
  EXPECT_EQ(e.password, "100..z()");

  e.clear();
  EXPECT_FALSE(search("d", dat, e));
  EXPECT_FALSE(search("do", dat, e));
  EXPECT_FALSE(search("lion", dat, e));
  EXPECT_FALSE(search("lion", "lion", e));
  EXPECT_FALSE(search("lion", ":", e));

  e.clear();
  EXPECT_TRUE(search("Brow", dat, e));
  EXPECT_EQ(e.name, "Brown");
  EXPECT_EQ(e.meta, ":");
  EXPECT_EQ(1747376841, e.updated_at);
  EXPECT_EQ(e.password, "( )");

  e.clear();
  EXPECT_TRUE(search("m", dat, e));
  EXPECT_EQ(e.name, "mouse");
  EXPECT_EQ(e.meta, "");
  EXPECT_EQ(1747376741, e.updated_at);
  EXPECT_EQ(e.password, "100..z()");
}

UTEST(PWMTest, verifyDumpEntry) {
  Storage::Entry e1{
      .name = "foo",
      .updated_at = 0,
      .password = "baz",
      .meta = "bar",
  };
  Storage::Entry e2{
      .name = "foo",
      .updated_at = 1632853098,
      .password = "baz",
      .meta = "bar beet",
  };
  Storage::Entry e3{
      .name = "foo",
      .updated_at = 1632853098,
      .password = "baz",
      .meta = "",
  };

  EXPECT_EQ(dump_entry(e1), "foo: bar baz\n");
  EXPECT_EQ(dump_entry(e2), "foo: bar beet 1632853098 baz\n");
  EXPECT_EQ(dump_entry(e3), "foo: 1632853098 baz\n");
}

UTEST(PWMTest, verifyUpdate) {
  std::vector<Storage::Entry> entries{
      {
          .name = "catdog",
          .updated_at = 0,
          .password = ":313*(@)(!+;^^two",
          .meta = "one two three\nfour\tfivesix..\0seven",
      },
      {
          .name = "dog",
          .updated_at = 5,
          .password = "two",
          .meta = "one",
      },
      {
          .name = "mouse",
          .updated_at = 1756951965,
          .password = "\x84\xca"s
                      "8|u\xe0~\x81+\xf9\x05OUf#\x8ch\xc0\x05\xe4gd\xbd/"s
                      "\xb1\x9c\xc6"s
                      "7\xe0\xba"s,
          .meta = ")\x95\xbd\xda\x08\x02Y\x0b0\x9c"s,
      },
      {
          .name = "mouse:213()*1.21@1ßronöëtü:-__",
          .updated_at = 1756951965,
          .password = ":313*(@)(!+;^^two",
          .meta = "",
      },
  };

  std::string dat{serializeAll(entries)};
  Storage::Entry e;
  std::string newdat;

  // update
  e.name = "catdog";
  e.meta = "duck pig";
  e.password = "REG";
  e.updated_at = 44;

  EXPECT_TRUE(update(dat, e, newdat, false));
  auto cur = deserializeAll(newdat);

  EXPECT_EQ(entries.size(), cur.size());
  EXPECT_EQ(e, cur[0]);
  EXPECT_EQ(entries[1], cur[1]);
  EXPECT_EQ(entries[2], cur[2]);
  EXPECT_EQ(entries[3], cur[3]);

  // incomplete update
  e.clear();
  e.name = "catd";
  e.password = "REG";
  e.updated_at = 48;

  EXPECT_TRUE(update(dat, e, newdat, false));
  cur = deserializeAll(newdat);
  EXPECT_EQ(entries.size(), cur.size());
  EXPECT_EQ(entries[1], cur[1]);
  EXPECT_EQ(entries[0].name, cur[0].name);
  EXPECT_EQ(e.updated_at, cur[0].updated_at);
  EXPECT_EQ(entries[0].meta, cur[0].meta);
  EXPECT_EQ(entries[2], cur[2]);
  EXPECT_EQ(entries[3], cur[3]);

  // insert
  e.clear();
  e.name = "pig";
  e.meta = "bore";
  e.password = "SNaPz2";
  e.updated_at = 55;

  EXPECT_TRUE(update(dat, e, newdat, false));
  cur = deserializeAll(newdat);
  EXPECT_EQ(entries.size() + 1, cur.size());
  EXPECT_EQ(entries[0], cur[0]);
  EXPECT_EQ(entries[1], cur[1]);
  EXPECT_EQ(entries[2], cur[2]);
  EXPECT_EQ(entries[3], cur[3]);

  // conflict but exact match
  e.clear();
  e.name = "mouse";
  e.password = "newpass\x11y5\xc2G"s;
  e.updated_at = 1757015251;
  EXPECT_TRUE(update(dat, e, newdat, false));
  cur = deserializeAll(newdat);
  EXPECT_EQ(entries.size(), cur.size());
  EXPECT_EQ(entries[0], cur[0]);
  EXPECT_EQ(entries[1], cur[1]);
  EXPECT_EQ(entries[3], cur[3]);
  EXPECT_EQ(entries[2].name, cur[2].name);
  EXPECT_EQ(entries[2].meta, cur[2].meta);
  EXPECT_EQ(e.updated_at, cur[2].updated_at);
  EXPECT_EQ(e.password, cur[2].password);

  // conflict but no exact match
  e.clear();
  e.name = "mous";
  e.updated_at = 78;
  EXPECT_FALSE(update(dat, e, newdat, false));
}

UTEST(PWMTest, verifyRandomStr) {
  std::string s1(random_str(128));
  std::string s2(random_str(8));

  EXPECT_EQ(s1.size(), 128u);
  EXPECT_EQ(s2.size(), 8u);

  for (char c : s1) {
    EXPECT_TRUE(std::isalnum(c) || ispunct(c));
  }
  for (char c : s2) {
    EXPECT_TRUE(std::isalnum(c) || ispunct(c));
  }
}

UTEST(PWMTest, verifySortData) {
  std::vector<Storage::Entry> entries{
      {
          .name = "catdog",
          .updated_at = 0,
          .password = ":313*(@)(!+;^^two",
          .meta = "one two three\nfour\tfivesix..\0seven",
      },
      {
          .name = "dog",
          .updated_at = 5,
          .password = "two",
          .meta = "one",
      },
      {
          .name = "mouse",
          .updated_at = 1756951965,
          .password = "\x84\xca"s
                      "8|u\xe0~\x81+\xf9\x05OUf#\x8ch\xc0\x05\xe4gd\xbd/"s
                      "\xb1\x9c\xc6"s
                      "7\xe0\xba"s,
          .meta = ")\x95\xbd\xda\x08\x02Y\x0b0\x9c"s,
      },
      {
          .name = "mouse:213()*1.21@1ßronöëtü:-__",
          .updated_at = 1756951965,
          .password = ":313*(@)(!+;^^two",
          .meta = "",
      },
  };
  std::string dat{serializeAll(entries)};
  std::random_device rd;
  std::mt19937 gen{rd()};
  std::shuffle(entries.begin(), entries.end(), gen);
  std::string shufdat{serializeAll(entries)};

  EXPECT_EQ(sort_data(shufdat), dat);
}

#define TEST_STORE "/tmp/pwmtest"

UTEST(PWMTest, verifyGetFlags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);

  // create an empty store file
  ASSERT_TRUE(dump_to_file("", TEST_STORE));

  std::vector<char *> argv{"pwm", "foo"};
  auto f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "bar", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("bar", f.name);
  EXPECT_EQ("foo", f.meta);

  argv = {"pwm", "bar", "foo", "-u"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_TRUE(f.update);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("bar", f.name);
  EXPECT_EQ("foo", f.meta);

  argv = {"pwm", "foo", "bar"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("bar", f.meta);

  argv = {"pwm", "-u", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_TRUE(f.update);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "-u", "foo", "bar", "baz"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_TRUE(f.update);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("bar baz", f.meta);

  argv = {"pwm", "-r", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_FALSE(f.update);
  EXPECT_TRUE(f.remove);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "-d", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_FALSE(f.update);
  EXPECT_FALSE(f.uses_writeops());
  EXPECT_FALSE(f.read_only);
  EXPECT_TRUE(f.dump);

  argv = {"pwm", "-C", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_FALSE(f.update);
  EXPECT_FALSE(f.dump);
  EXPECT_FALSE(f.remove);
  EXPECT_TRUE(f.chpass);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.read_only);

#pragma clang diagnostic pop
}

UTEST(PWMTest, verifyPasswordUpdate) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);

  std::vector<char *> argv{
      "pwm",
      "-u",
      "foo",
      "cstolley@dorkrange.com",
      "ding dong ding dong",
      "ok well then what happened",
      "I don't know but i could tell it was something",
      "So why not ask and then tell us later when you know for sure",
      "I do think we could ask a few more questions first then we will see "
      "what really happened",
      "ok but jeez just hang on a second and let me catch my breath its very "
      "hot in here"};
#pragma clang diagnostic pop
  auto f = get_flags(std::size(argv), argv.data());
  f.key = "test!key123";

  Storage::Entry entry;
  bool v = handle_update(f, entry);
  ASSERT_TRUE(v);
  f.meta = "cstolley@mail.com tamsams";
  v = handle_update(f, entry);
  ASSERT_TRUE(v);
  ASSERT_TRUE(handle_search(f, entry));
}

UTEST(PWMTest, verifyExplicitPasswordUpdate) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);

  std::vector<char *> argv{"pwm", "-p", "foobar", "extra", "info"};
#pragma clang diagnostic pop
  auto f = get_flags(std::size(argv), argv.data());
  f.key = "test!key123";
  // TODO: test passwords with spaces or colons (breaks)
  f.password = "atestpassword";

  Storage::Entry entry;
  bool v = handle_update(f, entry);
  ASSERT_TRUE(v);
  ASSERT_TRUE(handle_search(f, entry));
  ASSERT_TRUE(v);
  ASSERT_EQ(entry.password, f.password);
  ASSERT_EQ(entry.meta, "extra info");
  ASSERT_EQ(entry.name, "foobar");
}

UTEST(PWMTest, verifyChangeMasterPassword) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);

  std::vector<char *> argv{"pwm", "-u", "foo"};
#pragma clang diagnostic pop
  auto f = get_flags(std::size(argv), argv.data());
  f.key = "test!key123";

  Storage::Entry entry;
  bool v = handle_update(f, entry);
  ASSERT_TRUE(v);

  f.newkey = "change?key105dog";
  ASSERT_TRUE(handle_chpass(f));

  f.key = "change?key105dog";
  ASSERT_TRUE(handle_search(f, entry));
}

UTEST(PWMTest, verifyStorage) {
  const Storage::Entry ent{"colin", 1756316540, "passWordie21",
                           "Ok meta data for everyone!!"};
  const auto want =
      "\x00\x05"s +
      "colin\x00\n1756316540\x00\x0cpassWordie21\x00\x1bOk meta data for everyone!!\x00\x00"s;
  EXPECT_EQ(Storage::serialize(ent), want);

  Storage::Entry gotEnt;
  std::string_view wantsv{want};
  EXPECT_TRUE(Storage::deserialize(wantsv, gotEnt));
  EXPECT_EQ(gotEnt, ent);

  Storage sto{want};
  EXPECT_TRUE(sto.next(gotEnt));
  EXPECT_EQ(gotEnt, ent);
  EXPECT_FALSE(sto.next(gotEnt));
}

/* ==================== v1 keyslot store ==================== */

extern std::vector<std::pair<std::string, std::string>> g_fake_tokens;
extern bool g_fake_token_present;

// A store with one password slot, built the way handle_update() builds one.
static bool makeStore(const std::string &password, const std::string &plaintext,
                      StoreHeader &hdr, std::string &mk,
                      std::string &ciphertext) {
  hdr = StoreHeader{};
  hdr.fido_salt = random_bytes(FIDO_SALT_LENGTH);
  mk = random_bytes(MK_LENGTH);
  KeySlot pw;
  if (!make_password_slot(password, mk, pw)) {
    return false;
  }
  hdr.slots.push_back(pw);
  return encrypt_store(plaintext, hdr, mk, ciphertext);
}

// Enroll a simulated security key into an existing header.
static bool enrollFake(StoreHeader &hdr, const std::string &mk,
                       const std::string &label) {
  KeySlot slot;
  std::string secret, kek;
  slot.type = SLOT_FIDO2;
  slot.label = label;
  if (!fido_enroll(hdr.fido_salt, slot.cred_id, secret)) {
    return false;
  }
  if (!fido_kek(secret, hdr.fido_salt, kek) || !wrap_mk(kek, mk, slot)) {
    return false;
  }
  hdr.slots.push_back(slot);
  return true;
}

UTEST(PWMTest, verifyV1RoundTrip) {
  const std::string plain("a test crypt\n");
  StoreHeader hdr;
  std::string mk, ct, got;

  ASSERT_TRUE(makeStore("pwmtest", plain, hdr, mk, ct));
  ASSERT_TRUE(is_v1_store(ct));
  ASSERT_FALSE(is_v1_store("Salted__nope"));
  ASSERT_TRUE(decrypt_store(ct, mk, got));
  ASSERT_EQ(got, plain);

  // wrong master key
  std::string wrong = random_bytes(MK_LENGTH);
  ASSERT_FALSE(decrypt_store(ct, wrong, got));
}

UTEST(PWMTest, verifyHeaderRoundTrip) {
  StoreHeader hdr, parsed;
  std::string mk, ct;
  g_fake_tokens.clear();

  ASSERT_TRUE(makeStore("pwmtest", "data", hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "blue key"));
  ASSERT_TRUE(encrypt_store("data", hdr, mk, ct));

  ASSERT_TRUE(parse_header(ct, parsed));
  ASSERT_EQ(parsed.slots.size(), 2u);
  ASSERT_EQ(parsed.fido_salt, hdr.fido_salt);
  ASSERT_TRUE(parsed.slots[0].is_password());
  ASSERT_TRUE(parsed.slots[1].is_fido());
  ASSERT_EQ(parsed.slots[1].label, "blue key");
  ASSERT_EQ(parsed.slots[1].cred_id, hdr.slots[1].cred_id);
  ASSERT_EQ(parsed.slots[0].iter, static_cast<uint32_t>(500000));
  // the header the body is authenticated against must survive the round trip
  ASSERT_EQ(parsed.aad, serialize_header(hdr));
}

UTEST(PWMTest, verifyGarbageHeaderRejected) {
  StoreHeader hdr;
  std::string mk, ct, got;
  ASSERT_TRUE(makeStore("pwmtest", "data", hdr, mk, ct));

  // truncated at every length short of the full header
  for (size_t n = 1; n < ct.size() - 1; n += 7) {
    StoreHeader h;
    parse_header(ct.substr(0, n), h); // must not crash or read out of bounds
  }
  ASSERT_FALSE(parse_header("", hdr));
  ASSERT_FALSE(parse_header("PWMKEY01", hdr));

  // unknown version
  std::string bad = ct;
  bad[MAGIC_V1.size()] = 9;
  ASSERT_FALSE(parse_header(bad, hdr));

  // unknown slot type
  bad = ct;
  bad[MAGIC_V1.size() + 1 + FIDO_SALT_LENGTH + 1] = 77;
  ASSERT_FALSE(parse_header(bad, hdr));

  // zero slots
  bad = ct;
  bad[MAGIC_V1.size() + 1 + FIDO_SALT_LENGTH] = 0;
  ASSERT_FALSE(parse_header(bad, hdr));
}

UTEST(PWMTest, verifyPasswordSlotUnwrap) {
  StoreHeader hdr;
  std::string mk, ct, kek, got;
  ASSERT_TRUE(makeStore("pwmtest", "data", hdr, mk, ct));

  ASSERT_TRUE(
      password_kek("pwmtest", hdr.slots[0].salt, hdr.slots[0].iter, kek));
  ASSERT_TRUE(unwrap_mk(kek, hdr.slots[0], got));
  ASSERT_EQ(got, mk);

  // wrong password must fail the wrap's own tag, not merely yield a bad key
  ASSERT_TRUE(password_kek("wrong", hdr.slots[0].salt, hdr.slots[0].iter, kek));
  ASSERT_FALSE(unwrap_mk(kek, hdr.slots[0], got));
}

UTEST(PWMTest, verifySlotAadBindsCredId) {
  StoreHeader hdr;
  std::string mk, ct;
  g_fake_tokens.clear();
  ASSERT_TRUE(makeStore("pwmtest", "data", hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "one"));

  std::string secret, kek, got;
  ASSERT_TRUE(
      fido_secret_for_cred(hdr.slots[1].cred_id, hdr.fido_salt, secret));
  ASSERT_TRUE(fido_kek(secret, hdr.fido_salt, kek));
  ASSERT_TRUE(unwrap_mk(kek, hdr.slots[1], got));
  ASSERT_EQ(got, mk);

  // tampering with a slot's own metadata invalidates its wrap
  KeySlot tampered = hdr.slots[1];
  tampered.label = "renamed";
  ASSERT_FALSE(unwrap_mk(kek, tampered, got));
  tampered = hdr.slots[1];
  tampered.cred_id[0] ^= 0xff;
  ASSERT_FALSE(unwrap_mk(kek, tampered, got));
}

UTEST(PWMTest, verifyBodyAadDetectsSlotStripping) {
  const std::string plain("secrets go here\n");
  StoreHeader hdr;
  std::string mk, ct, got;
  g_fake_tokens.clear();

  ASSERT_TRUE(makeStore("pwmtest", plain, hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "one"));
  ASSERT_TRUE(encrypt_store(plain, hdr, mk, ct));
  ASSERT_TRUE(decrypt_store(ct, mk, got));
  ASSERT_EQ(got, plain);

  // Strip the security key slot: the header still parses, but the body tag now
  // fails, so a downgrade of which factors are accepted cannot go unnoticed.
  StoreHeader stripped = hdr;
  stripped.slots.pop_back();
  std::string forged =
      serialize_header(stripped) + ct.substr(serialize_header(hdr).size());
  StoreHeader reparsed;
  ASSERT_TRUE(parse_header(forged, reparsed));
  ASSERT_EQ(reparsed.slots.size(), 1u);
  ASSERT_FALSE(decrypt_store(forged, mk, got));
}

UTEST(PWMTest, verifyFreshNonceOnEveryWrap) {
  StoreHeader hdr;
  std::string mk, ct, kek;
  ASSERT_TRUE(makeStore("pwmtest", "data", hdr, mk, ct));
  ASSERT_TRUE(
      password_kek("pwmtest", hdr.slots[0].salt, hdr.slots[0].iter, kek));

  // Re-wrapping under the same KEK must never reuse the nonce; reuse would leak
  // the XOR of both master keys and the GCM authentication subkey.
  std::set<std::string> nonces{hdr.slots[0].wrap_nonce};
  for (int i = 0; i < 32; i++) {
    KeySlot slot = hdr.slots[0];
    ASSERT_TRUE(wrap_mk(kek, random_bytes(MK_LENGTH), slot));
    ASSERT_EQ(slot.wrap_nonce.size(), static_cast<size_t>(GCM_NONCE_LENGTH));
    ASSERT_TRUE(nonces.insert(slot.wrap_nonce).second);
  }
}

UTEST(PWMTest, verifyMultipleKeysUnlockSameStore) {
  const std::string plain("shared master key\n");
  StoreHeader hdr;
  std::string mk, ct;
  g_fake_tokens.clear();

  ASSERT_TRUE(makeStore("pwmtest", plain, hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "blue"));
  ASSERT_TRUE(enrollFake(hdr, mk, "grey"));
  ASSERT_TRUE(encrypt_store(plain, hdr, mk, ct));
  ASSERT_EQ(hdr.slots.size(), 3u);

  // every enrolled factor recovers the identical master key
  for (const auto &slot : hdr.slots) {
    std::string kek, got;
    if (slot.is_password()) {
      ASSERT_TRUE(password_kek("pwmtest", slot.salt, slot.iter, kek));
    } else {
      std::string secret;
      ASSERT_TRUE(fido_secret_for_cred(slot.cred_id, hdr.fido_salt, secret));
      ASSERT_TRUE(fido_kek(secret, hdr.fido_salt, kek));
    }
    ASSERT_TRUE(unwrap_mk(kek, slot, got));
    ASSERT_EQ(got, mk);
  }
}

UTEST(PWMTest, verifyUnlockStorePrefersToken) {
  const std::string plain("data\n");
  StoreHeader hdr, opened;
  std::string mk, ct, got;
  struct CmdFlags f;
  g_fake_tokens.clear();

  ASSERT_TRUE(makeStore("pwmtest", plain, hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "blue"));
  ASSERT_TRUE(encrypt_store(plain, hdr, mk, ct));

  // A token is attached, so no password is needed at all (f.key stays empty,
  // which would otherwise mean an interactive prompt).
  g_fake_token_present = true;
  ASSERT_TRUE(unlock_store(ct, f, got, opened));
  ASSERT_EQ(got, mk);

  // With the token gone, the password slot still opens it.
  g_fake_token_present = false;
  got.clear();
  f.key = "pwmtest";
  ASSERT_TRUE(unlock_store(ct, f, got, opened));
  ASSERT_EQ(got, mk);

  // -P ignores an attached token and goes straight to the password.
  g_fake_token_present = true;
  f.force_password = true;
  got.clear();
  ASSERT_TRUE(unlock_store(ct, f, got, opened));
  ASSERT_EQ(got, mk);

  // a wrong password with no token opens nothing
  g_fake_token_present = false;
  f.key = "nope";
  got.clear();
  ASSERT_FALSE(unlock_store(ct, f, got, opened));
}

UTEST(PWMTest, verifyRotateMkRevokes) {
  const std::string plain("data to keep\n");
  StoreHeader hdr;
  std::string mk, ct, got;
  g_fake_tokens.clear();

  ASSERT_TRUE(makeStore("oldpass", plain, hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "keeper"));
  ASSERT_TRUE(encrypt_store(plain, hdr, mk, ct));
  const std::string old_mk = mk;
  const std::string old_ct = ct;
  const std::string keeper_cred = hdr.slots[1].cred_id;

  const std::string old_salt = hdr.fido_salt;
  std::string newct;
  g_fake_token_present = true;
  ASSERT_TRUE(rotate_mk(plain, "newpass", hdr, mk, newct));

  // every wrapping parameter is regenerated, not just the nonce
  ASSERT_NE(hdr.fido_salt, old_salt);

  // new master key, and the contents survived
  ASSERT_NE(mk, old_mk);
  ASSERT_TRUE(decrypt_store(newct, mk, got));
  ASSERT_EQ(got, plain);
  ASSERT_EQ(hdr.slots.size(), 2u);

  // the old master key no longer opens the rewritten store
  ASSERT_FALSE(decrypt_store(newct, old_mk, got));

  // the surviving security key still works, under the same credential
  ASSERT_EQ(hdr.slots[1].cred_id, keeper_cred);
  std::string secret, kek;
  ASSERT_TRUE(fido_secret_for_cred(keeper_cred, hdr.fido_salt, secret));
  ASSERT_TRUE(fido_kek(secret, hdr.fido_salt, kek));
  ASSERT_TRUE(unwrap_mk(kek, hdr.slots[1], got));
  ASSERT_EQ(got, mk);

  // the KEK that key had before the rotation is now unrelated: the secret
  // derived under the old salt no longer wraps anything in this store
  std::string old_secret, old_kek;
  ASSERT_TRUE(fido_secret_for_cred(keeper_cred, old_salt, old_secret));
  ASSERT_NE(old_secret, secret);
  ASSERT_TRUE(fido_kek(old_secret, old_salt, old_kek));
  ASSERT_NE(old_kek, kek);
  ASSERT_FALSE(unwrap_mk(old_kek, hdr.slots[1], got));

  // the new password works and the old one does not
  ASSERT_TRUE(
      password_kek("newpass", hdr.slots[0].salt, hdr.slots[0].iter, kek));
  ASSERT_TRUE(unwrap_mk(kek, hdr.slots[0], got));
  ASSERT_EQ(got, mk);
  ASSERT_TRUE(
      password_kek("oldpass", hdr.slots[0].salt, hdr.slots[0].iter, kek));
  ASSERT_FALSE(unwrap_mk(kek, hdr.slots[0], got));

  // and the old file is untouched by all of this, which is why the user is told
  // to delete the backup
  ASSERT_TRUE(decrypt_store(old_ct, old_mk, got));
}

UTEST(PWMTest, verifyRotateRequiresEveryKey) {
  const std::string plain("data\n");
  StoreHeader hdr;
  std::string mk, ct, newct;
  g_fake_tokens.clear();

  ASSERT_TRUE(makeStore("pwmtest", plain, hdr, mk, ct));
  ASSERT_TRUE(enrollFake(hdr, mk, "lost"));
  ASSERT_EQ(hdr.slots.size(), 2u);
  const std::string mk_before = mk;
  const std::string salt_before = hdr.fido_salt;

  // Re-keying wraps under a fresh salt, so it needs the token. Missing keys
  // abort the whole operation rather than being silently dropped, and nothing
  // about the header or the master key is disturbed.
  g_fake_token_present = false;
  ASSERT_FALSE(rotate_mk(plain, "pwmtest", hdr, mk, newct));
  ASSERT_EQ(mk, mk_before);
  ASSERT_EQ(hdr.fido_salt, salt_before);
  ASSERT_EQ(hdr.slots.size(), 2u);

  // -F is the deliberate escape hatch for a key you no longer have.
  ASSERT_TRUE(rotate_mk(plain, "pwmtest", hdr, mk, newct, true));
  ASSERT_EQ(hdr.slots.size(), 1u);
  ASSERT_TRUE(hdr.slots[0].is_password());
  ASSERT_NE(mk, mk_before);

  std::string got;
  ASSERT_TRUE(decrypt_store(newct, mk, got));
  ASSERT_EQ(got, plain);
  g_fake_token_present = true;
}

UTEST(PWMTest, verifyEnrollAndDeauthViaHandlers) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);
  std::vector<char *> argv{"pwm", "-u", "foo"};
#pragma clang diagnostic pop
  g_fake_tokens.clear();
  g_fake_token_present = true;

  auto f = get_flags(std::size(argv), argv.data());
  f.key = "test!key123";
  Storage::Entry entry;
  ASSERT_TRUE(handle_update(f, entry));
  const std::string password = entry.password;

  // enroll two security keys
  struct CmdFlags ef = f;
  ef.update = false;
  ef.enroll = true;
  ef.label = "blue";
  ASSERT_TRUE(handle_enroll(ef));
  ef.label = "grey";
  ASSERT_TRUE(handle_enroll(ef));

  StoreHeader hdr;
  ASSERT_TRUE(parse_header(read_file(TEST_STORE), hdr));
  ASSERT_EQ(hdr.slots.size(), 3u);
  ASSERT_EQ(hdr.slots[1].label, "blue");
  ASSERT_EQ(hdr.slots[2].label, "grey");

  // the store opens with a token and no password at all
  struct CmdFlags rf = f;
  rf.key.clear();
  rf.update = false;
  Storage::Entry got;
  rf.name = "foo";
  ASSERT_TRUE(handle_search(rf, got));
  ASSERT_EQ(got.password, password);

  // and with the password and no token
  g_fake_token_present = false;
  rf.key = "test!key123";
  ASSERT_TRUE(handle_search(rf, got));
  ASSERT_EQ(got.password, password);
  g_fake_token_present = true;

  // removing the password slot is refused: it is the recovery path
  struct CmdFlags df = f;
  df.update = false;
  df.deauth = 0;
  ASSERT_FALSE(handle_deauth(df));

  // removing a security key rotates the master key, which needs the surviving
  // key present; without it the store is left exactly as it was
  const std::string before = read_file(TEST_STORE);
  df.deauth = 1;
  g_fake_token_present = false;
  ASSERT_FALSE(handle_deauth(df));
  ASSERT_EQ(read_file(TEST_STORE), before);
  g_fake_token_present = true;

  ASSERT_TRUE(handle_deauth(df));
  ASSERT_TRUE(parse_header(read_file(TEST_STORE), hdr));
  ASSERT_EQ(hdr.slots.size(), 2u);
  ASSERT_EQ(hdr.slots[1].label, "grey");

  // contents intact, and the entry is still reachable with either factor
  ASSERT_TRUE(handle_search(rf, got));
  ASSERT_EQ(got.password, password);
  ASSERT_NE(read_file(TEST_STORE), before);

  // out of range slots are rejected
  df.deauth = 9;
  ASSERT_FALSE(handle_deauth(df));
}

UTEST(PWMTest, verifyLegacyStoreUpgradesOnWrite) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);
  std::vector<char *> argv{"pwm", "-u", "foo"};
#pragma clang diagnostic pop

  // hand build a v0 "Salted__" store, as written by the previous version
  const std::string plain =
      Storage::serialize({"foo", 1756316540, "sekrit", ""});
  std::string v0;
  ASSERT_TRUE(encrypt(plain, "oldpass", v0));
  ASSERT_TRUE(dump_to_file(v0, TEST_STORE));
  ASSERT_FALSE(is_v1_store(read_file(TEST_STORE)));

  auto f = get_flags(std::size(argv), argv.data());
  f.key = "oldpass";

  // reads still work against the old format
  Storage::Entry got;
  struct CmdFlags rf = f;
  rf.update = false;
  rf.name = "foo";
  ASSERT_TRUE(handle_search(rf, got));
  ASSERT_EQ(got.password, "sekrit");

  // the first write upgrades it in place, keeping the same password
  Storage::Entry entry;
  entry.name = "bar";
  f.name = "bar";
  ASSERT_TRUE(handle_update(f, entry));
  ASSERT_TRUE(is_v1_store(read_file(TEST_STORE)));

  StoreHeader hdr;
  ASSERT_TRUE(parse_header(read_file(TEST_STORE), hdr));
  ASSERT_EQ(hdr.slots.size(), 1u);
  ASSERT_TRUE(hdr.slots[0].is_password());

  // both the old and the new entry are readable with the original password
  rf.name = "foo";
  ASSERT_TRUE(handle_search(rf, got));
  ASSERT_EQ(got.password, "sekrit");
  rf.name = "bar";
  ASSERT_TRUE(handle_search(rf, got));
  ASSERT_EQ(got.password, entry.password);
}

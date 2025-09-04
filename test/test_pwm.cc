#include "pwm.h"
#include "utest.h"
#include <array>
#include <cstdio>
#include <random>
#include <stdlib.h>

using namespace std::string_literals;
using namespace std::string_view_literals;

UTEST_MAIN();

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

UTEST(PWMTest, verifyTrim) {
  std::vector<std::string> testcases{"  a space",   "a space  ", "  a space  ",
                                     "\ta space  ", "a space\n", "a space"};
  for (const auto &t : testcases) {
    EXPECT_EQ(Storage::trim(t), "a space");
  }
  EXPECT_EQ(Storage::trim("   \n\t"), "");
  EXPECT_EQ(Storage::trim(""), "");
  EXPECT_EQ(Storage::trim("\n"), "");
  EXPECT_EQ(Storage::trim("\n "), "");
}

UTEST(PWMTest, verifySplit) {
  auto pieces = Storage::split("  Storage::split along  different ", " ");
  ASSERT_EQ(pieces.size(), 3u);
  EXPECT_EQ(pieces[0], "Storage::split");
  EXPECT_EQ(pieces[1], "along");
  EXPECT_EQ(pieces[2], "different");

  pieces = Storage::split("nospace", " ");
  ASSERT_EQ(pieces.size(), 1u);
  EXPECT_EQ(pieces[0], "nospace");

  pieces = Storage::split("", " ");
  EXPECT_EQ(pieces.size(), 0u);

  pieces = Storage::split(" ", " ");
  EXPECT_EQ(pieces.size(), 0u);
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
  const std::string dat(
      "dog: one two three\ndog2: fourteen\ndragon: monkeydog\n"
      "cat: four 5 6\nmouse: 100..z()\nblonde: 1632857699 passw\n"
      "tape: mall time 1632857700 passwood\nblorgish: 2Ua02=bar\n");

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
  EXPECT_EQ(e.meta, "four 5");
  EXPECT_EQ(0, e.updated_at);
  EXPECT_EQ(e.password, "6");

  e.clear();
  EXPECT_TRUE(search("mouse", dat, e));
  EXPECT_EQ(e.name, "mouse");
  EXPECT_EQ(e.meta, "");
  EXPECT_EQ(e.updated_at, 0);
  EXPECT_EQ(e.password, "100..z()");

  e.clear();
  EXPECT_FALSE(search("d", dat, e));
  EXPECT_FALSE(search("do", dat, e));
  EXPECT_FALSE(search("lion", dat, e));
  EXPECT_FALSE(search("lion", "lion", e));
  EXPECT_FALSE(search("lion", ":", e));

  e.clear();
  EXPECT_TRUE(search("blond", dat, e));
  EXPECT_EQ(e.name, "blonde");
  EXPECT_EQ(e.meta, "");
  EXPECT_EQ(1632857699, e.updated_at);
  EXPECT_EQ(e.password, "passw");

  e.clear();
  EXPECT_TRUE(search("tape", dat, e));
  EXPECT_EQ(e.name, "tape");
  EXPECT_EQ(e.meta, "mall time");
  EXPECT_EQ(1632857700, e.updated_at);
  EXPECT_EQ(e.password, "passwood");

  e.clear();
  EXPECT_TRUE(search("blorg", dat, e));
  EXPECT_EQ(e.name, "blorgish");
  EXPECT_EQ(e.meta, "");
  EXPECT_EQ(0, e.updated_at);
  EXPECT_EQ(e.password, "2Ua02=bar");
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

UTEST(PWMTest, verifyDeserializeOld) {
  Storage::Entry e1{
      .name = "foo",
      .updated_at = 0,
      .password = "baz",
      .meta = "bar",
  };
  Storage::Entry e2{
      .name = "cow",
      .updated_at = 1632853098,
      .password = "zap",
      .meta = "bar beet",
  };
  Storage::Entry e3{
      .name = "dog",
      .updated_at = 1632853098,
      .password = "zap",
      .meta = "",
  };
  Storage::Entry e4{
      .name = "goo",
      .updated_at = 0,
      .password = "2Ua02=bar",
      .meta = "",
  };
  Storage::Entry e5{
      .name = "goo",
      .updated_at = 1632853098,
      .password = "pizza",
      .meta = "zar",
  };
  Storage::Entry e6{
      .name = "Bäckerei",
      .updated_at = 1632853598,
      .password = "zar",
      .meta = "Übel Pizza",
  };

  Storage::Entry t;
  std::string_view want =
      "foo: bar baz\ncow: bar beet 1632853098 zap\ndog: 1632853098 zap\n"
      "goo: 2Ua02=bar\ngoo: zar 1632853098 pizza\nBäckerei: Übel Pizza 1632853598 zar\n"sv;
  EXPECT_TRUE(Storage::deserialize_old(want, t));
  EXPECT_EQ(e1, t);
  EXPECT_TRUE(Storage::deserialize_old(want, t));
  EXPECT_EQ(e2, t);
  EXPECT_TRUE(Storage::deserialize_old(want, t));
  EXPECT_EQ(e3, t);
  EXPECT_TRUE(Storage::deserialize_old(want, t));
  EXPECT_EQ(e4, t);
  EXPECT_TRUE(Storage::deserialize_old(want, t));
  EXPECT_EQ(e5, t);
  EXPECT_TRUE(Storage::deserialize_old(want, t));
  EXPECT_EQ(e6, t);
}

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
  putenv("PWM_LINGER=0");
  putenv("PWM_STORE=" TEST_STORE);
  remove(TEST_STORE);

  // create an empty store file
  ASSERT_TRUE(dump_to_file("", TEST_STORE));

  std::vector<char *> argv{"pwm", "foo"};
  auto f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_FALSE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "-l", "4", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_TRUE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "bar", "foo", "-l", "4"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_TRUE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("bar", f.name);
  EXPECT_EQ("foo", f.meta);

  argv = {"pwm", "-l", "4", "bar", "foo", "-u"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_TRUE(f.update);
  EXPECT_TRUE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("bar", f.name);
  EXPECT_EQ("foo", f.meta);

  argv = {"pwm", "foo", "bar"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_TRUE(f.is_search());
  EXPECT_FALSE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("bar", f.meta);

  argv = {"pwm", "-u", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_TRUE(f.update);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "-u", "foo", "bar", "baz"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_TRUE(f.update);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("bar baz", f.meta);

  argv = {"pwm", "-r", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_FALSE(f.update);
  EXPECT_TRUE(f.remove);
  EXPECT_TRUE(f.uses_writeops());
  EXPECT_FALSE(f.linger);
  EXPECT_FALSE(f.read_only);
  EXPECT_EQ("foo", f.name);
  EXPECT_EQ("", f.meta);

  argv = {"pwm", "-d", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_FALSE(f.update);
  EXPECT_FALSE(f.uses_writeops());
  EXPECT_FALSE(f.linger);
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
  EXPECT_FALSE(f.linger);
  EXPECT_FALSE(f.read_only);

  argv = {"pwm", "-Cl300", "foo"};
  f = get_flags(std::size(argv), argv.data());
  EXPECT_FALSE(f.is_search());
  EXPECT_FALSE(f.update);
  EXPECT_TRUE(f.linger);
  EXPECT_FALSE(f.read_only);

#pragma clang diagnostic pop
}

UTEST(PWMTest, verifyPasswordUpdate) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wwritable-strings"
  putenv("PWM_READONLY=0");
  putenv("PWM_LINGER=0");
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
  putenv("PWM_LINGER=0");
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
  putenv("PWM_LINGER=0");
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

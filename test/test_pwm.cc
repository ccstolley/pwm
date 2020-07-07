#include "pwm.h"
#include "utest.h"
#include <cstdio>

UTEST_MAIN();

UTEST(PWMTest, verifyDumpToFile) {
  std::string filename("atest.tmp");
  std::string data1("a ton\0of stuff to do\12\n\t\r\n");
  ASSERT_TRUE(dump_to_file(data1, filename));

  std::ifstream in(filename, std::ifstream::binary | std::ifstream::ate);
  auto size = in.tellg();
  ASSERT_EQ(size, static_cast<long long>(data1.size()));

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
    EXPECT_EQ(trim(t), "a space");
  }
  EXPECT_EQ(trim("   \n\t"), "");
  EXPECT_EQ(trim(""), "");
  EXPECT_EQ(trim("\n"), "");
  EXPECT_EQ(trim("\n "), "");
}

UTEST(PWMTest, verifySplit) {
  auto pieces = split("  split along  different ", " ");
  ASSERT_EQ(pieces.size(), 3u);
  EXPECT_EQ(pieces[0], "split");
  EXPECT_EQ(pieces[1], "along");
  EXPECT_EQ(pieces[2], "different");

  pieces = split("nospace", " ");
  ASSERT_EQ(pieces.size(), 1u);
  EXPECT_EQ(pieces[0], "nospace");

  pieces = split("", " ");
  EXPECT_EQ(pieces.size(), 0u);

  pieces = split(" ", " ");
  EXPECT_EQ(pieces.size(), 0u);
}

UTEST(PWMTest, verifyDecrypt) {
  const std::string encdat("Salted__!0F\x03\x95\x9a\xd5[\x87\x1f"
                           "B\xec\xa5\xedz\xc2\xd8"
                           "a-\x9dL\xae\x97"
                           "0");
  const std::string key("pwmtest");
  std::string s;
  ASSERT_TRUE(decrypt(encdat, key, s));
  ASSERT_EQ(s, "a test crypt\n");
}

UTEST(PWMTest, verifyEncrypt) {
  const std::string decdat("a test crypt\n");
  const std::string key("pwmtest");
  std::string s, r;

  ASSERT_TRUE(encrypt(decdat, key, s));
  ASSERT_TRUE(decrypt(s, key, r));

  ASSERT_EQ(r, decdat);
}

UTEST(PWMTest, verifyFind) {
  const std::string dat("dog: one two three\ndog2: fourteen\ndragon:\ncat: "
                        "four 5\nmouse: 100..z()");

  struct ent e;

  EXPECT_TRUE(find("dog", dat, e));
  EXPECT_EQ(e.name, "dog");
  EXPECT_EQ(e.meta, "one two");
  EXPECT_EQ(e.password, "three");

  e.clear();
  EXPECT_TRUE(find("cat", dat, e));
  EXPECT_EQ(e.name, "cat");
  EXPECT_EQ(e.meta, "four");
  EXPECT_EQ(e.password, "5");

  e.clear();
  EXPECT_TRUE(find("mouse", dat, e));
  EXPECT_TRUE(e.name == "mouse");
  EXPECT_TRUE(e.meta == "");
  EXPECT_TRUE(e.password == "100..z()");

  e.clear();
  EXPECT_FALSE(find("d", dat, e));
  EXPECT_FALSE(find("do", dat, e));
  EXPECT_FALSE(find("lion", dat, e));
  EXPECT_FALSE(find("lion", "lion", e));
  EXPECT_FALSE(find("lion", ":", e));
}

UTEST(PWMTest, verifyDumpEntry) {
  struct ent e1 {
    "foo", "bar", "baz"
  };
  struct ent e2 {
    "foo", "bar beet", "baz"
  };
  struct ent e3 {
    "foo", "", "baz"
  };

  EXPECT_EQ(dump_entry(e1), "foo: bar baz\n");
  EXPECT_EQ(dump_entry(e2), "foo: bar beet baz\n");
  EXPECT_EQ(dump_entry(e3), "foo: baz\n");
}

UTEST(PWMTest, verifyParseEntry) {
  struct ent e1 {
    "foo", "bar", "baz"
  };
  struct ent e2 {
    "cow", "bar beet", "zap"
  };
  struct ent e3 {
    "dog", "", "zap"
  };
  struct ent t;

  EXPECT_TRUE(parse_entry("foo: bar baz\n", t));
  EXPECT_TRUE(e1 == t);
  t.clear();
  EXPECT_TRUE(parse_entry("cow: bar beet zap\n", t));
  EXPECT_TRUE(e2 == t);
  t.clear();
  EXPECT_TRUE(parse_entry("dog: zap\n", t));
  EXPECT_TRUE(e3 == t);
}

UTEST(PWMTest, verifyUpdate) {
  std::string dat("dog: one two\ncatdog: four thumb 5te\nmouse: 100..z()\n");
  struct ent e;
  std::string newdat;

  // update
  e.name = "catdog";
  e.meta = "four thumb";
  e.password = "REG";

  EXPECT_TRUE(update(dat, e, newdat));
  EXPECT_EQ("dog: one two\ncatdog: four thumb REG\nmouse: 100..z()\n", newdat);

  // incomplete update
  e.clear();
  e.name = "catd";
  e.password = "REG";

  EXPECT_TRUE(update(dat, e, newdat));
  EXPECT_EQ("dog: one two\ncatdog: four thumb REG\nmouse: 100..z()\n", newdat);

  // insert
  e.clear();
  e.name = "pig";
  e.meta = "bore";
  e.password = "SNaPz2";
  EXPECT_TRUE(update(dat, e, newdat));
  EXPECT_EQ("dog: one two\ncatdog: four thumb 5te\nmouse: 100..z()\npig: bore "
            "SNaPz2\n",
            newdat);

  // conflict but exact match
  e.clear();
  dat = "cool: snapsids biItNYeU7B4.V8-\ncoolman: vstb'76t8H<sFUB\n";
  e.name = "cool";
  e.password = "newpass";
  EXPECT_TRUE(update(dat, e, newdat));
  EXPECT_EQ(newdat, "cool: snapsids newpass\ncoolman: vstb'76t8H<sFUB\n");

  // conflict but no exact match
  e.clear();
  dat = "cool: snapsids biItNYeU7B4.V8-\ncoolman: vstb'76t8H<sFUB\n";
  e.name = "coo";
  EXPECT_FALSE(update(dat, e, newdat));
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
  std::string dat("dog: one two\ncatdog: four thumb 5te\nmouse: 100..z()\ncat: "
                  "foobar baz\n");
  EXPECT_EQ("cat: foobar baz\ncatdog: four thumb 5te\ndog: one two\nmouse: "
            "100..z()\n",
            sort_data(dat));

  dat = "dog: foo bar\n"
        "dog1: doo zar\n"
        "dog2: doo zar\n";

  EXPECT_EQ(sort_data(dat), dat);
}

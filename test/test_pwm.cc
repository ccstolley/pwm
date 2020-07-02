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
}

UTEST(PWMTest, verifyTrim) {
  std::vector<std::string> testcases{"  a space",   "a space  ", "  a space  ",
                                     "\ta space  ", "a space\n", "a space"};

  for (const auto &t : testcases) {
    EXPECT_EQ(trim(t), "a space");
  }
  EXPECT_EQ(trim("   \n\t"), "");
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
}

UTEST(PWMTest, verifyDecrypt) {
  const std::string encdat("Salted__!0F\x03\x95\x9a\xd5[\x87\x1f"
                           "B\xec\xa5\xedz\xc2\xd8"
                           "a-\x9dL\xae\x97"
                           "0");
  const std::string key("pwmtest");
  std::string s;
  ASSERT_TRUE(decrypt(encdat, key, &s));
  ASSERT_EQ(s, "a test crypt\n");
}

UTEST(PWMTest, verifyEncrypt) {
  const std::string decdat("a test crypt\n");
  const std::string key("pwmtest");
  std::string s, r;

  ASSERT_TRUE(encrypt(decdat, key, &s));
  ASSERT_TRUE(decrypt(s, key, &r));

  ASSERT_EQ(r, decdat);
}

UTEST(PWMTest, verifyFind) {
  const std::string dat(
      "dog: one two three\ndragon:\ncat: four 5\nmouse: 100..z()");

  struct ent e;

  ASSERT_TRUE(find("dog", dat, &e));
  ASSERT_EQ(e.name, "dog");
  ASSERT_TRUE(e.meta == "one");
  ASSERT_TRUE(e.password == "three");

  memset(&e, 0, sizeof(struct ent));
  ASSERT_TRUE(find("cat", dat, &e));
  ASSERT_TRUE(e.name == "cat");
  ASSERT_TRUE(e.meta == "four");
  ASSERT_TRUE(e.password == "5");

  memset(&e, 0, sizeof(struct ent));
  ASSERT_TRUE(find("mouse", dat, &e));
  ASSERT_TRUE(e.name == "mouse");
  ASSERT_TRUE(e.meta == "");
  ASSERT_TRUE(e.password == "100..z()");

  ASSERT_FALSE(find("lion", dat, &e));
  ASSERT_FALSE(find("lion", "lion", &e));
  ASSERT_FALSE(find("lion", ":", &e));
}

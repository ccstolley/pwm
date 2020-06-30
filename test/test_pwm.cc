#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "pwm.h"
#include <cstdio>

TEST_CASE("verify dump_to_file()") {
  std::string filename("atest.tmp");
  std::string data1("a ton\0of stuff to do\12\n\t\r\n");
  REQUIRE(dump_to_file(data1, filename));

  std::ifstream in(filename, std::ifstream::binary | std::ifstream::ate);
  auto size = in.tellg();
  REQUIRE(size == static_cast<long long>(data1.size()));

  std::string s(size, '\0');
  in.seekg(0);
  REQUIRE(in.read(&s[0], size));
  REQUIRE(s == data1);
  remove(filename.c_str());
}

TEST_CASE("verify trim()") {
  std::vector<std::string> testcases{"  a space",   "a space  ", "  a space  ",
                                     "\ta space  ", "a space\n", "a space"};

  for (const auto &t : testcases) {
    CHECK(trim(t) == "a space");
  }
  CHECK(trim("   \n\t") == "");
}

TEST_CASE("verify split()") {
  auto pieces = split("  split along  different ", " ");
  REQUIRE(pieces.size() == 3);
  CHECK(pieces[0] == "split");
  CHECK(pieces[1] == "along");
  CHECK(pieces[2] == "different");

  pieces = split("nospace", " ");
  REQUIRE(pieces.size() == 1);
  CHECK(pieces[0] == "nospace");

  pieces = split("", " ");
  CHECK(pieces.size() == 0);
}

TEST_CASE("verify decrypt()") {
  const std::string encdat("Salted__!0F\x03\x95\x9a\xd5[\x87\x1f"
                           "B\xec\xa5\xedz\xc2\xd8"
                           "a-\x9dL\xae\x97"
                           "0");
  const std::string key("pwmtest");
  std::string s;
  REQUIRE(decrypt(encdat, key, &s));
  REQUIRE(s == "a test crypt\n");
}

TEST_CASE("verify encrypt()") {
  const std::string decdat("a test crypt\n");
  const std::string key("pwmtest");
  std::string s, r;

  REQUIRE(encrypt(decdat, key, &s));
  REQUIRE(decrypt(s, key, &r));

  REQUIRE(r == decdat);
}

TEST_CASE("verify find()") {
  const std::string dat("dog: one two three\ndragon:\ncat: four 5\nmouse: 100..z()");

  struct ent e;

  REQUIRE(find("dog", dat, &e));
  REQUIRE(e.name  == "dog");
  REQUIRE(e.meta == "one");
  REQUIRE(e.password == "three");

  memset(&e, 0, sizeof(struct ent));
  REQUIRE(find("cat", dat, &e));
  REQUIRE(e.name  == "cat");
  REQUIRE(e.meta == "four");
  REQUIRE(e.password == "5");

  memset(&e, 0, sizeof(struct ent));
  REQUIRE(find("mouse", dat, &e));
  REQUIRE(e.name  == "mouse");
  REQUIRE(e.meta == "");
  REQUIRE(e.password == "100..z()");

  REQUIRE_FALSE(find("lion", dat, &e));
  REQUIRE_FALSE(find("lion", "lion", &e));
  REQUIRE_FALSE(find("lion", ":", &e));
}

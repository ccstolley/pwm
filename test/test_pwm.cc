#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "pwm.h"

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

UNAME = `uname`
PORTABLE = -I portable portable/arc4random.c portable/readpassphrase.c portable/pledge.c
LIBS=-lz -lcrypto
CXXFLAGS=--std=c++17 -g -pedantic -Wall -Wextra -Wno-unused-function -Wno-write-strings

DetectOS:
	-@make $(UNAME)

Linux: pwm.cc pwm.h test_linux
	$(CXX) $(CXXFLAGS) $(PORTABLE) pwm.cc $(LIBS) -o pwm

OpenBSD: pwm.cc pwm.h test_openbsd
	$(CXX) $(CXXFLAGS) pwm.cc $(LIBS) -o pwm

fmt: pwm.cc pwm.h test/test_pwm.cc
	clang-format -i pwm.h pwm.cc test/test_pwm.cc

test_openbsd: pwm.h pwm.cc test/test_pwm.cc
	$(CXX) $(CXXFLAGS) -DTESTING -I. -Itest pwm.cc test/test_pwm.cc $(LIBS) -o test_pwm
	./test_pwm

test_linux: pwm.h pwm.cc test/test_pwm.cc
	$(CXX) $(CXXFLAGS) -DTESTING -I. -Itest $(PORTABLE) pwm.cc test/test_pwm.cc $(LIBS) -o test_pwm
	./test_pwm

clean:
	rm -f pwm *.core test_pwm *.o *.tmp

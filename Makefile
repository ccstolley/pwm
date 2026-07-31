UNAME = `uname`
PORTABLE = -I portable portable/arc4random.c portable/readpassphrase.c portable/pledge.c
LIBS=-lz -lcrypto
CXXFLAGS=--std=c++20 -g -pedantic -Wall -Wextra -Wno-unused-function -Wno-write-strings
CXX=c++

# FIDO2 security key support needs libfido2. Set FIDO2=0 to build without it;
# stores that have security keys enrolled then open with the password only.
FIDO2 ?= 1
ifeq ($(FIDO2),1)
CXXFLAGS += -DHAVE_FIDO2
LIBS += -lfido2
endif

DetectOS:
	-@make $(UNAME)

Linux: pwm.cc pwm.h test_linux
	$(CXX) $(CXXFLAGS) $(PORTABLE) pwm.cc $(LIBS) -o pwm

OpenBSD: pwm.cc pwm.h test_openbsd
	$(CXX) $(CXXFLAGS) pwm.cc $(LIBS) -o pwm

fmt: pwm.cc pwm.h test/test_pwm.cc
	clang-format -i pwm.h pwm.cc test/test_pwm.cc

# Tests stand in a simulated authenticator for the real one, so they neither
# need nor link libfido2.
TESTFLAGS=--std=c++20 -g -pedantic -Wall -Wextra -Wno-unused-function -Wno-write-strings -DTESTING
TESTLIBS=-lz -lcrypto

test_openbsd: pwm.h pwm.cc test/test_pwm.cc
	$(CXX) $(TESTFLAGS) -I. -Itest pwm.cc test/test_pwm.cc $(TESTLIBS) -o test_pwm
	./test_pwm

test_linux: pwm.h pwm.cc test/test_pwm.cc
	$(CXX) $(TESTFLAGS) -I. -Itest $(PORTABLE) pwm.cc test/test_pwm.cc $(TESTLIBS) -o test_pwm
	./test_pwm

clean:
	rm -f pwm *.core test_pwm *.o *.tmp

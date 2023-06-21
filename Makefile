UNAME = `uname`
PORTABLE = -I portable portable/arc4random.c portable/readpassphrase.c portable/pledge.c

DetectOS:
	-@make $(UNAME)

Linux: pwm.cc pwm.h test_linux
	clang++ --std=c++17 -g -lz -lcrypto -pedantic -Wall -Wextra $(PORTABLE) pwm.cc -o pwm

OpenBSD: pwm.cc pwm.h test_openbsd
	clang++ --std=c++17 -g -lz -lcrypto -pedantic -Wall -Wextra pwm.cc -o pwm

fmt: pwm.cc pwm.h test/test_pwm.cc
	clang-format -i pwm.h pwm.cc test/test_pwm.cc

test_openbsd: pwm.h pwm.cc test/test_pwm.cc
	clang++ --std=c++17 -DTESTING -g -lz -lcrypto -pedantic -Wall -Wextra -Wno-unused-function -I. -Itest pwm.cc test/test_pwm.cc -o test_pwm
	./test_pwm

test_linux: pwm.h pwm.cc test/test_pwm.cc
	clang++ --std=c++17 -DTESTING -g -lz -lcrypto -pedantic -Wall -Wextra -Wno-unused-function -I. -Itest $(PORTABLE) pwm.cc test/test_pwm.cc -o test_pwm
	./test_pwm

clean:
	rm -f pwm *.core test_pwm *.o *.tmp

all: pwm.cc
	clang++ --std=c++17 -g -lz -lcrypto -pedantic -Wall -Wextra -I portable portable/arc4random.c portable/readpassphrase.c portable/pledge.c pwm.cc -o pwm

fmt: pwm.cc pwm.h test/test_pwm.cc
	clang-format -i pwm.h pwm.cc test/test_pwm.cc

test: test_pwm run_tests

test_pwm: pwm.h pwm.cc test/test_pwm.cc
	clang++ --std=c++17 -DTESTING -g -lz -lcrypto -pedantic -Wall -Wextra -Wno-unused-function -I. -Itest -I portable portable/arc4random.c portable/readpassphrase.c portable/pledge.c pwm.cc test/test_pwm.cc -o test_pwm

run_tests: test_pwm
	./test_pwm

clean:
	rm -f pwm *.core test_pwm *.o *.tmp

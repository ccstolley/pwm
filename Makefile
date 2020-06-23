all: pwm.cc
	clang++ -g -lz -lcrypto -pedantic -Wall -Wextra pwm.cc -o pwm

fmt: pwm.cc pwm.h test/test_pwm.cc
	clang-format -i pwm.h pwm.cc test/test_pwm.cc

test: test_pwm run_tests

test_pwm: pwm.h pwm.cc test/test_pwm.cc
	clang++ -DTESTING -g -lz -lcrypto -pedantic -Wall -Wextra -I. -Itest pwm.cc test/test_pwm.cc -o test_pwm

run_tests: test_pwm
	./test_pwm

clean:
	rm -f pwm *.core test_pwm *.o *.tmp

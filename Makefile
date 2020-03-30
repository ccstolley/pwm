all: pwm.cc
	clang -std=c++17 -lstdc++ -lz -lcrypto -pedantic -Wall -Wextra pwm.cc -o pwm

fmt: pwm.cc
	clang-format -i pwm.cc

clean:
	rm -f pwm pwm.core *.o

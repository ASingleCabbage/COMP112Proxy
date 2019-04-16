# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall -std=gnu11 -Wextra $(IFLAGS)

IFLAGS  = -I/comp/40/include -I/usr/sup/cii40/include/cii
LDFLAGS = -g -L/comp/40/lib64 -L/usr/sup/cii40/lib64 -lum-dis -lcii
LDLIBS  = -lcii40 -lm -lssl -lcrypto

EXECS = test proxy_simple proxy_multiple

all: $(EXECS)

test: test.o request_parser.o response_parser.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

proxy_simple: proxy_simple.o request_parser.o response_parser.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

proxy_multiple: proxy_multiple.o request_parser.o response_parser.o double_table.o ssl_utils.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# To get *any* .o file, compile its .c file with the following rule.
%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(EXECS) *.o

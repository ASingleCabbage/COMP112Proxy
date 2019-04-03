# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall -std=gnu11

# the build target executable:
TARGET = test

# To get *any* .o file, compile its .c file with the following rule.
%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) -c $< -o $@

all: $(TARGET)

$(TARGET): $(TARGET).o request_parser.o response_parser.o
	$(CC) $(CFLAGS) $^ -o $(TARGET)

clean:
	$(RM) $(TARGET) client_3

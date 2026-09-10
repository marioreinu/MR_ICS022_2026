CC = gcc

CFLAGS = -Wall -Wextra -pedantic -std=c17

TARGET = sfm

SRC = \
	src/main.c \
	src/auth.c \
	src/crypto.c \
	src/fileops.c \
	src/logging.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
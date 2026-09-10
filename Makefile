CC = gcc

CFLAGS = -Wall -Wextra -pedantic -std=c17

TARGET = sfm

SRC = src/main.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
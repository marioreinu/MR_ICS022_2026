CC := gcc

OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)

CFLAGS := -Wall -Wextra -Wconversion -std=c11 -Iinclude -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS := -lssl -lcrypto

ifneq ($(OPENSSL_PREFIX),)
CFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,obj/%.o,$(SRC))
BIN := bin/secfile

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ) | bin
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

obj/%.o: src/%.c | obj
	$(CC) $(CFLAGS) -c $< -o $@

bin obj:
	mkdir -p $@

clean:
	rm -rf bin obj
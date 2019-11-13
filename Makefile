CC=gcc
CPPFLAGS=-g -ljansson -lnftables
SRC=nft_api.c
TARGET=main

.PHONY : all clean

all :
	$(CC) $(SRC) -o $(TARGET) $(CPPFLAGS)

clean :
	rm main

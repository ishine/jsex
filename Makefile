# Makefile for JSex Test tool
# by Vikman
# April 29, 2017
#
# Syntax: make [ DEBUG=1 ] [ all | clean ]

CC = gcc
RM = rm -f
CFLAGS = -pipe -Wall -Wextra

TARGET = jsex
OBJECTS = main.o jsex.o

ifeq ($(DEBUG), 1)
	CFLAGS += -g
else
	CFLAGS += -O2
endif

.PHONY: all clean

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

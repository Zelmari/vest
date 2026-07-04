CC = gcc
CFLAGS = -fno-stack-protector
LDFLAGS = -no-pie
TARGET = vuln
SRC = vuln.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

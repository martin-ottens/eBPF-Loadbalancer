CC = gcc
CFLAGS = -Wall -O2 -pthread

TARGET = keepalive
SRC = keepalive.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

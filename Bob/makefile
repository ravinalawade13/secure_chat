
CC = g++
CFLAGS = -Wall -std=c++11
LIBS = -lssl -lcrypto -lpthread

TARGET = chat
SRC = p2pChat.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(TARGET)

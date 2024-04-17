
CC = g++
CFLAGS = -Wall -std=c++11
LIBS = -lssl -lcrypto -lpthread

TARGET = secure_chat_active_interceptor
SRC = secure_chat_active_interceptor.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(TARGET)

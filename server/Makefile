CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -lws2_32 -lssl -lcrypto
SRC      := server.cpp net_io.cpp
TARGET   := server.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) net_io.h platform.h
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

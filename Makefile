TARGET = main

CC = g++

CFLAGS = -g -Wall

LIBS = -lpcap

SRCS = main.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)



$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
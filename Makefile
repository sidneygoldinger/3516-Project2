wireview: wireview.cpp
	g++ -lpcap -o wireview wireview.cpp

all: wireview.cpp
	g++ -o wireview wireview.cpp -lpcap

clean:
	$(RM) wireview
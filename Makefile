wireview: wireview.cpp
	g++ -lpcap -o wireview wireview.cpp

all: wireview.cpp
	g++ -o wireview wireview.cpp -lpcap -std=c++11
	# -std=c++11 maybe?

clean:
	$(RM) wireview
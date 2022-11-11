wireview: wireview.cpp
	gcc -lpcap -o wireview wireview.cpp

all: wireview.cpp
	gcc -lpcap -o wireview wireview.cpp

clean:
	$(RM) wireview
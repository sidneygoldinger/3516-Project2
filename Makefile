wireview: wireview.cpp
	g++ -lpcap -o wireview wireview.cpp

all: wireview.cpp
	g++ -lpcap -o wireview wireview.cpp
	# note: do 'gcc -o wireview wireview.c -lpcap' if that errors

clean:
	$(RM) wireview
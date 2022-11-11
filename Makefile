wireview: wireview.cpp
	gcc -lpcap -o wireview wireview.cpp

all: wireview.cpp
	gcc -lpcap -o wireview wireview.cpp
	# note: do 'gcc -o wireview wireview.c -lpcap' if that errors

clean:
	$(RM) wireview
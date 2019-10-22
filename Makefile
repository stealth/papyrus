
all:
	cc -fPIC -fpic -std=c11 -Wall -pedantic -c papyrus.c
	gcc -shared -pie papyrus.o -o papyrus


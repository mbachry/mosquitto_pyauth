DEBUG = -DPYAUTH_DEBUG
CFLAGS = -std=gnu99 -fPIC -I../lib -I../src `python2.7-config --includes` -Wall -Wextra -ggdb3
LIBS = `python2.7-config --libs`

all : auth_plugin_pyauth.so

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

auth_plugin_pyauth.so : auth_plugin_pyauth.o
	$(CC) $(CFLAGS) -shared -o $@ $^  $(LIBS)

clean :
	rm -f auth_plugin_pyauth.so *.o

.PHONY: all clean

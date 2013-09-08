DEBUG = -DPYAUTH_DEBUG
CFLAGS = -std=gnu99 -fPIC -I../lib `python-config --includes` -Wall -Wextra -ggdb3
LIBS = `python-config --libs`
DESTDIR = /usr

all : auth_plugin_pyauth.so

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

auth_plugin_pyauth.so : auth_plugin_pyauth.o
	$(CC) $(CFLAGS) -shared -o $@ $^  $(LIBS)

install: auth_plugin_pyauth.so
	mkdir -p $(DESTDIR)/lib/mosquitto
	install -m 755 auth_plugin_pyauth.so $(DESTDIR)/lib/mosquitto

clean :
	rm -f auth_plugin_pyauth.so *.o

.PHONY: all clean

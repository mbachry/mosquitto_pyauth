MOSQUITTO_SRC ?= ./
CFLAGS = -std=gnu99 -fPIC -I../lib -I../src `python-config --includes` -Wall -Wextra -O2
ifdef DEBUG
CFLAGS += -DPYAUTH_DEBUG -O0 -ggdb3
endif
LIBS = `python-config --libs` -lmosquitto -lcares
DESTDIR = /usr

CFLAGS += -I$(MOSQUITTO_SRC)/src/
CFLAGS += -I$(MOSQUITTO_SRC)/lib/

#LDFLAGS =-lmosquitto 
LDFLAGS += -L$(MOSQUITTO_SRC)/lib/

all : auth_plugin_pyauth.so

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

auth_plugin_pyauth.so : auth_plugin_pyauth.o
	$(CC) $(CFLAGS) -shared -o $@ $^  $(LIBS)  $(LDFLAGS)

install: auth_plugin_pyauth.so
	mkdir -p $(DESTDIR)/lib/mosquitto
	install -s -m 755 auth_plugin_pyauth.so $(DESTDIR)/lib/mosquitto

clean :
	rm -f auth_plugin_pyauth.so *.o

.PHONY: all clean

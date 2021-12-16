#
# 'make'        build executable file 'mycc'
# 'make clean'  removes all .o and executable files
#

CC = gcc
CFLAGS = -Wall -O2 -MMD -static 
INCLUDES =
LFLAGS =
LIBS =
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
# define the executable file 
MAIN = signEd

.PHONY: depend clean

all:    $(MAIN)
	@echo  Program has been compiled

.PHONY: install
install: $(MAIN)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $< $(DESTDIR)$(PREFIX)/bin/$(MAIN)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) -r -f src/*.o src/*.d src/*~ $(MAIN)


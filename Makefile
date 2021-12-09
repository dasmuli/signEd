#
# 'make'        build executable file 'mycc'
# 'make clean'  removes all .o and executable files
#

CC = gcc
CFLAGS = -Wall -g -MMD
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

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)


MAINPROG=dhcp-stats

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:.c=.o)
FLAGS=-std=gnu99 -pedantic -Wall -Wextra 

all: $(SRCS) $(MAINPROG)

$(MAINPROG): $(OBJS)
	gcc $(FLAGS) $(OBJS) -o $@ -lpcap

.c.o:
	gcc $(FLAGS) -c $< -o $@ -lpcap

clean:
	rm *.o $(MAINPROG)
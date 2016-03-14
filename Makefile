CFLAGS = -W -Wall -O -g
OBJS = find-dhcp-servers.o list_node.o
LIBS = -lpcap

all: find-dhcp-servers

clean:
	rm -f $(OBJS) find-dhcp-servers

find-dhcp-servers: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

find-dhcp-servers.o : find-dhcp-servers.c list_node.h
list_node.o : list_node.c list_node.h

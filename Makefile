
CC = gcc
CPPFLAGS = -I. $(ccan_includes)
CFLAGS = -Wall -Werror -Wextra -ggdb --std=c99
LDFLAGS = -fwhole-program

sbsign_objs = sbsign.o idc.o image.o
sbverify_objs = sbverify.o idc.o image.o
libs = -lbfd -lcrypto

ccan_objs = lib/ccan/libccan.a
ccan_includes = -I./lib/ccan

tools = sbsign sbverify

all: $(tools)

sbsign: $(sbsign_objs) $(ccan_objs)
	$(LINK.o) -o $@ $^ $(libs)

sbverify: $(sbverify_objs) $(ccan_objs)
	$(LINK.o) -o $@ $^ $(libs)

gen-keyfiles: gen-keyfiles.o $(ccan_objs)
	$(LINK.o) -o $@ $^ $(libs)
gen-keyfiles: libs = -luuid

$(ccan_objs):
	cd $(@D) && $(MAKE)

clean:
	rm -f $(tools)
	rm -f *.o

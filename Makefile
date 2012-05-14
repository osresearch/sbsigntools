
# compile options
CC = gcc
CPPFLAGS = -I. $(ccan_includes)
CFLAGS = -Wall -Werror -Wextra -ggdb --std=c99
LDFLAGS = -fwhole-program

# build configuration
sbsign_objs = sbsign.o idc.o image.o
sbverify_objs = sbverify.o idc.o image.o
ccan_objs = lib/ccan/libccan.a
ccan_includes = -I./lib/ccan
libs = -lbfd -lcrypto

# install paths
DESTDIR ?=
prefix ?= /usr
bindir ?= ${prefix}/bin
install_dirs = install -m 755 -d $(DESTDIR)$(bindir)
install_bin = install -m 755 -t $(DESTDIR)$(bindir)

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

install: $(tools)
	$(install_dirs)
	$(install_bin) $(tools)
.PHONY: install

clean:
	rm -f $(tools)
	rm -f *.o

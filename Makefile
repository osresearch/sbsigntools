
# compile options
CC = gcc
CPPFLAGS = -I. $(ccan_includes)
CFLAGS = -Wall -Werror -Wextra -ggdb --std=c99
LDFLAGS = -fwhole-program

# build configuration
sbsign_objs = sbsign.o idc.o image.o
sbverify_objs = sbverify.o idc.o image.o
libs = -lbfd -lcrypto
objs = $(sort $(sbsign_objs) $(sbverify_objs))

# ccan build configuration
ccan_dir = lib/ccan
ccan_objs = $(ccan_dir)/libccan.a
ccan_includes = -I./lib/ccan
ccan_modules = talloc
ccan_stamp = $(ccan_dir)/Makefile
ccan_config = $(ccan_dir)/config.h

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

# ccan build
$(ccan_objs): $(ccan_stamp)
	cd $(@D) && $(MAKE)

$(ccan_config): $(ccan_stamp)
	cd $(@D) && $(MAKE) config.h

# built objects may require headers from ccan
$(objs): $(ccan_stamp) $(ccan_config)

install: $(tools)
	$(install_dirs)
	$(install_bin) $(tools)
.PHONY: install

clean:
	rm -f $(tools)
	rm -f *.o

distclean: clean
	rm -rf $(ccan_dir)

# ccan import
ccan_source_dir = lib/ccan.git
ccan_source_file = $(ccan_source_dir)/Makefile

$(ccan_source_file):
	git submodule init
	git submodule update

$(ccan_stamp): $(ccan_source_file)
	$(ccan_source_dir)/tools/create-ccan-tree --exclude-tests \
		$(@D) $(ccan_modules)


AM_CFLAGS = -Wall -Wextra --std=gnu99

bin_PROGRAMS = sbsign sbverify sbattach sbvarsign

coff_headers = coff/external.h coff/pe.h coff/i386.h coff/x86_64.h

common_SOURCES = idc.c idc.h image.c image.h fileio.c fileio.h $(coff_headers)
common_LDADD = lib/ccan/libccan.a $(libcrypto_LIBS)
common_CFLAGS = -I$(srcdir)/lib/ccan/

sbsign_SOURCES = sbsign.c $(common_SOURCES)
sbsign_LDADD = $(common_LDADD)
sbsign_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbverify_SOURCES = sbverify.c $(common_SOURCES)
sbverify_LDADD = $(common_LDADD)
sbverify_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbattach_SOURCES = sbattach.c $(common_SOURCES)
sbattach_LDADD = $(common_LDADD)
sbattach_CFLAGS = $(AM_CFLAGS) $(common_CFLAGS)

sbvarsign_SOURCES = sbvarsign.c $(common_SOURCES)
sbvarsign_LDADD = $(common_LDADD) $(uuid_LIBS)
sbvarsign_CPPFLAGS = $(EFI_CPPFLAGS)
sbvarsign_CFLAGS = $(AM_CFLAGS) $(uuid_CFLAGS) $(common_CFLAGS)


man1_MANS = docs/sbsign.1 docs/sbverify.1 docs/sbattach.1

EXTRA_DIST = docs/sbsign.1.in docs/sbverify.1.in docs/sbattach.1.in
CLEANFILES = $(man1_MANS)

$(top_builddir)/docs/%.1: $(srcdir)/docs/%.1.in $(top_builddir)/%
	$(MKDIR_P) $(@D)
	$(HELP2MAN) --no-info -i $< -o $@ $(top_builddir)/$*

SUBDIRS = lib/ccan . tests

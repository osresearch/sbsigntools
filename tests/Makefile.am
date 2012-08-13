
AUTOMAKE_OPTIONS = parallel-tests

test_key = private-key.rsa
test_cert = public-cert.pem
test_arches = x86_64 i386
test_images = test-x86_64.pecoff test-i386.pecoff

check_PROGRAMS = test-x86_64.pecoff test-i386.pecoff
check_DATA = $(test_key) $(test_cert)
check_SCRIPTS = test-wrapper.sh

test_i386_pecoff_SOURCES = test.S test-i386.lds
test_x86_64_pecoff_SOURCES = test.S test-x86_64.lds

test-%.pecoff: test-%.elf
	$(OBJCOPY) -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc \
		--target=efi-app-$(test_image_arch) $^ $@
	$(STRIP) $@

test-x86_64.pecoff: test_image_arch = x86-64
test-x86_64.pecoff: test_lds = $(srcdir)/test-x86_64.lds
test-x86_64.pecoff: ASFLAGS += -m64
test-x86_64.pecoff: LDFLAGS += -m64
test-i386.pecoff: test_image_arch = i386
test-i386.pecoff: test_lds = $(srcdir)/test-i386.lds
test-i386.pecoff: ASFLAGS += -m32
test-i386.pecoff: LDFLAGS += -m32

test-%.elf: LDFLAGS = -nostdlib -T $(test_lds)
test-%.elf: test-%.$(OBJEXT) $(test_lds)
	$(LINK) $<

test-%.$(OBJEXT): $(srcdir)/test.S
	$(COMPILE.S) -o $@ $^

$(test_key): Makefile
	openssl genrsa -out $@ 2048

$(test_cert): $(test_key) Makefile
	openssl req -x509 -sha256 -subj '/' -new -key $< -out $@

TESTS = sign-verify.sh \
	sign-verify-detached.sh \
	sign-detach-verify.sh \
	sign-attach-verify.sh \
	sign-missing-image.sh \
	sign-missing-cert.sh \
	sign-missing-key.sh \
	verify-missing-image.sh \
	verify-missing-cert.sh \
	sign-invalidattach-verify.sh \
	cert-table-header.sh \
	resign-warning.sh \
	reattach-warning.sh \
	detach-remove.sh

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = TEST_ARCHES="$(test_arches)" $(srcdir)/test-wrapper.sh

EXTRA_DIST = $(test_lds) test.S $(TESTS) $(check_SCRIPTS)
CLEANFILES = $(test_key) $(test_cert) $(test_images)

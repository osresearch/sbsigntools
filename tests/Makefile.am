
test_key = private-key.rsa
test_cert = public-cert.pem
test_image = test.pecoff

check_PROGRAMS = test.pecoff
check_DATA = $(test_key) $(test_cert)
check_SCRIPTS = common.sh

test_image_arch = x86-64
test_lds = $(srcdir)/test.lds

test_pecoff_SOURCES =

test.pecoff: test.elf
	$(OBJCOPY) -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc \
		--target=efi-app-$(test_image_arch) $^ $@
	$(STRIP) $@

test.elf: LDFLAGS = -nostdlib -T $(test_lds) -m64
test.elf: test.$(OBJEXT) $(test_lds)
	$(LINK) $<

.INTERMEDIATE: test.elf

test.$(OBJEXT): ASFLAGS = -m64
test.$(OBJEXT): $(srcdir)/test.S
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
	reattach-warning.sh

EXTRA_DIST = $(test_lds) test.S $(TESTS) $(check_SCRIPTS)
CLEANFILES = $(test_key) $(test_cert) $(test_image)

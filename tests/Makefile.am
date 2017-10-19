
AUTOMAKE_OPTIONS = parallel-tests

test_key = private-key.rsa
test_cert = public-cert.pem
test_arches = $(EFI_ARCH)

check_PROGRAMS = test.pecoff

# override the automake rule to say we build from .elf files
test.pecoff$(EXEEXT): test.elf

if TEST_BINARY_FORMAT
EFILDFLAGS = --defsym=EFI_SUBSYSTEM=0x0a
FORMAT = -O binary
else
FORMAT = --target=efi-app-$(EFI_ARCH)
endif
check_DATA = $(test_key) $(test_cert)
check_SCRIPTS = test-wrapper.sh

.elf.pecoff:
	echo "TEST ARCHES $(test_arches) TEST_COMPAT=$(TEST_COMPAT_FALSE)"
	$(OBJCOPY) -j .text -j .sdata -j .data \
		-j .dynamic -j .dynsym  -j .rel \
		-j .rela -j .reloc \
		$(FORMAT) $^ $@

.$(OBJEXT).elf:
	$(LD) $(EFILDFLAGS) -nostdlib -L $(CRTPATH) -shared -Bsymbolic $(CRTPATH)/crt0-efi-$(EFI_ARCH).o -T elf_$(EFI_ARCH)_efi.lds $< -o $@ -lefi -lgnuefi

AM_CFLAGS=-fpic -I/usr/include/efi -I/usr/include/efi/$(EFI_ARCH)

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
	resign-warning.sh \
	reattach-warning.sh

if !TEST_BINARY_FORMAT
##
# These tests involve objdump which will fail because the format
# is not recognised. Someone needs to fix arm bfd to add efi
##
TESTS +=	cert-table-header.sh \
		detach-remove.sh
endif


TEST_EXTENSIONS = .sh
AM_TESTS_ENVIRONMENT = TEST_ARCHES='$(test_arches)'; export TEST_ARCHES;
SH_LOG_COMPILER = $(srcdir)/test-wrapper.sh

EXTRA_DIST = test.S $(TESTS) $(check_SCRIPTS)
CLEANFILES = $(test_key) $(test_cert)

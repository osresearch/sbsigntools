#!/bin/bash

ccan_modules=talloc

# Add ccan upstream sources
if [ ! -e lib/ccan.git/Makefile ]
then
	git submodule init
	git submodule update
fi

# create ccan build tree
if [ ! -e lib/ccan ]
then
	lib/ccan.git/tools/create-ccan-tree \
		--build-type=automake lib/ccan $ccan_modules
fi

# Create generatable docs from git
(
	echo "Authors of sbsigntool:"
	echo
	git log --format='%an' | sort -u | sed 's,^,\t,'
) > AUTHORS

# Generate simple ChangeLog
git log --date=short --format='%ad %t %an <%ae>%n%n  * %s%n' > ChangeLog

# automagic
aclocal
autoheader
autoconf
automake --add-missing -Wno-portability

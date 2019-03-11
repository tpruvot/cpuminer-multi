#!/bin/bash

# Linux build, optimised for ARM devices

if [ ! -e configure ]; then
	echo "Creating configure..."
	rm -rf autom4te.cache
	rm -f Makefile.in aclocal.m4 autom4te.cache compat/Makefile.in
	rm -f compile config.guess config.sub config.status configure
	rm -f cpuminer-config.h.in depcomp install-sh missing
	if ./autogen.sh; then
		echo "  => done."
	else
		exit 1
	fi
fi

if [ -e Makefile ]; then
	echo "Cleaning previous build..."
	make distclean
	echo "  => done."
fi

echo "Configuring..."

# --disable-assembly: some ASM code doesn't build on ARM
# Note: we don't enable -flto, it doesn't bring anything here but slows down
# the build a lot. If needed, just add -flto to the CFLAGS string.
# normal build.
./configure --with-crypto --with-curl --disable-assembly CC=gcc CXX=g++ CFLAGS="-Ofast -fuse-linker-plugin -ftree-loop-if-convert-stores -march=native" LDFLAGS="-march=native"

# debug build
#./configure --with-crypto --with-curl --disable-assembly CC=gcc CXX=g++ CFLAGS="-O0 -g3 -fuse-linker-plugin -ftree-loop-if-convert-stores -march=native" LDFLAGS="-g3 -march=native"

[ $? = 0 ] || exit $?
echo "  => done."

if [ -z "$NPROC" ]; then
	NPROC=$(nproc 2>/dev/null)
	NPROC=${NPROC:-1}
fi

echo "Compiling on $NPROC processes..."

make -j $NPROC

if [ $? != 0 ]; then
	echo "Compilation failed (make=$?)".
	echo "Common causes: missing libjansson-dev libcurl4-openssl-dev libssl-dev"
	echo "If you pulled updates into this directory, remove configure and try again."
	exit 1
fi
echo "  => done."

echo '$ ls -l cpuminer'
ls -l cpuminer

echo "Stripping..."

strip -s cpuminer

[ $? = 0 ] || exit $?
echo "  => done."

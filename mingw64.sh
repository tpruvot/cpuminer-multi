./autogen.sh

CURL_PREFIX=/usr/local
SSL_PREFIX=/usr/local/ssl

# gcc 4.4
extracflags="-O3 -Wall -D_REENTRANT -fmerge-all-constants" # -funroll-loops -fvariable-expansion-in-unroller -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# gcc 4.8+
# extracflags="$extracflags -Ofast -fuse-linker-plugin -ftree-loop-if-convert-stores" # -flto "

# extracflags="$extracflags -march=native"

# extracflags="-pg -static -fno-inline-small-functions"
CFLAGS="-DCURL_STATICLIB -DOPENSSL_NO_ASM -DUSE_ASM -static-libgcc $extracflags"
# CPPFLAGS=""

# icon
windres res/icon.rc icon.o

./configure --build=x86_64-w64-mingw32 --with-crypto=$SSL_PREFIX --with-curl=$CURL_PREFIX \
	CFLAGS="$CFLAGS" CPPFLAGS="$CPPFLAGS" LDFLAGS="icon.o"

make

strip -p --strip-debug --strip-unneeded cpuminer.exe

if [ -e sign.sh ] ; then
. sign.sh
fi


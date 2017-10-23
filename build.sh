#!/bin/bash

if [ "$OS" = "Windows_NT" ]; then
    ./mingw64.sh
    exit 0
fi

# Linux build

make clean || echo clean

rm -f config.status
./autogen.sh || echo done

# Ubuntu 10.04 (gcc 4.4)
# extracflags="-O3 -march=native -Wall -D_REENTRANT -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# Debian 7.7 / Ubuntu 14.04 (gcc 4.7+)
extracflags="$extracflags -Ofast -flto -fuse-linker-plugin -ftree-loop-if-convert-stores"

found_arm="no"

if [ ! "0" = `cat /proc/cpuinfo | grep -c avx` ]; then
    # march native doesn't always works, ex. some Pentium Gxxx (no avx)
    extracflags="$extracflags -march=native"
fi

if [ ! "0" = `grep -i ^Features /proc/cpuinfo | grep -c neon` ]; then
	    # add general ARM neon support on Arm CPUs
            extracflags="$extracflags -march=armv7-a -mfloat-abi=hard -mfpu=neon-vfpv4  -funsafe-math-optimizations -mtune=cortex-a7"
            found_arm="yes"
fi

if [ ! "0" = `grep -i ^Hardware /proc/cpuinfo | egrep -c -e ODROID-C2 -e sun50iw1p1` ]; then
            # add ARM neon support on Odroid-C2 (aarch64) boards
            extracflags="$extracflags -march=armv8-a+fp+simd+crc+lse -mtune=cortex-a53"
	    found_arm="yes"
fi

if [ ! "0" = `grep -i ^Hardware /proc/cpuinfo | grep -c ODROID-XU3` ]; then
            # add ARM neon support on ODROID XU3,XU4 and HC1 Boards (Exynos5422)
            extracflags="$extracflags -march=armv7-a -mfloat-abi=hard -mfpu=neon-vfpv4  -funsafe-math-optimizations -mtune=cortex-a15.cortex-a7"
	    found_arm="yes"
fi

if [ "$found_arm" = "yes" ]; then
	./configure --with-crypto --with-curl CFLAGS="-O2 $extracflags -pg" --disable-assembly 
else
	./configure --with-crypto --with-curl CFLAGS="-O2 $extracflags -DUSE_ASM -pg"
fi

make -j 4

strip -s cpuminer

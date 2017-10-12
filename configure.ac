AC_INIT([cpuminer-multi], [1.3.3])

AC_PREREQ([2.59c])
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([cpu-miner.c])
AC_CONFIG_HEADERS([cpuminer-config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC_C99
AC_PROG_GCC_TRADITIONAL
AM_PROG_CC_C_O
AM_PROG_AS
AC_PROG_RANLIB
AC_PROG_CXX

dnl Checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/endian.h sys/param.h syslog.h])
# sys/sysctl.h requires sys/types.h on FreeBSD
# sys/sysctl.h requires sys/param.h on OpenBSD
AC_CHECK_HEADERS([sys/sysctl.h], [], [],
[#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

AC_CHECK_DECLS([be32dec, le32dec, be32enc, le32enc, le16dec, le16enc], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_FUNC_ALLOCA
AC_CHECK_FUNCS([getopt_long])

MINGW_TARGET=`$CC -dumpmachine 2>&1`
case $MINGW_TARGET in
  arm*-*-*)
    have_arm=true
    ;;
  aarch64*-*-*)
    have_arm=true
    ;;
  i*86-*-mingw*)
    have_x86=true
    have_win32=true
    CFLAGS="-Icompat/pthreads $CFLAGS"
    PTHREAD_LDFLAGS="-Lcompat/pthreads/x86"
    WS2_LIBS="-lws2_32"
    ;;
  x86_64-*-mingw*|amd64-*-mingw*)
    have_x86_64=true
    have_win32=true
    CFLAGS="-Icompat/pthreads $CFLAGS"
    PTHREAD_LDFLAGS="-Lcompat/pthreads/x64"
    # SHOULD BE AT END! after -lcrypto #
    WS2_LIBS="-L/mingw/x86_64-w64-mingw32/lib -lws2_32"
    ;;
  i*86-*-*)
    have_x86=true
    ;;
  x86_64-*-*|amd64-*-*)
    have_x86_64=true
    ;;
esac

AC_ARG_ENABLE([assembly],
  AS_HELP_STRING([--disable-assembly], [disable assembly-language routines]))
if test x$enable_assembly != xno; then
  AC_DEFINE([USE_ASM], [1], [Define to 1 if assembly routines are wanted.])
fi

if test x$enable_assembly != xno -a x$have_x86_64 = xtrue
then
  AC_MSG_CHECKING(whether we can compile AVX code)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vmovdqa %ymm0, %ymm1");])],
    AC_DEFINE(USE_AVX, 1, [Define to 1 if AVX assembly is available.])
    AC_MSG_RESULT(yes)
    AC_MSG_CHECKING(whether we can compile XOP code)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vprotd \$7, %xmm0, %xmm1");])],
      AC_DEFINE(USE_XOP, 1, [Define to 1 if XOP assembly is available.])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
      AC_MSG_WARN([The assembler does not support the XOP instruction set.])
    )
    AC_MSG_CHECKING(whether we can compile AVX2 code)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vpaddd %ymm0, %ymm1, %ymm2");])],
      AC_DEFINE(USE_AVX2, 1, [Define to 1 if AVX2 assembly is available.])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
      AC_MSG_WARN([The assembler does not support the AVX2 instruction set.])
    )
  ,
    AC_MSG_RESULT(no)
    AC_MSG_WARN([The assembler does not support the AVX instruction set.])
  )
fi

AC_CHECK_LIB(jansson, json_loads, request_jansson=false, request_jansson=true)

# GC2 for GNU static
if test "x$OS" = "xWindows_NT" ; then
   # MinGW
   AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthreadGC2",[])
else
   AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthread",[])
fi

LDFLAGS="$PTHREAD_LDFLAGS $LDFLAGS"
# PTHREAD_LIBS="$PTHREAD_LIBS"

AC_MSG_CHECKING(whether __uint128_t is supported)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([static __uint128_t i = 100;])],
      AC_DEFINE(USE_INT128, 1, [Define if __uint128_t is available])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
)

# allow if <var> in Makefile.am
AM_CONDITIONAL([WANT_JANSSON], [test x$request_jansson = xtrue])
AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([USE_ASM], [test x$enable_assembly != xno])
AM_CONDITIONAL([ARCH_x86], [test x$have_x86 = xtrue])
AM_CONDITIONAL([ARCH_x86_64], [test x$have_x86_64 = xtrue])
AM_CONDITIONAL([ARCH_ARM], [test x$have_arm = xtrue])
AM_CONDITIONAL([MINGW], [test "x$OS" = "xWindows_NT"])

if test x$request_jansson = xtrue ; then
	JANSSON_LIBS="compat/jansson/libjansson.a"
else
	JANSSON_LIBS=-ljansson
fi

# libcurl install path (for mingw : --with-curl=/usr/local)
AC_ARG_WITH([curl],
   [  --with-curl=PATH         prefix where curl is installed [default=/usr]])

if test -n "$with_curl" ; then
   LIBCURL_CFLAGS="$LIBCURL_CFLAGS -I$with_curl/include"
   LIBCURL_CPPFLAGS="$LIBCURL_CPPFLAGS -I$with_curl/include"
   LIBCURL_LDFLAGS="-L$with_curl/lib $LIBCURL_LDFLAGS"
   LIBCURL="-lcurl -lz"
fi

# SSL install path (for mingw : --with-crypto=/usr/local/ssl)
AC_ARG_WITH([crypto],
   [  --with-crypto=PATH       prefix where openssl crypto is installed [default=/usr]])

if test -n "$with_crypto" ; then
   LIBCURL_CFLAGS="$LIBCURL_CFLAGS -I$with_crypto/include"
   LIBCURL_CPPFLAGS="$LIBCURL_CPPFLAGS -I$with_crypto/include"
   LIBCURL_LDFLAGS="-L$with_crypto/lib $LIBCURL_LDFLAGS"
   LIBCURL="$LIBCURL -lssl -lcrypto"
fi

CFLAGS="$CFLAGS $LIBCURL_CFLAGS"
CPPFLAGS="$CPPFLAGS $LIBCURL_CPPFLAGS"
LDFLAGS="$LDFLAGS $LIBCURL_LDFLAGS"

#AC_CHECK_LIB([z],[gzopen],[],[])
#AC_CHECK_LIB([crypto],[OPENSSL_init], crypto=yes, [AC_MSG_ERROR([OpenSSL crypto library required])])
#AC_CHECK_LIB([ssl],[SSL_new], ssl=yes, ssl=no)

# AC_CHECK_LIB([curl], [curl_multi_timeout],
#    have_libcurl=yes,
#    have_libcurl=no AC_MSG_ERROR([curl library required])
# )

# LIBCURL_CHECK_CONFIG([yes], 7.15, curlconfig=yes, curlconfig=no)

AC_SUBST(LIBCURL)
AC_SUBST(LIBCURL_CFLAGS)
AC_SUBST(LIBCURL_CPPFLAGS)
# AC_SUBST(LIBCURL_LDFLAGS)

AC_SUBST(JANSSON_LIBS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(WS2_LIBS)

AC_CONFIG_FILES([
	Makefile
	compat/Makefile
	compat/jansson/Makefile
	])
AC_OUTPUT

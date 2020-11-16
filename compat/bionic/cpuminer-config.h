/* cpuminer-config.h.in.  Adapted for arm bionic (Android 5.1.1 Tegra K1) */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the declaration of `be32dec', and to 0 if you
   don't. */
#define HAVE_DECL_BE32DEC 0

/* Define to 1 if you have the declaration of `be32enc', and to 0 if you
   don't. */
#define HAVE_DECL_BE32ENC 0

/* Define to 1 if you have the declaration of `le16dec', and to 0 if you
   don't. */
#define HAVE_DECL_LE16DEC 0

/* Define to 1 if you have the declaration of `le16enc', and to 0 if you
   don't. */
#define HAVE_DECL_LE16ENC 0

/* Define to 1 if you have the declaration of `le32dec', and to 0 if you
   don't. */
#define HAVE_DECL_LE32DEC 0

/* Define to 1 if you have the declaration of `le32enc', and to 0 if you
   don't. */
#define HAVE_DECL_LE32ENC 0

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/endian.h> header file. */
/* #undef HAVE_SYS_ENDIAN_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
#undef HAVE_SYS_SYSCTL_H

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Name of package */
#define PACKAGE "cpuminer-multi"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "cpuminer-multi"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "cpuminer-multi " VERSION

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "cpuminer-multi"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://github.com/tpruvot/cpuminer-multi"

/* Define to the version of this package. */
#define PACKAGE_VERSION VERSION

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if assembly routines are wanted. */
#define USE_ASM 1

/* Define to 1 if AVX assembly is available. */
#define USE_AVX 1

/* Define to 1 if AVX2 assembly is available. */
#define USE_AVX2 1

/* Define if __uint128_t is available */
#undef USE_INT128

/* Define to 1 if XOP assembly is available. */
#define USE_XOP 1

/* Define to `unsigned int' if <sys/types.h> does not define. */
#undef size_t


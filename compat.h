#ifndef __COMPAT_H__
#define __COMPAT_H__

#ifdef WIN32

#include <windows.h>
#include <time.h>

#ifndef localtime_r
#define localtime_r(src, dst) localtime_s(dst, src)
#endif

#define sleep(secs) Sleep((secs) * 1000)

enum {
	PRIO_PROCESS		= 0,
};

extern int opt_priority;
static __inline int setpriority(int which, int who, int prio)
{
	switch (opt_priority) {
		case 5:
			prio = THREAD_PRIORITY_TIME_CRITICAL;
			break;
		case 4:
			prio = THREAD_PRIORITY_HIGHEST;
			break;
		case 3:
			prio = THREAD_PRIORITY_ABOVE_NORMAL;
			break;
		case 2:
			prio = THREAD_PRIORITY_NORMAL;
			break;
		case 1:
			prio = THREAD_PRIORITY_BELOW_NORMAL;
			break;
		case 0:
		default:
			prio = THREAD_PRIORITY_IDLE;
	}
	return -!SetThreadPriority(GetCurrentThread(), prio);
}

#ifdef _MSC_VER
#define snprintf(...) _snprintf(__VA_ARGS__)
#define strdup(...) _strdup(__VA_ARGS__)
#define strncasecmp(x,y,z) _strnicmp(x,y,z)
#define strcasecmp(x,y) _stricmp(x,y)
#define __func__ __FUNCTION__
#define __thread __declspec(thread)
#define _ALIGN(x) __declspec(align(x))
typedef int ssize_t;

__inline int msver(void) {
	switch (_MSC_VER) {
	case 1500: return 2008;
	case 1600: return 2010;
	case 1700: return 2012;
	case 1800: return 2013;
	case 1900: return 2015;
	default: return (_MSC_VER/100);
	}
}

#include <stdlib.h>
// This static var is made to be compatible with linux/mingw (no free on string result)
// This is not thread safe but we only use that once on process start
static char dirname_buffer[_MAX_PATH] = { 0 };
static __inline char * dirname(char *file) {
	char drive[_MAX_DRIVE] = { 0 };
	char dir[_MAX_DIR] = { 0 };
	char fname[_MAX_FNAME], ext[_MAX_EXT];
	_splitpath_s(file, drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
	if (dir && strlen(dir) && dir[strlen(dir)-1] == '\\') {
		dir[strlen(dir) - 1] = '\0';
	}
	sprintf(dirname_buffer, "%s%s", drive, dir);
	return &dirname_buffer[0];
}
#endif

#endif /* WIN32 */

#ifndef _MSC_VER
#define _ALIGN(x) __attribute__ ((aligned(x)))
#endif

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#ifndef WIN32
#define MAX_PATH PATH_MAX
#endif

#endif /* __COMPAT_H__ */

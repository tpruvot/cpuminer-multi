/**
 * Unit to read cpu informations
 *
 * tpruvot 2014
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"

#ifndef WIN32

#define HWMON_PATH \
 "/sys/devices/platform/coretemp.0/hwmon/hwmon1/temp1_input"
#define HWMON_ALT \
 "/sys/class/hwmon/hwmon1/temp1_input"
#define HWMON_ALT2 \
 "/sys/class/hwmon/hwmon0/temp1_input"
#define HWMON_ALT3 \
 "/sys/devices/platform/coretemp.0/hwmon/hwmon0/temp2_input"
#define HWMON_ALT4 \
 "/sys/class/hwmon/hwmon0/temp2_input"
#define HWMON_ALT5 \
 "/sys/class/hwmon/hwmon0/device/temp1_input"

static float linux_cputemp(int core)
{
	float tc = 0.0;
	FILE *fd = fopen(HWMON_PATH, "r");
	uint32_t val = 0;

	if (!fd)
		fd = fopen(HWMON_ALT, "r");

	if (!fd)
		fd = fopen(HWMON_ALT2, "r");

	if (!fd)
		fd = fopen(HWMON_ALT3, "r");

	if (!fd)
		fd = fopen(HWMON_ALT4, "r");

	if (!fd)
                fd = fopen(HWMON_ALT5, "r");

	if (!fd)
		return tc;

	if (fscanf(fd, "%d", &val))
		tc = val / 1000.0;

	fclose(fd);
	return tc;
}

#define CPUFREQ_PATH \
 "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq"
static uint32_t linux_cpufreq(int core)
{
	FILE *fd = fopen(CPUFREQ_PATH, "r");
	uint32_t freq = 0;

	if (!fd)
		return freq;

	if (!fscanf(fd, "%d", &freq))
		return freq;

	return freq;
}

#else /* WIN32 */

static float win32_cputemp(int core)
{
	// todo
	return 0.0;
}

#endif /* !WIN32 */


/* exports */


float cpu_temp(int core)
{
#ifdef WIN32
	return win32_cputemp(core);
#else
	return linux_cputemp(core);
#endif
}

uint32_t cpu_clock(int core)
{
#ifdef WIN32
	return 0;
#else
	return linux_cpufreq(core);
#endif
}

int cpu_fanpercent()
{
	return 0;
}

#ifndef __arm__
static inline void cpuid(int functionnumber, int output[4]) {
#if defined (_MSC_VER) || defined (__INTEL_COMPILER)
	// Microsoft or Intel compiler, intrin.h included
	__cpuidex(output, functionnumber, 0);
#elif defined(__GNUC__) || defined(__clang__)
	// use inline assembly, Gnu/AT&T syntax
	int a, b, c, d;
	asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(functionnumber), "c"(0));
	output[0] = a;
	output[1] = b;
	output[2] = c;
	output[3] = d;
#else
	// unknown platform. try inline assembly with masm/intel syntax
	__asm {
		mov eax, functionnumber
		xor ecx, ecx
		cpuid;
		mov esi, output
		mov[esi], eax
		mov[esi + 4], ebx
		mov[esi + 8], ecx
		mov[esi + 12], edx
	}
#endif
}
#endif /* !__arm__ */

// http://en.wikipedia.org/wiki/CPUID
#define OSXSAVE_Flag  (1 << 27)
#define AVX1_Flag    ((1 << 28)|OSXSAVE_Flag)
#define XOP_Flag      (1 << 11)
#define FMA3_Flag    ((1 << 12)|AVX1_Flag|OSXSAVE_Flag)
#define AES_Flag      (1 << 25)
#define SSE42_Flag    (1 << 20)

#define SSE_Flag      (1 << 25) // EDX
#define SSE2_Flag     (1 << 26) // EDX

#define AVX2_Flag     (1 << 5) // ADV EBX

bool has_aes_ni()
{
#ifdef __arm__
	return false;
#else
	int cpu_info[4] = { 0 };
	cpuid(1, cpu_info);
	return cpu_info[2] & AES_Flag;
#endif
}

void bestcpu_feature(char *outbuf, int maxsz)
{
#ifdef __arm__
	sprintf(outbuf, "ARM");
#else
	int cpu_info[4] = { 0 };
	int cpu_info_adv[4] = { 0 };
	cpuid(1, cpu_info);
	cpuid(7, cpu_info_adv);
	if ((cpu_info[2] & AVX1_Flag) && (cpu_info_adv[1] & AVX2_Flag))
		sprintf(outbuf, "AVX2");
	else if (cpu_info[2] & AVX1_Flag)
		sprintf(outbuf, "AVX1");
	else if (cpu_info[2] & FMA3_Flag)
		sprintf(outbuf, "FMA3");
	else if (cpu_info[2] & XOP_Flag)
		sprintf(outbuf, "XOP");
	else if (cpu_info[2] & SSE42_Flag)
		sprintf(outbuf, "SSE42");
	else if (cpu_info[3] & SSE2_Flag)
		sprintf(outbuf, "SSE2");
	else if (cpu_info[3] & SSE_Flag)
		sprintf(outbuf, "SSE");
	else
		*outbuf = '\0';
#endif
}

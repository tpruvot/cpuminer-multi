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

	fclose(fd);
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

#if !defined(__arm__) && !defined(__aarch64__)
static inline void cpuid(int functionnumber, int output[4]) {
#ifdef _MSC_VER
	// Microsoft compiler, intrin.h included
	__cpuidex(output, functionnumber, 0);
#elif defined(__INTEL_COMPILER)
	__cpuid(output, functionnumber);
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
#else /* !__arm__ */
#define cpuid(fn, out) out[0] = 0;
#endif

// For the i7-5775C will output : Intel(R) Core(TM) i7-5775C CPU @ 3.30GHz
void cpu_getname(char *outbuf, size_t maxsz)
{
	memset(outbuf, 0, maxsz);
#ifdef WIN32
	char brand[0xC0] = { 0 };
	int output[4] = { 0 }, ext;
	cpuid(0x80000000, output);
	ext = output[0];
	if (ext >= 0x80000004) {
		for (int i = 2; i <= (ext & 0xF); i++) {
			cpuid(0x80000000+i, output);
			memcpy(&brand[(i-2) * 4*sizeof(int)], output, 4*sizeof(int));
		}
		snprintf(outbuf, maxsz, "%s", brand);
	} else {
		// Fallback, for the i7-5775C will output
		// Intel64 Family 6 Model 71 Stepping 1, GenuineIntel
		snprintf(outbuf, maxsz, "%s", getenv("PROCESSOR_IDENTIFIER"));
	}
#else
	// Intel(R) Xeon(R) CPU E3-1245 V2 @ 3.40GHz
	FILE *fd = fopen("/proc/cpuinfo", "rb");
	char *buf = NULL, *p, *eol;
	size_t size = 0;
	if (!fd) return;
	while(getdelim(&buf, &size, 0, fd) != -1) {
		if (buf && (p = strstr(buf, "model name\t")) && strstr(p, ":")) {
			p = strstr(p, ":");
			if (p) {
				p += 2;
				eol = strstr(p, "\n"); if (eol) *eol = '\0';
				snprintf(outbuf, maxsz, "%s", p);
			}
			break;
		}
	}
	free(buf);
	fclose(fd);
#endif
}

void cpu_getmodelid(char *outbuf, size_t maxsz)
{
	memset(outbuf, 0, maxsz);
#ifdef WIN32
	// For the i7-5775C will output 6:4701:8
	snprintf(outbuf, maxsz, "%s:%s:%s", getenv("PROCESSOR_LEVEL"), // hexa ?
		getenv("PROCESSOR_REVISION"), getenv("NUMBER_OF_PROCESSORS"));
#else
	FILE *fd = fopen("/proc/cpuinfo", "rb");
	char *buf = NULL, *p, *eol;
	int cpufam = 0, model = 0, stepping = 0;
	size_t size = 0;
	if (!fd) return;
	while(getdelim(&buf, &size, 0, fd) != -1) {
		if (buf && (p = strstr(buf, "cpu family\t")) && strstr(p, ":")) {
			p = strstr(p, ":");
			if (p) {
				p += 2;
				cpufam = atoi(p);
			}
		}
		if (buf && (p = strstr(buf, "model\t")) && strstr(p, ":")) {
			p = strstr(p, ":");
			if (p) {
				p += 2;
				model = atoi(p);
			}
		}
		if (buf && (p = strstr(buf, "stepping\t")) && strstr(p, ":")) {
			p = strstr(p, ":");
			if (p) {
				p += 2;
				stepping = atoi(p);
			}
		}
		if (cpufam && model && stepping) {
			snprintf(outbuf, maxsz, "%x:%02x%02x:%d", cpufam, model, stepping, num_cpus);
			outbuf[maxsz-1] = '\0';
			break;
		}
	}
	free(buf);
	fclose(fd);
#endif
}

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
#if defined(__arm__) || defined(__aarch64__)
	return false;
#else
	int cpu_info[4] = { 0 };
	cpuid(1, cpu_info);
	return cpu_info[2] & AES_Flag;
#endif
}

void cpu_bestfeature(char *outbuf, size_t maxsz)
{
#if defined(__arm__) || defined(__aarch64__)
	sprintf(outbuf, "ARM");
#else
	int cpu_info[4] = { 0 };
	int cpu_info_adv[4] = { 0 };
	cpuid(1, cpu_info);
	cpuid(7, cpu_info_adv);
	if ((cpu_info[2] & AVX1_Flag) && (cpu_info_adv[1] & AVX2_Flag))
		sprintf(outbuf, "AVX2");
	else if (cpu_info[2] & AVX1_Flag)
		sprintf(outbuf, "AVX");
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

/*
 * Copyright 2014 ccminer team
 *
 * Implementation by tpruvot (based on cgminer)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#define APIVERSION "1.1"

#ifdef WIN32
# define  _WINSOCK_DEPRECATED_NO_WARNINGS
# include <winsock2.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "miner.h"

#ifndef WIN32
# include <errno.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# define SOCKETTYPE long
# define SOCKETFAIL(a) ((a) < 0)
# define INVSOCK -1 /* INVALID_SOCKET */
# define INVINETADDR -1 /* INADDR_NONE */
# define CLOSESOCKET close
# define SOCKETINIT {}
# define SOCKERRMSG strerror(errno)
#else
# define SOCKETTYPE SOCKET
# define SOCKETFAIL(a) ((a) == SOCKET_ERROR)
# define INVSOCK INVALID_SOCKET
# define INVINETADDR INADDR_NONE
# define CLOSESOCKET closesocket
# define in_addr_t uint32_t
#endif

#define GROUP(g) (toupper(g))
#define PRIVGROUP GROUP('W')
#define NOPRIVGROUP GROUP('R')
#define ISPRIVGROUP(g) (GROUP(g) == PRIVGROUP)
#define GROUPOFFSET(g) (GROUP(g) - GROUP('A'))
#define VALIDGROUP(g) (GROUP(g) >= GROUP('A') && GROUP(g) <= GROUP('Z'))
#define COMMANDS(g) (apigroups[GROUPOFFSET(g)].commands)
#define DEFINEDGROUP(g) (ISPRIVGROUP(g) || COMMANDS(g) != NULL)
struct APIGROUPS {
	// This becomes a string like: "|cmd1|cmd2|cmd3|" so it's quick to search
	char *commands;
} apigroups['Z' - 'A' + 1]; // only A=0 to Z=25 (R: noprivs, W: allprivs)

struct IP4ACCESS {
	in_addr_t ip;
	in_addr_t mask;
	char group;
};

static int ips = 1;
static struct IP4ACCESS *ipaccess = NULL;

// Socket data buffers
#define MYBUFSIZ	16384
#define SOCK_REC_BUFSZ	1024

// Socket is on 127.0.0.1
#define QUEUE	10

#define ALLIP4 "0.0.0.0"

static const char *localaddr = "127.0.0.1";
static const char *UNAVAILABLE = " - API will not be available";
static char *buffer = NULL;
static time_t startup = 0;
static int bye = 0;

extern char *opt_api_allow;
extern int opt_api_listen; /* port */
extern int opt_api_remote;
extern uint64_t global_hashrate;
extern uint32_t solved_count;
extern uint32_t accepted_count;
extern uint32_t rejected_count;

#define cpu_threads opt_n_threads

#define USE_MONITORING
extern float cpu_temp(int);
extern uint32_t cpu_clock(int);
extern int cpu_fanpercent(void);

/***************************************************************/

static void cpustatus(int thr_id)
{
	if (thr_id >= 0 && thr_id < opt_n_threads) {
		struct cpu_info *cpu = &thr_info[thr_id].cpu;
		char buf[512]; *buf = '\0';

		cpu->thr_id = thr_id;
		cpu->khashes = thr_hashrates[thr_id] / 1000.0; //todo: stats_get_speed(thr_id, 0.0) / 1000.0;

		snprintf(buf, sizeof(buf), "CPU=%d;KHS=%.2f|", thr_id, cpu->khashes);

		// append to buffer
		strcat(buffer, buf);
	}
}

/*****************************************************************************/

/**
* Returns miner global infos
*/
static char *getsummary(char *params)
{
	char algo[64]; *algo = '\0';
	time_t ts = time(NULL);
	double uptime = difftime(ts, startup);
	double accps = (60.0 * accepted_count) / (uptime ? uptime : 1.0);

	struct cpu_info cpu = { 0 };
#ifdef USE_MONITORING
	cpu.has_monitoring = true;
	cpu.cpu_temp = cpu_temp(0);
	cpu.cpu_fan = cpu_fanpercent();
	cpu.cpu_clock = cpu_clock(0);
#endif

	get_currentalgo(algo, sizeof(algo));

	*buffer = '\0';
	sprintf(buffer, "NAME=%s;VER=%s;API=%s;"
		"ALGO=%s;CPUS=%d;KHS=%.2f;SOLV=%d;ACC=%d;REJ=%d;"
		"ACCMN=%.3f;DIFF=%.6f;TEMP=%.1f;FAN=%d;FREQ=%d;"
		"UPTIME=%.0f;TS=%u|",
		PACKAGE_NAME, PACKAGE_VERSION, APIVERSION,
		algo, opt_n_threads, (double)global_hashrate / 1000.0,
		solved_count, accepted_count, rejected_count, accps, net_diff > 0. ? net_diff : stratum_diff,
		cpu.cpu_temp, cpu.cpu_fan, cpu.cpu_clock,
		uptime, (uint32_t) ts);
	return buffer;
}

/**
 * Returns cpu/thread specific stats
 */
static char *getthreads(char *params)
{
	*buffer = '\0';
	for (int i = 0; i < opt_n_threads; i++)
		cpustatus(i);
	return buffer;
}

/**
 * Is remote control allowed ?
 */
static bool check_remote_access(void)
{
	return (opt_api_remote > 0);
}

/**
 * Change pool url (see --url parameter)
 * seturl|stratum+tcp://XeVrkPrWB7pDbdFLfKhF1Z3xpqhsx6wkH3:X@stratum+tcp://mine.xpool.ca:1131|
 * seturl|stratum+tcp://Danila.1:X@pool.ipominer.com:3335|
 */
extern bool stratum_need_reset;
static char *remote_seturl(char *params)
{
	*buffer = '\0';
	if (!check_remote_access())
		return buffer;
	parse_arg('o', params);
	stratum_need_reset = true;
	sprintf(buffer, "%s", "ok|");
	return buffer;
}

/**
 * Ask the miner to quit
 */
static char *remote_quit(char *params)
{
	*buffer = '\0';
	if (!check_remote_access())
		return buffer;
	bye = 1;
	sprintf(buffer, "%s", "bye|");
	return buffer;
}

static char *gethelp(char *params);
struct CMDS {
	const char *name;
	char *(*func)(char *);
} cmds[] = {
	{ "summary", getsummary },
	{ "threads", getthreads },
	/* remote functions */
	{ "seturl", remote_seturl },
	{ "quit",    remote_quit },
	/* keep it the last */
	{ "help",    gethelp },
};
#define CMDMAX ARRAY_SIZE(cmds)

static char *gethelp(char *params)
{
	*buffer = '\0';
	char * p = buffer;
	for (int i = 0; i < CMDMAX-1; i++)
		p += sprintf(p, "%s\n", cmds[i].name);
	sprintf(p, "|");
	return buffer;
}


static int send_result(SOCKETTYPE c, char *result)
{
	int n;
	if (!result) {
		n = (int) send(c, "", 1, 0);
	} else {
		// ignore failure - it's closed immediately anyway
		n = (int) send(c, result, (int) strlen(result) + 1, 0);
	}
	return n;
}

/* ---- Base64 Encoding/Decoding Table --- */
static const char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uchar *indata, size_t insize, char *outptr, size_t outlen)
{
	uchar ibuf[3];
	uchar obuf[4];
	int i, inputparts, inlen = (int) insize;
	size_t len = 0;
	char *output, *outbuf;

	memset(outptr, 0, outlen);

	outbuf = output = (char*)calloc(1, inlen * 4 / 3 + 4);
	if (outbuf == NULL) {
		return -1;
	}

	while (inlen > 0) {
		for (i = inputparts = 0; i < 3; i++) {
			if (inlen  > 0) {
				inputparts++;
				ibuf[i] = (uchar) *indata;
				indata++; inlen--;
			}
			else
				ibuf[i] = 0;
		}

		obuf[0] = (uchar)  ((ibuf[0] & 0xFC) >> 2);
		obuf[1] = (uchar) (((ibuf[0] & 0x03) << 4) | ((ibuf[1] & 0xF0) >> 4));
		obuf[2] = (uchar) (((ibuf[1] & 0x0F) << 2) | ((ibuf[2] & 0xC0) >> 6));
		obuf[3] = (uchar)   (ibuf[2] & 0x3F);

		switch(inputparts) {
		case 1: /* only one byte read */
			snprintf(output, 5, "%c%c==",
				table64[obuf[0]],
				table64[obuf[1]]);
			break;
		case 2: /* two bytes read */
			snprintf(output, 5, "%c%c%c=",
				table64[obuf[0]],
				table64[obuf[1]],
				table64[obuf[2]]);
			break;
		default:
			snprintf(output, 5, "%c%c%c%c",
				table64[obuf[0]],
				table64[obuf[1]],
				table64[obuf[2]],
				table64[obuf[3]] );
			break;
		}
		if ((len+4) > outlen)
			break;
		output += 4; len += 4;
	}
	len = snprintf(outptr, len, "%s", outbuf);
	// todo: seems to be missing on linux
	if (strlen(outptr) == 27)
		strcat(outptr, "=");
	free(outbuf);

	return len;
}

#include "compat/curl-for-windows/openssl/openssl/crypto/sha/sha.h"

/* websocket handshake (tested in Chrome) */
static int websocket_handshake(SOCKETTYPE c, char *result, char *clientkey)
{
	char answer[256];
	char inpkey[128] = { 0 };
	char seckey[64];
	uchar sha1[20];
	SHA_CTX ctx;

	if (opt_protocol)
		applog(LOG_DEBUG, "clientkey: %s", clientkey);

	sprintf(inpkey, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", clientkey);

	// SHA-1 test from rfc, returns in base64 "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	//sprintf(inpkey, "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inpkey, strlen(inpkey));
	SHA1_Final(sha1, &ctx);

	base64_encode(sha1, 20, seckey, sizeof(seckey));

	sprintf(answer,
		"HTTP/1.1 101 Switching Protocol\r\n"
		"Upgrade: WebSocket\r\nConnection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"Sec-WebSocket-Protocol: text\r\n"
		"\r\n", seckey);

	// data result as tcp frame

	uchar hd[10] = { 0 };
	hd[0] = 129; // 0x1 text frame (FIN + opcode)
	uint64_t datalen = (uint64_t) strlen(result);
	uint8_t frames = 2;
	if (datalen <= 125) {
		hd[1] = (uchar) (datalen);
	} else if (datalen <= 65535) {
		hd[1] = (uchar) 126;
		hd[2] = (uchar) (datalen >> 8);
		hd[3] = (uchar) (datalen);
		frames = 4;
	} else {
		hd[1] = (uchar) 127;
		hd[2] = (uchar) (datalen >> 56);
		hd[3] = (uchar) (datalen >> 48);
		hd[4] = (uchar) (datalen >> 40);
		hd[5] = (uchar) (datalen >> 32);
		hd[6] = (uchar) (datalen >> 24);
		hd[7] = (uchar) (datalen >> 16);
		hd[8] = (uchar) (datalen >> 8);
		hd[9] = (uchar) (datalen);
		frames = 10;
	}

	size_t handlen = strlen(answer);
	uchar *data = (uchar*) calloc(1, handlen + frames + (size_t) datalen + 1);
	if (data == NULL)
		return -1;
	else {
		uchar *p = data;
		// HTTP header 101
		memcpy(p, answer, handlen);
		p += handlen;
		// WebSocket Frame - Header + Data
		memcpy(p, hd, frames);
		memcpy(p + frames, result, (size_t)datalen);
		send(c, (const char*)data, (int) (strlen(answer) + frames + (size_t)datalen + 1), 0);
		free(data);
	}
	return 0;
}

/*
 * N.B. IP4 addresses are by Definition 32bit big endian on all platforms
 */
static void setup_ipaccess()
{
	char *buf = NULL, *ptr, *comma, *slash, *dot;
	int ipcount, mask, octet, i;
	char group;

	buf = (char*) calloc(1, strlen(opt_api_allow) + 1);
	if (unlikely(!buf))
		proper_exit(1);//, "Failed to malloc ipaccess buf");

	strcpy(buf, opt_api_allow);
	ipcount = 1;
	ptr = buf;
	while (*ptr) if (*(ptr++) == ',')
		ipcount++;

	// possibly more than needed, but never less
	ipaccess = (struct IP4ACCESS *) calloc(ipcount, sizeof(struct IP4ACCESS));
	if (unlikely(!ipaccess))
		proper_exit(1);//, "Failed to calloc ipaccess");

	ips = 0;
	ptr = buf;
	while (ptr && *ptr) {
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		if (*ptr == ',') {
			ptr++;
			continue;
		}

		comma = strchr(ptr, ',');
		if (comma)
			*(comma++) = '\0';

		group = NOPRIVGROUP;

		if (isalpha(*ptr) && *(ptr+1) == ':') {
			if (DEFINEDGROUP(*ptr))
				group = GROUP(*ptr);
			ptr += 2;
		}

		ipaccess[ips].group = group;

		if (strcmp(ptr, ALLIP4) == 0)
			ipaccess[ips].ip = ipaccess[ips].mask = 0;
		else
		{
			slash = strchr(ptr, '/');
			if (!slash)
				ipaccess[ips].mask = 0xffffffff;
			else {
				*(slash++) = '\0';
				mask = atoi(slash);
				if (mask < 1 || mask > 32)
					goto popipo; // skip invalid/zero

				ipaccess[ips].mask = 0;
				while (mask-- >= 0) {
					octet = 1 << (mask % 8);
					ipaccess[ips].mask |= (octet << (24 - (8 * (mask >> 3))));
				}
			}

			ipaccess[ips].ip = 0; // missing default to '.0'
			for (i = 0; ptr && (i < 4); i++) {
				dot = strchr(ptr, '.');
				if (dot)
					*(dot++) = '\0';
				octet = atoi(ptr);

				if (octet < 0 || octet > 0xff)
					goto popipo; // skip invalid

				ipaccess[ips].ip |= (octet << (24 - (i * 8)));

				ptr = dot;
			}

			ipaccess[ips].ip &= ipaccess[ips].mask;
		}

		ips++;
popipo:
		ptr = comma;
	}

	free(buf);
}

static bool check_connect(struct sockaddr_in *cli, char **connectaddr, char *group)
{
	bool addrok = false;

	*connectaddr = inet_ntoa(cli->sin_addr);

	*group = NOPRIVGROUP;
	if (opt_api_allow) {
		int client_ip = htonl(cli->sin_addr.s_addr);
		for (int i = 0; i < ips; i++) {
			if ((client_ip & ipaccess[i].mask) == ipaccess[i].ip) {
				addrok = true;
				*group = ipaccess[i].group;
				break;
			}
		}
	}
	else
		addrok = (strcmp(*connectaddr, localaddr) == 0);

	return addrok;
}

static void api()
{
	const char *addr = opt_api_allow;
	unsigned short port = (unsigned short) opt_api_listen; // 4048
	char buf[MYBUFSIZ];
	int c, n, bound;
	char *connectaddr;
	char *binderror;
	char group;
	time_t bindstart;
	struct sockaddr_in serv;
	struct sockaddr_in cli;
	socklen_t clisiz;
	bool addrok = false;
	long long counter;
	char *result;
	char *params;
	int i;

	SOCKETTYPE *apisock;
	if (!opt_api_listen && opt_debug) {
		applog(LOG_DEBUG, "API disabled");
		return;
	}

	if (opt_api_allow) {
		setup_ipaccess();
		if (ips == 0) {
			applog(LOG_WARNING, "API not running (no valid IPs specified)%s", UNAVAILABLE);
		}
	}

	apisock = (SOCKETTYPE*) calloc(1, sizeof(*apisock));
	*apisock = INVSOCK;

	sleep(1);

	*apisock = socket(AF_INET, SOCK_STREAM, 0);
	if (*apisock == INVSOCK) {
		applog(LOG_ERR, "API initialisation failed (%s)%s", strerror(errno), UNAVAILABLE);
		return;
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(addr);
	if (serv.sin_addr.s_addr == (in_addr_t)INVINETADDR) {
		applog(LOG_ERR, "API initialisation 2 failed (%s)%s", strerror(errno), UNAVAILABLE);
		return;
	}

	serv.sin_port = htons(port);

#ifndef WIN32
	// On linux with SO_REUSEADDR, bind will get the port if the previous
	// socket is closed (even if it is still in TIME_WAIT) but fail if
	// another program has it open - which is what we want
	int optval = 1;
	// If it doesn't work, we don't really care - just show a debug message
	if (SOCKETFAIL(setsockopt(*apisock, SOL_SOCKET, SO_REUSEADDR, (void *)(&optval), sizeof(optval))))
	        applog(LOG_DEBUG, "API setsockopt SO_REUSEADDR failed (ignored): %s", SOCKERRMSG);
#else
	// On windows a 2nd program can bind to a port>1024 already in use unless
	// SO_EXCLUSIVEADDRUSE is used - however then the bind to a closed port
	// in TIME_WAIT will fail until the timeout - so we leave the options alone
#endif

	// try for 1 minute ... in case the old one hasn't completely gone yet
	bound = 0;
	bindstart = time(NULL);
	while (bound == 0) {
		if (bind(*apisock, (struct sockaddr *)(&serv), sizeof(serv)) < 0) {
			binderror = strerror(errno);
			if ((time(NULL) - bindstart) > 61)
				break;
			else {
				if (!opt_quiet || opt_debug)
					applog(LOG_WARNING, "API bind to port %d failed - trying again in 20sec", port);
				sleep(20);
			}
		}
		else
			bound = 1;
	}

	if (bound == 0) {
		applog(LOG_WARNING, "API bind to port %d failed (%s)%s", port, binderror, UNAVAILABLE);
		free(apisock);
		return;
	}

	if (SOCKETFAIL(listen(*apisock, QUEUE))) {
		applog(LOG_ERR, "API initialisation 3 failed (%s)%s", strerror(errno), UNAVAILABLE);
		CLOSESOCKET(*apisock);
		free(apisock);
		return;
	}

	buffer = (char *) calloc(1, MYBUFSIZ + 1);

	counter = 0;
	while (bye == 0) {
		counter++;

		clisiz = sizeof(cli);
		if (SOCKETFAIL(c = accept((SOCKETTYPE)*apisock, (struct sockaddr *)(&cli), &clisiz))) {
			applog(LOG_ERR, "API failed (%s)%s", strerror(errno), UNAVAILABLE);
			CLOSESOCKET(*apisock);
			free(apisock);
			free(buffer);
			return;
		}

		addrok = check_connect(&cli, &connectaddr, &group);
		if (opt_debug && opt_protocol)
			applog(LOG_DEBUG, "API: connection from %s - %s",
				connectaddr, addrok ? "Accepted" : "Ignored");

		if (addrok) {
			bool fail;
			char *wskey = NULL;
			n = recv(c, &buf[0], SOCK_REC_BUFSZ, 0);

			fail = SOCKETFAIL(n);
			if (fail)
				buf[0] = '\0';
			else if (n > 0 && buf[n-1] == '\n') {
				/* telnet compat \r\n */
				buf[n-1] = '\0'; n--;
				if (n > 0 && buf[n-1] == '\r')
					buf[n-1] = '\0';
			}
			if (n >= 0)
				buf[n] = '\0';

			//if (opt_debug && opt_protocol && n > 0)
			//	applog(LOG_DEBUG, "API: recv command: (%d) '%s'+char(%x)", n, buf, buf[n-1]);

			if (!fail) {
				char *msg = NULL;
				/* Websocket requests compat. */
				if ((msg = strstr(buf, "GET /")) && strlen(msg) > 5) {
					char cmd[256] = { 0 };
					sscanf(&msg[5], "%s\n", cmd);
					params = strchr(cmd, '/');
					if (params)
						*(params++) = '|';
					params = strchr(cmd, '/');
					if (params)
						*(params++) = '\0';
					wskey = strstr(msg, "Sec-WebSocket-Key");
					if (wskey) {
						char *eol = strchr(wskey, '\r');
						if (eol) *eol = '\0';
						wskey = strchr(wskey, ':');
						wskey++;
						while ((*wskey) == ' ') wskey++; // ltrim
					}
					n = sprintf(buf, "%s", cmd);
				}

				params = strchr(buf, '|');
				if (params != NULL)
					*(params++) = '\0';

				if (opt_debug && opt_protocol && n > 0)
					applog(LOG_DEBUG, "API: exec command %s(%s)", buf, params);

				for (i = 0; i < CMDMAX; i++) {
					if (strcmp(buf, cmds[i].name) == 0) {
						if (params && strlen(params)) {
							// remove possible trailing |
							if (params[strlen(params) - 1] == '|')
								params[strlen(params) - 1] = '\0';
						}
						result = (cmds[i].func)(params);
						if (wskey) {
							websocket_handshake(c, result, wskey);
							break;
						}
						send_result(c, result);
						break;
					}
				}
				CLOSESOCKET(c);
			}
		}
	}

	CLOSESOCKET(*apisock);
	free(apisock);
	free(buffer);
}

/* external access */
void *api_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info*)userdata;

	startup = time(NULL);
	api();
	tq_freeze(mythr->q);

	if (bye) {
		// quit command
		proper_exit(1);
	}

	return NULL;
}

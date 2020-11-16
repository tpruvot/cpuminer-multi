#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
int gettimeofday(struct timeval *tv, struct timezone *tz);
void usleep(__int64 usec);
#ifdef __cplusplus
}
#endif
typedef __int64 useconds_t;

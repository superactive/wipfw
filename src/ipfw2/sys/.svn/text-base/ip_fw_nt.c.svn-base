/* 
 * Copyright (c) 2004-2006 Vlad Goncharov, Ruslan Staritsin
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 */

#include <ntddk.h>
#include <stdarg.h>
#include <stdio.h>

#include "ip_fw_nt.h"
#include <netinet/tcp.h>        // for tcp_respond

#include "log.h"
#include "wipfw.h"              // for struct sockopt

KSPIN_LOCK  g_spin_lock;

int     securelevel = 1;        // what value?
int     fw_one_pass = 1;        // what value?

void *ip_dn_io_ptr = NULL;

static u_long randseed;

/* some undocumented prototypes (from http://www.acc.umu.se/~bosse/ntifs.h) */

typedef enum { SystemTimeOfDayInformation = 3 } SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_TIME_OF_DAY_INFORMATION { // information class 3
    LARGE_INTEGER   BootTime;
    LARGE_INTEGER   CurrentTime;
    LARGE_INTEGER   TimeZoneBias;
    ULONG           CurrentTimeZoneId;
} SYSTEM_TIME_OF_DAY_INFORMATION, *PSYSTEM_TIME_OF_DAY_INFORMATION;

NTSTATUS NTAPI      ZwQuerySystemInformation (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID                   SystemInformation,
    IN ULONG                    Length,
    OUT PULONG                  ReturnLength);

/* --- */

void
ip_fw_nt_init(void)
{
    KeInitializeSpinLock(&g_spin_lock);

    randseed = (u_long)get_current_time();      // good?
}

void
log_win32(int type, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

char *
inet_ntoa_thread_safe(struct in_addr addr, char *buf)
{
    u_int32_t host_addr = ntohl(addr.s_addr);

#define PRINT_IP_ADDR(addr) \
    ((u_int8_t *)&(addr))[3], ((u_int8_t *)&(addr))[2], ((u_int8_t *)&(addr))[1], ((u_int8_t *)&(addr))[0]

    sprintf(buf, "%u.%u.%u.%u", PRINT_IP_ADDR(host_addr));

    return buf;
}

MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");

static char fake_zero_size_block;

void *
malloc(unsigned long size, struct malloc_type *type, int flags)
{
    void *result;

    if (size == 0) {
        // ExAllocatePool seems to work with zero size block not correctly
        return &fake_zero_size_block;
    }

    // XXX for now ignore malloc_type

    result = ExAllocatePool(NonPagedPool, size);
    if (result != NULL && (flags & M_ZERO) != 0)
        memset(result, 0, size);

    return result;
}

void
free(void *addr, struct malloc_type *type)
{
    if (addr == NULL || addr == &fake_zero_size_block)
        return;

    // XXX for now ignore malloc_type

    ExFreePool(addr);
}

#define EPOCH_BIAS                  116444736000000000i64
#define KE_TIME_TO_TIME_T(ke_time)  (time_t)(((ke_time) - EPOCH_BIAS) / 10000000i64)

time_t
get_current_time(void)
{
    NTSTATUS status;
    time_t result;
    LARGE_INTEGER tod = {0};

    KeQuerySystemTime(&tod);
    result = KE_TIME_TO_TIME_T(tod.QuadPart);

    return result;
}

void
tcp_respond(struct tcpcb *tp, void *ipgen, struct tcphdr *th, struct mbuf *m, tcp_seq ack, tcp_seq seq, int flags)
{
    // TODO!!!!!!!!!!! (later)
}

void
icmp_error(struct mbuf *n, int type, int code, n_long dest, struct ifnet *destifp)
{
    // TODO!!!!!!!!!!! (later)
}

/*
* Pseudo-random number generator for randomizing the profiling clock,
* and whatever else we might use it for.  The result is uniform on
* [0, 2^31 - 1].
*/
u_long
random(void)
{
    register long x, hi, lo, t;

    /*
    * Compute x[n + 1] = (7^5 * x[n]) mod (2^31 - 1).
    * From "Random number generators: good ones are hard to find",
    * Park and Miller, Communications of the ACM, vol. 31, no. 10,
    * October 1988, p. 1195.
    */
    x = randseed;
    hi = x / 127773;
    lo = x % 127773;
    t = 16807 * lo - 2836 * hi;
    if (t <= 0)
        t += 0x7fffffff;
    randseed = t;
    return (t);
}

int
sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen)
{
    size_t valsize;

    /*
    * If the user gives us more than we wanted, we ignore it,
    * but if we don't get the minimum length the caller
    * wants, we return EINVAL.  On success, sopt->sopt_valsize
    * is set to however much we actually retrieved.
    */
    if ((valsize = sopt->sopt_valsize) < minlen)
        return EINVAL;
    if (valsize > len)
        sopt->sopt_valsize = valsize = len;

    bcopy(sopt->sopt_val, buf, valsize);
    return 0;
}

/* Helper routine for getsockopt */
int
sooptcopyout(struct sockopt *sopt, void *buf, size_t len)
{
    int error;
    size_t valsize;

    error = 0;

    /*
    * Documented get behavior is that we always return a value,
    * possibly truncated to fit in the user's buffer.
    * Traditional behavior is that we always tell the user
    * precisely how much we copied, rather than something useful
    * like the total amount we had available for her.
    * Note that this interface is not idempotent; the entire answer must
    * generated ahead of time.
    */
    valsize = min(len, sopt->sopt_valsize);
    sopt->sopt_valsize = valsize;
    bcopy(buf, sopt->sopt_val, valsize);
    
    return error;
}

/*
 * Rearange an mbuf chain so that len bytes are contiguous
 * and in the data area of an mbuf (so that mtod and dtom
 * will work for a structure of size len).  Returns the resulting
 * mbuf chain on success, frees it and returns null on failure.
 * If there is room, it will add up to max_protohdr-len extra bytes to the
 * contiguous region in an attempt to avoid being called next time.
 */
struct mbuf *
m_pullup(struct mbuf *n, int len)
{
    // Vlad: due to our simplified mbuf usage m_pullup is not needed
    return NULL;
}

/* Copyright (c) 2004-2006 Vlad Goncharov, Ruslan Staritsin
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */

#ifndef _ip_fw_nt_h_
#define _ip_fw_nt_h_

// [u][_]int{8,16,32,64}_t moved to stdint.h
#include "stdint.h"

typedef char *          caddr_t;        /* core address */


#define __P(protos)     protos          /* full-blown ANSI C */

/* find first bit set in a word */
static __inline int
ffs(int mask)
{
        int bit;

        if (mask == 0)
        	return (0);
        for (bit = 1; !(mask & 1); bit++)
        	mask = (unsigned int)mask >> 1;
        return (bit);
}

/* Vlad: <sys/queue> stuff */

#undef SLIST_ENTRY          // avoid conflicts with <ntddk.h>

#include <sys/queue.h>


/*
 * XPG4.2 states that inclusion of <netinet/in.h> must pull these
 * in and that inclusion of <sys/socket.h> must pull in sa_family_t.
 * We put there here because there are other headers that require
 * these types and <sys/socket.h> and <netinet/in.h> will indirectly
 * include <sys/types.h>.  Thus we are compliant without too many hoops.
 */
typedef u_int32_t       in_addr_t;      /* base type for internet address */
typedef u_int16_t       in_port_t;      /* IP port type */
typedef u_int16_t       sa_family_t;    /* sockaddr address family type (make sockaddr_in compatible with winsock one) */
typedef u_int32_t       socklen_t;      /* length type for network syscalls */



/*
 * IP Version 4 Internet address (a structure for historical reasons)
 */
struct in_addr {
        in_addr_t s_addr;
};

/*
 * IP Version 4 socket address.
 */
#pragma pack(1)     // Vlad: this structure compatible with winsock one
struct sockaddr_in {
        sa_family_t sin_family;
        in_port_t   sin_port;
        struct      in_addr sin_addr;
        int8_t      sin_zero[8];
        u_char      sin_len;
};
#pragma pack()

/*
 * Network types.
 *
 * Internally the system keeps counters in the headers with the bytes
 * swapped so that VAX instructions will work on them.  It reverses
 * the bytes before transmission at each protocol level.  The n_ types
 * represent the types with the bytes in ``high-ender'' order.
 */
typedef u_int16_t n_short;              /* short as received from the net */
typedef u_int32_t n_long;               /* long as received from the net */

typedef u_int32_t n_time;               /* ms since 00:00 GMT, byte rev */



#define LITTLE_ENDIAN   1234
#define BIG_ENDIAN      4321


#define BYTE_ORDER  LITTLE_ENDIAN


#define NBBY    8               /* number of bits in a byte */


struct ifaddr {
        struct  sockaddr *ifa_addr;     /* address of interface */
        struct  ifnet *ifa_ifp;         /* back-pointer to interface */
        TAILQ_ENTRY(ifaddr) ifa_link;   /* queue macro glue */
        // Vlad: ripped
};

TAILQ_HEAD(ifaddrhead, ifaddr); /* instantiation is preserved in the list */

/*
 * Structure defining a network interface.
 *
 * (Would like to call this struct ``if'', but C isn't PL/1.)
 */
struct ifnet {
        // Vlad: structure ripped
        char    if_name[16];            /* name, e.g. ``en'' or ``lo'' */
        short   if_unit;                /* sub-unit for lower level driver */

        struct  ifaddrhead if_addrhead; /* linked list of addresses per if */

        // Vlad: iphlpapi interface index
        unsigned int    if_indx;
};


/*
 * Interface address, Internet version.  One of these structures
 * is allocated for each interface with an Internet address.
 * The ifaddr structure contains the protocol-independent part
 * of the structure and is assumed to be first.
 */
struct in_ifaddr {
        struct  ifaddr ia_ifa;          /* protocol-independent info */
#define ia_ifp          ia_ifa.ifa_ifp
        TAILQ_ENTRY(in_ifaddr) ia_list; /* list of internet addresses */
        struct  sockaddr_in ia_addr;    /* reserve space for interface name */
        // Vlad: ripped
};



TAILQ_HEAD(in_ifaddrhead, in_ifaddr);
extern  struct  in_ifaddrhead in_ifaddr;

/*
 * Macro for finding the interface (ifnet structure) corresponding to one
 * of our IP addresses.
 */
/*
 * Vlad: this macro in ip_fw.c used only to check is this address belongs to localhost (ifp only checked == NULL)
 *       and it's called always inside g_iflist_guard spinlock
 */
#define INADDR_TO_IFP(addr, ifp) \
        /* struct in_addr addr; */ \
        /* struct ifnet *ifp; */ \
{ \
        register struct in_ifaddr *ia; \
\
        for (ia = in_ifaddr.tqh_first; \
            ia != NULL && ia->ia_addr.sin_addr.s_addr != (addr).s_addr; \
            ia = ia->ia_list.tqe_next) \
                 continue; \
        (ifp) = (ia == NULL) ? NULL : ia->ia_ifp; \
}




/*
 * Structure used by kernel to store most
 * addresses.
 */
#pragma pack(1)
struct sockaddr {       // Vlad: this structure is compatible with winsock one
        sa_family_t sa_family;          /* address family */
        char        sa_data[14];        /* actually longer; address value */
};
#pragma pack()

#define AF_MAX          0
#define AF_INET         2               /* internetwork: UDP, TCP, etc. */


/*
 * Vlad: C99 snprintf returns number of total bytes that should be copied (not bytes actually copied)
 * but in ip_fw.c it looks like snprintf should return strlen(buf)
 * Windows' _snprintf doesn't terminate buffer with zero if size > buf_size
 */
static int
snprintf(char *buf, size_t buf_size, const char *fmt, ...)
{
    int result;
    va_list ap;
    va_start(ap, fmt);
    result = _vsnprintf(buf, buf_size, fmt, ap);
    if (result < 0) {
        buf[buf_size - 1] = '\0';
        result = buf_size - 1;
    }
    va_end(ap);
    return result;
}

/*
 * Vlad: the original inet_ntoa is not thread safe. There's no TLS in kernel mode so I added buffer as 2nd parameter
 * function returns buf
 * buf size is INET_NTOA_BUF_SIZE
 */
char      *inet_ntoa_thread_safe(struct in_addr, char *buf);

#define INET_NTOA_BUF_SIZE      sizeof("255.255.255.255")
#define DECLARE_INET_NTOA_BUF   char inet_ntoa_buf[INET_NTOA_BUF_SIZE]

#define inet_ntoa(in_addr)      inet_ntoa_thread_safe(in_addr, inet_ntoa_buf)


/* Note that these macros evaluate their arguments several times.  */
#define __swap16gen(x)                                                  \
    (u_int16_t)(((u_int16_t)(x) & 0xff) << 8 | ((u_int16_t)(x) & 0xff00) >> 8)

#define __swap32gen(x)                                                  \
    (u_int32_t)(((u_int32_t)(x) & 0xff) << 24 |                         \
    ((u_int32_t)(x) & 0xff00) << 8 | ((u_int32_t)(x) & 0xff0000) >> 8 | \
    ((u_int32_t)(x) & 0xff000000) >> 24)

#define __swap64gen(x)                                                  \
        (u_int64_t)(((u_int64_t)(x) & 0xff) << 56) |                    \
            ((u_int64_t)(x) & 0xff00) << 40 |                           \
            ((u_int64_t)(x) & 0xff0000) << 24 |                         \
            ((u_int64_t)(x) & 0xff000000) << 8 |                        \
            ((u_int64_t)(x) & 0xff00000000) >> 8 |                      \
            ((u_int64_t)(x) & 0xff0000000000) >> 24 |                   \
            ((u_int64_t)(x) & 0xff000000000000) >> 40 |                 \
            ((u_int64_t)(x) & 0xff00000000000000) >> 56)


#define swap16 __swap16gen
#define swap32 __swap32gen
#define swap64 __swap64gen


#if BYTE_ORDER == LITTLE_ENDIAN

#define htobe16 swap16
#define htobe32 swap32
#define htobe64 swap64
#define betoh16 swap16
#define betoh32 swap32
#define betoh64 swap64

#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define letoh16(x) (x)
#define letoh32(x) (x)
#define letoh64(x) (x)

#define htons htobe16
#define htonl htobe32
#define ntohs betoh16
#define ntohl betoh32

#define NTOHL(x) (x) = ntohl((u_int32_t)(x))
#define NTOHS(x) (x) = ntohs((u_int16_t)(x))
#define HTONL(x) (x) = htonl((u_int32_t)(x))
#define HTONS(x) (x) = htons((u_int16_t)(x))

#else

#define htole16 __swap16
#define htole32 __swap32
#define htole64 __swap64
#define letoh16 __swap16
#define letoh32 __swap32
#define letoh64 __swap64

#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)
#define betoh16(x) (x)
#define betoh32(x) (x)
#define betoh64(x) (x)

#define	ntohl(x)	(x)
#define	ntohs(x)	(x)
#define	htonl(x)	(x)
#define	htons(x)	(x)

#define	NTOHL(x)	(x)
#define	NTOHS(x)	(x)
#define	HTONL(x)	(x)
#define	HTONS(x)	(x)

#endif

/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */


/* facility codes */
#define LOG_SECURITY    (13<<3) /* security subsystems (firewalling, etc.) */



// Vlad: avoid intrinsic log() from math.h
void    log_win32(int, const char *, ...);
#define log     log_win32


typedef u_int32_t    time_t;        // Vlad: using 32-bit time_t (will expire after 19:14:07, January 18, 2038, UTC)

// Vlad: extern time_t   time_second;
time_t  get_current_time(void);
#define time_second     get_current_time()



/*
 * flags to malloc.
 */
#define M_WAITOK        0x0000
#define M_NOWAIT        0x0001          /* do not block */

#define M_ZERO          0x0008          /* Vlad: not a original value */

#define M_MAGIC         877983977       /* time when first defined :-) */

struct malloc_type {
        // Vlad: ripped
        u_long  ks_magic;       /* if it's not magic, don't touch it */
        const char *ks_shortdesc;       /* short description */
};

#define MALLOC_DEFINE(type, shortdesc, longdesc) \
        struct malloc_type type[1] = { \
                { M_MAGIC, shortdesc } \
        }

#define MALLOC_DECLARE(type) \
        extern struct malloc_type type[1]

MALLOC_DECLARE(M_TEMP);

void    free(void *addr, struct malloc_type *type);
void    *malloc(unsigned long size, struct malloc_type *type, int flags);


// Vlad: very nice function to implement :-)
static __inline void
panic(const char *msg, ...)
{
    KdPrint(("!!!PANIC!!! %s", msg));
    KdBreakPoint();
    KeBugCheck(MANUALLY_INITIATED_CRASH);       // is this code good enough?
}



/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than the software page size, and,
 * on machines that exchange pages of input or output buffers with mbuf
 * clusters (MAPPED_MBUFS), MCLBYTES must also be an integral multiple
 * of the hardware page size.
 */
#define MSIZE           2048            /* size of an mbuf Vlad: this value depends on what? */
#define MCLSHIFT        11              /* convert bytes to m_buf clusters */
#define MCLBYTES        (1 << MCLSHIFT) /* size of a m_buf cluster */
#define MCLOFSET        (MCLBYTES - 1)  /* offset within a m_buf cluster */



/*
 * Mbufs are of a single size, MSIZE (machine/param.h), which
 * includes overhead.  An mbuf may add a single "mbuf cluster" of size
 * MCLBYTES (also in machine/param.h), which has no additional overhead
 * and is used instead of the internal data area; this is done when
 * at least MINCLSIZE of data must be stored.
 */

#define MLEN            (MSIZE - sizeof(struct m_hdr))  /* normal data len */
#define MHLEN           (MLEN - sizeof(struct pkthdr))  /* data len w/pkthdr */

/*
 * Macros for type conversion
 * mtod(m,t) -  convert mbuf pointer to data pointer of correct type
 */
#define mtod(m,t)       ((t)((m)->m_data))

/* header at beginning of each mbuf: */
struct m_hdr {
        struct  mbuf *mh_next;          /* next buffer in chain */
        caddr_t mh_data;                /* location of data */
        u_int   mh_len;                 /* amount of data in this mbuf */
        short   mh_flags;               /* flags; see below */
        // Vlad: ripped
};

/* record/packet header in first mbuf of chain; valid if M_PKTHDR set */
struct  pkthdr {
        struct  ifnet *rcvif;           /* rcv interface */
        int     len;                    /* total packet length */
        // Vlad: ripped
};

struct mbuf {
        struct  m_hdr m_hdr;
        union {
                struct {
                        struct  pkthdr MH_pkthdr;       /* M_PKTHDR set */
                        union {
                                // Vlad: ripped
                                char    MH_databuf[MHLEN];
                        } MH_dat;
                } MH;
                char    M_databuf[MLEN];                /* !M_PKTHDR, !M_EXT */
        } M_dat;
};

// Vlad: not all macros
#define m_next          m_hdr.mh_next
#define m_len           m_hdr.mh_len
#define m_data          m_hdr.mh_data
#define m_flags         m_hdr.mh_flags
#define m_pkthdr        M_dat.MH.MH_pkthdr
#define m_pktdat        M_dat.MH.MH_dat.MH_databuf
#define m_dat           M_dat.M_databuf

/* mbuf flags */
#define M_PKTHDR        0x0002  /* start of record */

/* mbuf pkthdr flags, also in m_flags */
#define M_BCAST         0x0100  /* send/received as link-level broadcast */
#define M_MCAST         0x0200  /* send/received as link-level multicast */

/* flags to m_get/MGET */
#define M_DONTWAIT      M_NOWAIT
#define M_WAIT          M_WAITOK


struct  mbuf *m_pullup(struct mbuf *, int);



/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct  ether_header {
        u_char  ether_dhost[6];
        u_char  ether_shost[6];
        u_short ether_type;
};

#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP        0x8035  /* reverse Addr. resolution protocol */



u_long   random(void);


#define KASSERT(cond, msg)              \
    do {                                \
        if (!(cond)) {                  \
            KdPrint(msg);               \
            KdBreakPoint();             \
        }                               \
    } while(0)



#define __IPADDR(x)     ((u_int32_t) htonl((u_int32_t)(x)))

#define IN_CLASSD(i)            (((u_int32_t)(i) & __IPADDR(0xf0000000)) == \
                                 __IPADDR(0xe0000000))
/* These ones aren't really net and host fields, but routing needn't know. */
#define IN_MULTICAST(i)         IN_CLASSD(i)


/*
 * Overlay for ip header used by other protocols (tcp, udp).
 */
struct ipovly {
        u_char  ih_x1[9];               /* (unused) */
        u_char  ih_pr;                  /* protocol */
        u_short ih_len;                 /* protocol length */
        struct  in_addr ih_src;         /* source internet address */
        struct  in_addr ih_dst;         /* destination internet address */
};

// Vlad: void   bcopy(const void *, void *, size_t);        ???? or memmove() ????
#define bcopy(src, dst, size)       memcpy((dst), (src), (size))

// Vlad: void   bzero(void *, size_t);
#define bzero(p, size)              memset((p), 0, (size))
#define bcmp(p1, p2, size)          memcmp((p2),(p1), (size))

#include <sys/errno.h>

extern KSPIN_LOCK   g_spin_lock;

static __inline int
splimp(void)
{
#ifndef IPFW2
    KIRQL old_irql;
    KeAcquireSpinLock(&g_spin_lock, &old_irql);
    return (int)old_irql;
#else
    return 0;
#endif
}

static __inline void
splx(int s)
{
#ifndef IPFW2
    KeReleaseSpinLock(&g_spin_lock, (KIRQL)s);
#endif
;
}

extern int securelevel;         /* system security level (see init(8)) */

int     sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen);
int     sooptcopyout(struct sockopt *sopt, void *buf, size_t len);


typedef PDRIVER_OBJECT  module_t;       // good?

#define MOD_LOAD        1
#define MOD_UNLOAD      2

typedef int     modevent_t(module_t mod, int type, void *unused);

typedef struct moduledata {
    char        *name;
    modevent_t  *modevent;
    int         unknown;
} moduledata_t;

#define DECLARE_MODULE(a, b, c, d)      struct moduledata *module_##a = &b;

#if DBG
# define printf      DbgPrint
#else
# define printf
#endif

#define SYSCTL_NODE(parent, nbr, name, access, handler, descr)
#define SYSCTL_INT(parent, nbr, name, access, ptr, val, descr) \
	int *_fw_##name = ptr;

static int fw_enable;

/* Vlad: due to missing reverse function of RtlNtStatusToDosError() define NTSTATUS equialents directly */

#define ENOSPC          STATUS_INSUFFICIENT_RESOURCES   /* No space left on device (Vlad: on malloc() fail) */
#define EINVAL          STATUS_INVALID_PARAMETER        /* Invalid argument */
#define EPERM           STATUS_ACCESS_DENIED            /* Operation not permitted */
#define ENOBUFS         STATUS_INSUFFICIENT_RESOURCES   /* No buffer space available (Vlad: on malloc() fail inside spinlock) */
#define ENOMEM          STATUS_INSUFFICIENT_RESOURCES   /* -/- */
#define EEXIST          STATUS_OBJECT_NAME_EXISTS       /* File exists */
#define ESRCH           STATUS_OBJECT_NAME_EXISTS       /* ??? */

// Vlad: struct sockopt moved out to wipfw.h
#include "wipfw.h"

void    ip_fw_nt_init(void);
void    init_tables(void);
void    rn_init(void);

#endif  /* _ip_fw_nt_h_ */

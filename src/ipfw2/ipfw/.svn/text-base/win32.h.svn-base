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

#ifndef _win32_h_
#define _win32_h_

#include <iphlpapi.h>

#ifdef _MSC_VER
// conversion possible lost of data
#   pragma warning(disable: 4018) 
#   pragma warning(disable: 4242) 
#   pragma warning(disable: 4244)
#   pragma warning(disable: 4761)
#endif

#define __BSD_VISIBLE   1
#define SIOCGIFFLAGS    0

#define EX_USAGE        64      /* command line usage error */
#define EX_DATAERR      65      /* data format error */
#define EX_NOHOST       68      /* host name unknown */
#define EX_UNAVAILABLE  69      /* service unavailable */
#define EX_OSERR        71      /* system error (e.g., can't fork) */
#define EX_OK           0       /* successful termination */
#define R_OK            4	/* check for read permission */

#define warnx      warn
#define err        errx
#define access     _access

#define setsockopt      wnd_setsockopt
#define getsockopt      wnd_getsockopt
#define exit	Exit

#ifndef HAVE_STRCASECMP
# define strcasecmp(a, b) _stricmp(a, b)
#endif

#ifndef STDIN_FILENO
# define STDIN_FILENO    _fileno(stdin)
#endif
#define isatty          _isatty

#ifdef _MSC_VER
typedef unsigned int	pid_t;
#endif

#define bcmp(p1, p2, size)          memcmp((p2),(p1), (size))
#define bzero(p, size)              memset((p), 0, (size))
#define bcopy(src, dst, size)       memcpy((dst), (src), (size))

#define index	strchr

CRITICAL_SECTION cs;

void
dump_data(const unsigned char *buf, unsigned int size);

typedef struct ifreq{
    char ifr_name[32];
} IFREQ;

static struct {
    unsigned int    type;
    const char      *name;
} g_if_types[] = {
    { MIB_IF_TYPE_OTHER,        "if\0"  },        // index MUST == 0
    { MIB_IF_TYPE_LOOPBACK,     "lo\0"  },        // index MUST == 1
    { MIB_IF_TYPE_ETHERNET,     "eth\0" },
    { MIB_IF_TYPE_TOKENRING,    "tr\0"  },
    { MIB_IF_TYPE_FDDI,         "fd\0"  },
    { MIB_IF_TYPE_PPP,          "ppp\0" },
    { MIB_IF_TYPE_SLIP,         "sl\0"  }
};

extern int      opterr,optind, optopt, optreset;
extern char     *optarg;

void setservent(int stayopen);
void endservent();

int orig_main(int ac, char *av[]);
int inet_aton(const char *cp, struct in_addr *addr);
int wnd_setsockopt (int s, int level, int sopt_name, void *optval, unsigned long optlen);
int wnd_getsockopt (int s, int level, int sopt_name, void *optval, unsigned int *optlen);
int wnd_main(int ac, char *av[]);

struct passwd *getpwent(void);
struct passwd *getpwuid(unsigned int uid);
struct group *getgrent(void);
struct group *getgrgid(int a);
struct passwd *getpwnam(const char *login);
struct group *getgrnam(const char *name);
int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
void heapsort(void *q, int rq_elements, int size, void *q2);
char *strsep(char **stringp, const char *delim);

int ioctl(int s, int flags, void *data);
int getopt(int nargc, char *nargv[], const char *ostr);
int sysctl_io(int ctln, int ctlv, int rw);
void sysctl_handler(int ac, char *av[], int quiet);

void warn(const char *fmt, ...);
void errx(int MSGTYPE_ERROR, char *fmt, ...);
void Exit(int exitcode);

/*
 * Windows' _snprintf doesn't terminate buffer with zero if size > buf_size
 */
__inline static  int 
snprintf(char *buf, size_t buf_size, const char *fmt, ...)
{
    int n;
    
    va_list ap;
    va_start(ap, fmt);
    
    n = _vsnprintf(buf, buf_size, fmt, ap);
    if (n < 0)
        buf[buf_size - 1] = '\0';
    va_end(ap);
    
    return n;
}

#endif /* _win32_h_ */


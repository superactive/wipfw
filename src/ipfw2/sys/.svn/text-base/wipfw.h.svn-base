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
 */

#ifndef _wipfw_h_
#define _wipfw_h_

//#include <ntddk.h>
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

/*
 * XPG4.2 states that inclusion of <netinet/in.h> must pull these
 * in and that inclusion of <sys/socket.h> must pull in sa_family_t.
 * We put there here because there are other headers that require
 * these types and <sys/socket.h> and <netinet/in.h> will indirectly
 * include <sys/types.h>.  Thus we are compliant without too many hoops.
 */
typedef u_int32_t       in_addr_t;      /* base type for internet address */

#define FILE_DEVICE_IPFW    0x00654324
#define IP_FW_BASE_CTL      0x840

#define	IP_FW_TABLE_ADD		40   /* add entry */
#define	IP_FW_TABLE_DEL		41   /* delete entry */
#define	IP_FW_TABLE_FLUSH	42   /* flush table */
#define	IP_FW_TABLE_GETSIZE	43   /* get table size */
#define	IP_FW_TABLE_LIST	44   /* list table contents */

#define IP_FW_ADD               50   /* add a firewall rule to chain */
#define IP_FW_DEL               51   /* delete a firewall rule from chain */
#define IP_FW_FLUSH             52   /* flush firewall rule chain */
#define IP_FW_ZERO              53   /* clear single/all firewall counter(s) */
#define IP_FW_GET               54   /* get entire firewall rule chain */
#define IP_FW_RESETLOG          55   /* reset logging counters */

#define	IP_DUMMYNET_CONFIGURE	60   /* add/configure a dummynet pipe */
#define	IP_DUMMYNET_DEL		61   /* delete a dummynet pipe from chain */
#define	IP_DUMMYNET_FLUSH	62   /* flush dummynet */
#define	IP_DUMMYNET_GET		64   /* get entire dummynet pipes */

#define SIGTERM     0
#define IFNAMSIZ    10

#define IP_FW_SETSOCKOPT \
        CTL_CODE(FILE_DEVICE_IPFW, IP_FW_BASE_CTL + 1, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IP_FW_GETSOCKOPT \
        CTL_CODE(FILE_DEVICE_IPFW, IP_FW_BASE_CTL + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IP_FW_SET_IFLIST \
        CTL_CODE(FILE_DEVICE_IPFW, IP_FW_BASE_CTL + 3, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IP_FW_SYSCTL_IO \
        CTL_CODE(FILE_DEVICE_IPFW, IP_FW_BASE_CTL + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IP_FW_GET_IFLIST \
        CTL_CODE(FILE_DEVICE_IPFW, IP_FW_BASE_CTL + 5, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(1)

enum sopt_dir { SOPT_GET, SOPT_SET };
struct sockopt {
        // Vlad: changed & ripped
        enum    sopt_dir sopt_dir;  /* is this a get or a set? */
        int     sopt_name;          /* third arg of [gs]etsockopt */
        size_t  sopt_valsize;       /* (almost) fifth arg of [gs]etsockopt */
        char    *sopt_val;          /* fourth arg of [gs]etsockopt (ignored in user-level) */
        char    sopt_val_buf[0];    /* for easy data transfer */
};

struct ip_fw_iflist_entry {
    u_int32_t   size;       // size of the whole entry
    char        name[16];   // "eth", "ppp", "lo", etc. (size is equal to if_net in struct ifnet)
    u_int16_t   unit;       // eth0, etc.
    u_int32_t   indx;      // iphlpapi interface index
    u_int16_t   addr_count;
    struct      sockaddr_in addr[0];    // IPv4 addresses only for now
};

enum sysctlvar {
	FW_ONE_PASS,
	FW_DEBUG,
	FW_VERBOSE,
	FW_VERBOSE_LIMIT,
	DYN_BUCKETS,
	CURR_DYN_BUCKETS,
	DYN_COUNT,
	DYN_MAX,
	STATIC_COUNT,
	DYN_ACK_LIFETIME,
	DYN_SYN_LIFETIME,
	DYN_FIN_LIFETIME,
	DYN_RST_LIFETIME,
	DYN_UDP_LIFETIME,
	DYN_SHORT_LIFETIME,
#ifndef IPFW2
	DYN_GRACE_TIME
#else
	DYN_KEEPALIVE
#endif
};

struct sysctl {
	enum sopt_dir sopt_dir;  /* is this a get or a set? */
	int sysctl_name;
	int sysctl_val;
};

struct passwd {
	       char *pw_name;
	       char *pw_passwd;
	       int  pw_uid;
	       int  pw_gid;
	       char *pw_age;
	       char *pw_comment;
	       char *pw_gecos;
	       char *pw_dir;
	       char *pw_shell;
};

struct group {
	  char *gr_name;
	  char *gr_passwd;
	  int  gr_gid;
	  char **gr_mem;
};

struct clockinfo{
        int hz;
};

#pragma pack()

#endif

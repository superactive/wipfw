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

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock.h>
#include <winioctl.h>

#include "stdint.h"
#include "win32.h"
#include "wipfw.h"

void setservent(int stayopen) {}
void endservent() {}

void
dump_data(const unsigned char *buf, unsigned int size)
{
    unsigned int i, j;

    for (i = 0; i < size; i += 16) {

        // print offset
        printf("%04x  ", i);

        // output hex bytes
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        }

        // output chars
        for (j = 0; j < 16 && i + j < size; j++)
            putchar(buf[i + j] >= ' ' ? buf[i + j] : '.');

        putchar('\n');
    }
}

struct passwd *getpwent(void)
{
	return 0;
}

struct passwd *getpwuid(unsigned int uid)
{
	return NULL;
}

struct group *getgrent(void)
{
	return 0;
}

struct group *getgrgid(int a)
{
	return 0;
}

struct passwd *getpwnam(const char *login)
{
	return 0;
}

struct group *getgrnam(const char *name)
{
	return NULL;
}

int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
     return 0;
}

void
heapsort(void *q, int rq_elements, int size, void *q2)
{
              ;
}

char  
*strsep(char **stringp, const char *delim)
{
	return 0;
}

void
warn (const char *fmt, ...)
{
    char message[1024];
    va_list ap;

    va_start (ap, fmt);
    if (_vsnprintf (message, sizeof (message), fmt, ap) == -1)
        message[sizeof (message) - 1] = '\0';
    va_end (ap);

    fprintf (stderr, "%s\n", message);
}

void
errx (int MSGTYPE_ERROR, char *fmt, ...)
{
    va_list ap;
    char message[1024];

    // prepare message
    va_start (ap, fmt);
    if (_vsnprintf (message, sizeof (message), fmt, ap) == -1)
        message[sizeof (message) - 1] = '\0';
    va_end (ap);

    // got message
    fprintf (stderr, "error %i: %s (win32: %u)\n", MSGTYPE_ERROR, message,
             GetLastError ());

    exit (MSGTYPE_ERROR);
    /* NOTREACHED */
}

int
inet_aton (const char *cp, struct in_addr *addr)
{
    addr->s_addr = inet_addr (cp);
    return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

/*
int
ioctl2(int s, int flags, void *data)
{
        HANDLE drv;
        DWORD n;
        int len, result;
        struct ip_fw_iflist_entry *ife;

        drv = CreateFile ("\\\\.\\Global\\ip_fw", GENERIC_READ |
                GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL);
        if (drv == INVALID_HANDLE_VALUE) {
                return -1;
        }


        result = DeviceIoControl (drv, IP_FW_GET_IFLIST,
			    ife, len, ife, len, &n, NULL);

        return 0;
}
*/

int
ioctl(int s, int flags, void *data)
{
    return 1;

    /* IP_ADAPTER_INFO *ai;
       DWORD status;
       ULONG size;
       static long index;
       char *ifname;
       int unit,type,prev_type = 0;

       ifname = (char *)data;
       if (!strncmp(ifname, "lo",2))
           return 1;

       // trying with only one interface
       size = sizeof(IP_ADAPTER_INFO);
       ai = malloc(size);
       status = GetAdaptersInfo(ai, &size);
       if (status != ERROR_SUCCESS) {
       // not enough space
    free(ai);
    ai = malloc(size);
    if (ai == NULL)
      return -1;
    status = GetAdaptersInfo(ai, &size);
       }

       if (status == ERROR_SUCCESS) for (;ai != NULL; ai = ai->Next) {
       	int i = 0;
    char if_str[32];

    type = ai->Type;
    if (type != prev_type) {
    	unit = 0;
    	prev_type = ai->Type;
    } else unit++;

    for (i = 0; i < sizeof(g_if_types) / sizeof(*g_if_types); i++)
    	if (g_if_types[i].type == ai->Type)
    		break;
    if (i >= sizeof(g_if_types) / sizeof(*g_if_types))
    	i = 0;      // MIB_IF_TYPE_OTHER by default

    sprintf(if_str, "%s%d", g_if_types[i].name, unit);
    if (!strncmp(if_str, ifname, strlen(if_str))) {
    	index = ai->Index;
    	free(ai);
    	return 1;
    }
       }
       free(ai);
       return -1;
    */
}

int
wnd_setsockopt (int s, int level, int sopt_name, void *optval,
                unsigned long optlen)
{
    size_t len = sizeof (struct sockopt) + optlen;
    struct sockopt *sock;
    HANDLE drv;
    DWORD n;
    BOOL result;

    sock = malloc (len);
    if (sock == NULL)
        return -1;

    sock->sopt_dir = SOPT_SET;
    sock->sopt_name = sopt_name;
    sock->sopt_valsize = optlen;
    sock->sopt_val = NULL;	// unused in user-mode

    memcpy (sock->sopt_val_buf, optval, optlen);

    /* Special Handling For Accessing Device On Windows 2000 Terminal Server
       See Microsoft KB Article 259131 */
    drv = CreateFile ("\\\\.\\Global\\ip_fw", GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, 0, NULL);
    if (drv == INVALID_HANDLE_VALUE) {
        free (sock);
        return -1;
    }

    result = DeviceIoControl (drv, IP_FW_SETSOCKOPT, sock, len, NULL, 0, &n, NULL);

    free (sock);
    CloseHandle (drv);

    return (result ? 0 : -1);
}

int
wnd_getsockopt (int s, int level, int sopt_name, void *optval,
                unsigned int *optlen)
{
    size_t len = sizeof (struct sockopt) + *optlen;
    struct sockopt *sock;
    HANDLE drv;
    DWORD n;
    BOOL result;

    sock = malloc (len);
    if (sock == NULL)
        return -1;

    sock->sopt_dir = SOPT_GET;
    sock->sopt_name = sopt_name;
    sock->sopt_valsize = *optlen;
    sock->sopt_val = NULL;	// not used in user-mode

    memcpy (sock->sopt_val_buf, optval, *optlen);

    drv = CreateFile ("\\\\.\\Global\\ip_fw", GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, 0, NULL);
    if (drv == INVALID_HANDLE_VALUE) {
        free (sock);
        return -1;
    }

    result = DeviceIoControl (drv, IP_FW_GETSOCKOPT, sock, len, sock, len, &n, NULL);

    *optlen = sock->sopt_valsize;
    memcpy (optval, sock->sopt_val_buf, *optlen);

    free (sock);
    CloseHandle (drv);

    return (result ? 0 : -1);
}

int
sysctl_io (int rw, int ctln, int ctlv)
{
    HANDLE drv;
    DWORD n;
    BOOL result;
    int len = sizeof (struct sysctl);
    struct sysctl ctldata = {
                                rw, ctln, ctlv
                            };

    drv = CreateFile ("\\\\.\\Global\\ip_fw", GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, 0, NULL);
    if (drv == INVALID_HANDLE_VALUE) {
        printf ("INVALID_HANDLE_VALUE\n");
        return -1;
    }

    result = DeviceIoControl (drv, IP_FW_SYSCTL_IO,
                              &ctldata, len, &ctldata, len, &n, NULL);

    n = ctldata.sysctl_val;

    CloseHandle (drv);
    return (result ? n : -1);
}

void
sysctl_handler (int ac, char *av[], int do_quiet)
{
    int i = 1, j, n;
    char *ptr;
    char *ctlnam[] = {
                         "one_pass",
                         "debug",
                         "verbose",
                         "verbose_limit",
                         "dyn_buckets",
                         "curr_dyn_buckets",
                         "dyn_count",
                         "dyn_max",
                         "static_count",
                         "dyn_ack_lifetime",
                         "dyn_syn_lifetime",
                         "dyn_fin_lifetime",
                         "dyn_rst_lifetime",
                         "dyn_udp_lifetime",
                         "dyn_short_lifetime",
#ifndef IPFW2
                         "dyn_grace_time"
#else
                         "dyn_keepalive"
#endif
                     };

    for (; i < ac; i++)
        for (j = 0; j < 16; j++) {
            if ((strncmp (av[i], ctlnam[j], strlen (ctlnam[j])) == 0) || ac == 2) {
                ptr = strstr(av[i], "=");

                n = sysctl_io (SOPT_GET, j, 0);
                if (!do_quiet)
                    printf ("%s: %i", ctlnam[j], n);
                if (ptr == NULL) {
                    if (!do_quiet)
                        printf ("\n");
                }
                else {
                    n = sysctl_io (SOPT_SET, j, atoi (++ptr));
                    if (n >= 0 && (!do_quiet))
                        printf (" -> %i\n", n);
                }

            }
        }
}

void
Exit (int exitcode)
{
    WSACleanup ();

#undef exit

    exit (exitcode);
}


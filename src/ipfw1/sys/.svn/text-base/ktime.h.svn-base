// -*- mode: C++; tab-width: 4; indent-tabs-mode: nil -*- (for GNU Emacs)

#ifndef _ktime_h_
#define _ktime_h_

typedef struct _SYSTEMTIME {
    unsigned short  wYear;
    unsigned short  wMonth;
    unsigned short  wDayOfWeek;
    unsigned short  wDay;
    unsigned short  wHour;
    unsigned short  wMinute;
    unsigned short  wSecond;
    unsigned short  wMilliseconds;
} SYSTEMTIME;

void    KernelTimeToSystemTime(PLARGE_INTEGER KernelTime, SYSTEMTIME *lpSystemTime);

#endif

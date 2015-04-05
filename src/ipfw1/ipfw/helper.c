/* Copyright (c) 2004-2006 Ruslan Staritsin, Vlad Goncharov
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

#include <windows.h>
#include <winsock2.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <process.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>

#include "helper.h"
#include "stdint.h"
#include "wipfw.h"
#include "win32.h"

static unsigned __stdcall   iflist_thread(void *param);
static unsigned __stdcall   iflist_thread2(void *param);
static HANDLE    g_threads[2];
static SOCKET    g_socket;
static int g_sw;

#define BUF_SIZE    (640 * 256)

BOOL
start(const char *config, BOOL exec)
{
    TCHAR szPath[MAX_PATH];
    unsigned int tid,tid2;
    int status;
    char exestr[MAX_PATH];
    char cmdline[1024];

    InitializeCriticalSection(&cs);

    // setup information about interfaces
    status = update_if_info(TRUE);
    if (status != 0) {
        fprintf(stderr, "start: update_if_info: %d\n", status);
        DeleteCriticalSection(&cs);
        return FALSE;
    }

    GetModuleFileName(0, szPath, MAX_PATH);
    *strrchr(szPath, '\\') = 0;
    SetCurrentDirectory ( szPath );

    if (exec == TRUE) {
        // execute command script
        if (_snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\"", config) < 0) {
            fprintf(stderr, "start: Command line to execute too long!");
            // continue anyway
        }
        else {
            // execute startup script
            WinExec(cmdline, SW_HIDE);
        }
    }

    g_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (g_socket == INVALID_SOCKET) {
        fprintf(stderr, "start: socket: %d\n", WSAGetLastError());
        DeleteCriticalSection(&cs);
        return FALSE;
    }

    g_threads[0] = (HANDLE)_beginthreadex(NULL, 0, iflist_thread, NULL, 0, &tid);
    g_threads[1] = (HANDLE)_beginthreadex(NULL, 0, iflist_thread2, NULL, 0, &tid2);
    if ((g_threads[0] == NULL) || (g_threads[1] == NULL)) {
        fprintf(stderr, "start: _beginthreadex: %d\n", errno);
        closesocket(g_socket);
        DeleteCriticalSection(&cs);
        return FALSE;
    }

    return TRUE;
}

void
stop(void)
{
    closesocket(g_socket);
    g_sw = 1;
}

void
wait(void)
{
    WaitForMultipleObjects(2, g_threads, FALSE, INFINITE);
    if (g_threads[0] != NULL)
        CloseHandle(g_threads[0]);
    if (g_threads[1] != NULL)
        CloseHandle(g_threads[1]);
    DeleteCriticalSection(&cs);
}

void
if_check()
{
    IP_ADAPTER_INFO *ipi, *ai;
    DWORD status;
    ULONG size;
    ULONG idx = 0;
    static ULONG old_idx;

    GetAdaptersInfo(NULL, &size);
    ipi = malloc(size);
    status = GetAdaptersInfo(ipi, &size);

    if (status == ERROR_SUCCESS && ipi != NULL) {
        /* get the 'checksum' of indexes */
        for (ai = ipi; ai != NULL; ai = ai->Next)
            idx += ai->Index;

        /* if checksum changed, update adapters info */
        if (idx != old_idx) {
            old_idx = idx;
            update_if_info(TRUE);
        }
        free(ipi);
    }

    return;
}

unsigned __stdcall
iflist_thread(void *param)
{
    while ( !g_sw ) {
        Sleep(5000);
        if_check();
    }
    return 0;
}

unsigned __stdcall
iflist_thread2(void *param)
{
    DWORD n;

    for (;;) {
        Sleep(1000);
        if (WSAIoctl(g_socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &n, NULL, NULL) == SOCKET_ERROR) {
            fprintf(stderr, "WSAIoctl: %d\n", WSAGetLastError());
            break;
        }
        update_if_info(TRUE);
    }
    return 0;
}

int idx_byguid(char *guid, char *name)
{
    TCHAR PrePath[] = _T("SYSTEM\\CurrentControlSet\\Control\\Network\\"\
                         "{4D36E972-E325-11CE-BFC1-08002BE10318}\\");
    TCHAR Path[MAX_PATH];
    TCHAR szName[MAX_PATH];
    DWORD size = MAX_PATH;
    HKEY hBaseKey = NULL;
    DWORD i = 0;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     PrePath,
                     0,
                     KEY_READ,
                     &hBaseKey) != ERROR_SUCCESS)
        return 0;

    while (RegEnumKeyEx(hBaseKey, ++i, szName, &size, \
                        NULL, NULL, NULL, NULL) != ERROR_NO_MORE_ITEMS) {
        if (!strncmp(szName, guid, size)) {
            RegCloseKey(hBaseKey);

            wsprintf(Path, _T("%s%s%s"), PrePath, szName, _T("\\Connection"));

            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &hBaseKey) == ERROR_SUCCESS)
                if (RegQueryValueEx(hBaseKey, _T("Name"),0, NULL, Path, &size)== ERROR_SUCCESS)
                    strncpy(name, Path, 41);

            return i;
        }
        size = MAX_PATH;
    }

    RegCloseKey(hBaseKey);
    return 0;
}

int
update_if_info(BOOL cfile)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    DWORD n, ie_buf_size, last_ie_offset;
    IP_ADAPTER_INFO *ai;
    IP_ADDR_STRING *as;
    char *buf = NULL, *ie_buf = NULL, *ifnam = NULL;
    int status, i;
    unsigned short last_units[sizeof(g_if_types) / sizeof(*g_if_types)];
    struct ip_fw_iflist_entry *last_ie;
    struct sockaddr_in *sin;

    if (cfile == TRUE)
        EnterCriticalSection(&cs);

    buf = malloc(BUF_SIZE);
    if (buf == NULL) {
        perror("malloc");
        goto done;
    }

    memset(last_units, 0, sizeof(last_units));

    // first, append information about loopback adapter

    ie_buf = (char *)malloc(sizeof(struct ip_fw_iflist_entry) + sizeof(struct sockaddr_in));
    if (ie_buf == NULL) {
        perror("malloc");
        goto done;
    }

    last_ie = (struct ip_fw_iflist_entry *)ie_buf;
    last_ie->size = sizeof(struct ip_fw_iflist_entry) + sizeof(struct sockaddr_in);
    ie_buf_size = last_ie->size;

    strcpy(last_ie->name, "lo");
    last_ie->unit = last_units[1]++;    // MIB_IF_TYPE_LOOPBACK
    last_ie->indx = 1;         // ??? is it always correct ???
    last_ie->addr_count = 1;

    sin = &last_ie->addr[0];
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("%s%d  - MS TCP Loopback (127.0.0.1)\n", last_ie->name, last_ie->unit);

    // next, append information about all another adapters
    n = BUF_SIZE;

    status = GetAdaptersInfo((IP_ADAPTER_INFO *)buf, &n);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "GetAdaptersInfo: %d\n", status);

        // ignore error but setup buf to NULL (assume we have only loopback adapter)
        free(buf);
        buf = NULL;
    }

    for (ai = (IP_ADAPTER_INFO *)buf; ai != NULL; ai = ai->Next) {

        ie_buf = (char *)realloc(ie_buf, ie_buf_size + sizeof(struct ip_fw_iflist_entry));
        if (ie_buf == NULL) {
            perror("realloc");
            goto done;
        }

        last_ie = (struct ip_fw_iflist_entry *)(ie_buf + ie_buf_size);
        ie_buf_size += sizeof(struct ip_fw_iflist_entry);
        last_ie->size = sizeof(struct ip_fw_iflist_entry);

        // find adapter name by type
        for (i = 0; i < sizeof(g_if_types) / sizeof(*g_if_types); i++)
            if (g_if_types[i].type == ai->Type)
                break;

        if (i >= sizeof(g_if_types) / sizeof(*g_if_types))
            i = 0;      // MIB_IF_TYPE_OTHER by default

        strcpy(last_ie->name, g_if_types[i].name);

        ifnam = malloc(256);
        if (ifnam == NULL) {
            perror("malloc");
            goto done;
        }
        memset(ifnam, 0, 256);
        if (ai->Type != MIB_IF_TYPE_PPP) {
            last_ie->unit = idx_byguid(ai->AdapterName, ifnam);
            CharToOem(ifnam,ifnam);
            if (last_ie->unit < 1)
                last_ie->unit = last_units[i]++;
        }
        else
            last_ie->unit = last_units[i]++;
        if (strlen(ifnam) < 2)
            strcpy(ifnam, ai->Description);
        if (strlen(ifnam) > 40)
            strncpy(ifnam+37, "...\0", 4);
        last_ie->indx = ai->Index;
        last_ie->addr_count = 0;

        printf("%s%d - %s ", last_ie->name, last_ie->unit, ifnam);
        free(ifnam);

        for (as = &ai->IpAddressList; as != NULL; as = as->Next) {

            if (strcmp(as->IpAddress.String, "0.0.0.0") == 0) {
                ;
                continue;       // not interested in such addresses
            }

            ie_buf_size += sizeof(struct sockaddr_in);
            last_ie->size += sizeof(struct sockaddr_in);

            last_ie_offset = (char *)last_ie - ie_buf;

            ie_buf = (char *)realloc(ie_buf, ie_buf_size);
            if (ie_buf == NULL) {
                perror("realloc");
                goto done;
            }

            // recalc last_ie after realloc()
            last_ie = (struct ip_fw_iflist_entry *)(ie_buf + last_ie_offset);

            sin = &last_ie->addr[last_ie->addr_count++];

            memset(sin, 0, sizeof(*sin));

            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = inet_addr(as->IpAddress.String);

            printf("(%s)", as->IpAddress.String);
        }
        printf("\n");
    }

    // append the last entry with size = 0

    ie_buf = (char *)realloc(ie_buf, ie_buf_size + sizeof(struct ip_fw_iflist_entry));
    if (ie_buf == NULL) {
        perror("realloc");
        goto done;
    }

    last_ie = (struct ip_fw_iflist_entry *)(ie_buf + ie_buf_size);
    ie_buf_size += sizeof(struct ip_fw_iflist_entry);
    last_ie->size = 0;

    if (cfile == FALSE)
        goto done;

    // ie_buf is ready to be sent!

    device = CreateFile("\\\\.\\Global\\ip_fw", GENERIC_READ | GENERIC_WRITE, \
                        FILE_SHARE_READ | FILE_SHARE_WRITE, \
                        NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        void *buf;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL,GetLastError(), 0, (LPTSTR) &buf, 0, NULL);
        CharToOem(buf,buf);
        fprintf(stderr, "CreateFile: %s\n", (LPTSTR)buf);
        goto done;
    }
    if (!DeviceIoControl(device, IP_FW_SET_IFLIST, ie_buf, ie_buf_size, NULL, 0, &n, NULL))
        fprintf(stderr, "DeviceIoControl: %d\n", GetLastError());

done:

    if (device != INVALID_HANDLE_VALUE)
        CloseHandle(device);

    if (ie_buf != NULL)
        free(ie_buf);
    if (buf != NULL)
        free(buf);
    if (cfile == TRUE)
        LeaveCriticalSection(&cs);

    return 0;
}

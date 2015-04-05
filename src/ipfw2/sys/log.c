/*
 * Copyright (c) 2003 Vladislav Goncharov
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

#include <ntddk.h>
#include <stdarg.h>
#include <stdio.h>

#include "log.h"
#include "ktime.h"

#define MEM_TAG             'ipfL'

#define LOG_QUEUE_SIZE      100
#define ASYNC_STRING_SIZE   128

#define LOG_PATH            L"\\SystemRoot\\security\\logs"

struct queue_entry {
    char        string[ASYNC_STRING_SIZE];
    SYSTEMTIME  time;
    unsigned int log_skipped;
};

static struct {
    struct      queue_entry *data;
    KSPIN_LOCK  guard;
    unsigned int head;   /* write to head */
    unsigned int tail;   /* read from tail */
    
    HANDLE      file;
    KMUTEX      file_guard;

    HANDLE      write_thread;
    KEVENT      write_event;
    
    BOOLEAN     b_exit;
} g_queue;

static long volatile g_last_event_id = 0;

static void     logger_thread(PVOID param);
static void     write_log_file(const SYSTEMTIME *time, const char *str);

/* some undocumented prototypes (from http://www.acc.umu.se/~bosse/ntifs.h) */

NTSTATUS
NTAPI
ZwWaitForSingleObject (
    IN HANDLE           Handle,
    IN BOOLEAN          Alertable,
    IN PLARGE_INTEGER   Timeout OPTIONAL
);


NTSTATUS
log_init(void)
{
    NTSTATUS status;

    KeInitializeMutex(&g_queue.file_guard, 0);

    // init queue
    
    KeInitializeSpinLock(&g_queue.guard);
    KeInitializeEvent(&g_queue.write_event, SynchronizationEvent, FALSE);

    g_queue.data = (struct queue_entry *)ExAllocatePoolWithTag(NonPagedPool, (sizeof(struct queue_entry) * LOG_QUEUE_SIZE), MEM_TAG);
    if (g_queue.data == NULL) {
        KdPrint(("[wipfw] log_init: malloc!\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memset(g_queue.data, 0, sizeof(struct queue_entry) * LOG_QUEUE_SIZE);

    g_queue.head = g_queue.tail = 0;
    g_queue.file = NULL;

    // create worker thread
    
    status = PsCreateSystemThread(&g_queue.write_thread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        logger_thread, NULL);
    if (status != STATUS_SUCCESS) {
        KdPrint(("[wipfw] log_init: PsCreateSystemThread!\n"));

        ExFreePool(g_queue.data);
        return status;
    }

    return STATUS_SUCCESS;
}

void
log_free(void)
{
    static const char end_msg[] = "--- end ---\r\n";

    LARGE_INTEGER offset;
    IO_STATUS_BLOCK isb;
    KIRQL irql;

    // terminate logger_thread
    g_queue.b_exit = TRUE;
    KeSetEvent(&g_queue.write_event, 0, FALSE);
    ZwWaitForSingleObject(g_queue.write_thread, FALSE, NULL);
    ZwClose(g_queue.write_thread);

    // clear logger queue
    KeAcquireSpinLock(&g_queue.guard, &irql);
    ExFreePool(g_queue.data);
    KeReleaseSpinLock(&g_queue.guard, irql);

    // close file

    KeWaitForSingleObject(&g_queue.file_guard, Executive, KernelMode, FALSE, NULL);

    offset.QuadPart = 0;
    ZwWriteFile(g_queue.file, NULL, NULL, NULL, &isb, (char *)end_msg, sizeof(end_msg) - 1, &offset, NULL);
   
    ZwClose(g_queue.file);
    g_queue.file = NULL;

    KeReleaseMutex(&g_queue.file_guard, FALSE);
}

void
log_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

void
log_vprintf(const char *fmt, va_list ap)
{
    char msg1[256], msg2[256 + sizeof("#4294967295 yyyy.mm.dd hh:mm:ss.mss\r\n")];
    size_t len;
    NTSTATUS status;
    LARGE_INTEGER time1, time2;
    SYSTEMTIME time3;
    KIRQL irql;
    struct queue_entry entry;
    unsigned int next_head;

    if (_vsnprintf(msg1, sizeof(msg1), fmt, ap) < 0)
        msg1[sizeof(msg1) - 1] = '\0';

    // remove the last \n if any

    len = strlen(msg1);
    while (len > 0 && msg1[len - 1] == '\n')
        msg1[--len] = '\0';
    
    // prepare msg2 with event number and timestamp

    KeQuerySystemTime(&time1);
    ExSystemTimeToLocalTime(&time1, &time2);
    KernelTimeToSystemTime(&time2, &time3);

    if (_snprintf(msg2, sizeof(msg2), "%010u %04d.%02d.%02d %02d:%02d:%02d.%03d\t%s\r\n", 
        InterlockedIncrement((long *)&g_last_event_id),
        time3.wYear, time3.wMonth, time3.wDay,
        time3.wHour, time3.wMinute, time3.wSecond, time3.wMilliseconds,
        msg1) < 0)
        msg2[sizeof(msg2) - 1] = '\0';

    KdPrint(("[wipfw] log_vprintf: %s\r\n", msg2));

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        // work with file
        write_log_file(&time3, msg2);

    } else {
        // work with queue

        strncpy(entry.string, msg2, sizeof(entry.string));
        entry.string[sizeof(entry.string) - 1] = '\0';

        memcpy(&entry.time, &time3, sizeof(SYSTEMTIME));

        KeAcquireSpinLock(&g_queue.guard, &irql);

        next_head = (g_queue.head + 1) % LOG_QUEUE_SIZE;
        
        if (next_head == g_queue.tail) {
            // queue overflow: reject one entry from tail
            entry.log_skipped = g_queue.data[g_queue.tail].log_skipped + 1;
            g_queue.tail = (g_queue.tail + 1) % LOG_QUEUE_SIZE;
        } else
            entry.log_skipped = 0;

        memcpy(&g_queue.data[g_queue.head], &entry, sizeof(struct queue_entry));

        g_queue.head = next_head;

        KeReleaseSpinLock(&g_queue.guard, irql);

        KeSetEvent(&g_queue.write_event, IO_NO_INCREMENT, FALSE);
    }
}

void
write_log_file(const SYSTEMTIME *time, const char *str)
{
    static const char   begin_msg[] = "--- begin ---\r\n";
    static const char   midnight_msg[] = "--- midnight ---\r\n";
    static SYSTEMTIME   last_time;
 
    NTSTATUS status;
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK isb;
    wchar_t log_name[256];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;

    KeWaitForSingleObject(&g_queue.file_guard, Executive, KernelMode, FALSE, NULL);

    if (g_queue.file == NULL || time->wDay != last_time.wDay) {
        // open or re-open file

        if (g_queue.file != NULL) {
            // previous file closed by a midnight reason

            status = ZwWriteFile(g_queue.file, NULL, NULL, NULL, &isb,
                (char *)midnight_msg, sizeof(midnight_msg) - 1, &offset, NULL);
            if (status != STATUS_SUCCESS)
                KdPrint(("[wipfw] write_log_file: ZwWriteFile: 0x%x\n", status));

            ZwClose(g_queue.file);
            g_queue.file = NULL;

            g_last_event_id = 0;
        }

        if (_snwprintf(log_name, sizeof(log_name), L"%s\\wipfw%04d%02d%02d.log", LOG_PATH,
            time->wYear, time->wMonth, time->wDay) < 0) {
                KdPrint(("[wipfw] write_log_file: name is too long!\n"));
                goto done;
            }

        RtlInitUnicodeString(&name, log_name);
        InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwCreateFile(&g_queue.file, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &isb, 0,
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);
        if (status != STATUS_SUCCESS) {
            KdPrint(("[wipfw] write_log_file: ZwCreateFile: 0x%x\n", status));
            goto done;
        }

        offset.QuadPart = 0;

        status = ZwWriteFile(g_queue.file, NULL, NULL, NULL, &isb, (char *)begin_msg, sizeof(begin_msg) - 1, &offset, NULL);
        if (status != STATUS_SUCCESS)
            KdPrint(("[wipfw] write_log_file: ZwWriteFile: 0x%x\n", status));
    }

    offset.QuadPart = 0;

    status = ZwWriteFile(g_queue.file, NULL, NULL, NULL, &isb, (char *)str, strlen(str), &offset, NULL);
    if (status != STATUS_SUCCESS)
        KdPrint(("[wipfw] write_log_file: ZwWriteFile: 0x%x\n", status));

done:
    memcpy(&last_time, time, sizeof(SYSTEMTIME));

    KeReleaseMutex(&g_queue.file_guard, FALSE);
}

void
logger_thread(PVOID param)
{
    KIRQL irql;
    struct queue_entry entry;
    BOOLEAN has_request;
    char skip_msg[64];

    for (;;) {
        KeWaitForSingleObject(&g_queue.write_event, Executive, KernelMode, FALSE, NULL);

        if (g_queue.b_exit)
            break;

        for (;;) {
            has_request = FALSE;

            // enter DISPATCH level
            KeAcquireSpinLock(&g_queue.guard, &irql);

            if (g_queue.head != g_queue.tail) {
                memcpy(&entry, &g_queue.data[g_queue.tail], sizeof(entry));
                has_request = TRUE;

                g_queue.tail = (g_queue.tail + 1) % LOG_QUEUE_SIZE;
            }

            KeReleaseSpinLock(&g_queue.guard, irql);
            // we're on PASSIVE level

            if (!has_request)
                break;

            if (entry.log_skipped != 0) {
                sprintf(skip_msg, "SKIP\t%u\r\n", entry.log_skipped);
                write_log_file(&entry.time, skip_msg);
            }

            write_log_file(&entry.time, entry.string);
        }
    }
}

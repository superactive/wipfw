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

#include <ntddk.h>
#include <ntddndis.h>
#include <pfhook.h>
#include <stdarg.h>
#include <stdio.h>

#include "ip_fw_nt.h"
#include <sys/queue.h>
#include <netinet/ip.h>
#include <netinet/ip_fw.h>

#include "if_list.h"
#include "ip_pfhook.h"

extern PDRIVER_OBJECT g_driver_object;

static NTSTATUS set_hook(PacketFilterExtensionPtr hook_fn);

static PF_FORWARD_ACTION    main_hook_proc(
        unsigned char *PacketHeader, unsigned char *Packet, unsigned int PacketLength,
        unsigned int RecvInterfaceIndex, unsigned int SendInterfaceIndex,
        IPAddr RecvLinkNextHop, IPAddr SendLinkNextHop);

static PF_FORWARD_ACTION    ipfw_hook_proc(
        unsigned char *PacketHeader, unsigned char *Packet, unsigned int PacketLength,
        unsigned int RecvInterfaceIndex, unsigned int SendInterfaceIndex,
        IPAddr RecvLinkNextHop, IPAddr SendLinkNextHop);

/* some undocumented prototypes (from http://www.acc.umu.se/~bosse/ntifs.h) */

NTSTATUS NTAPI  ZwLoadDriver(IN PUNICODE_STRING RegistryPath);
NTSTATUS NTAPI  ZwUnloadDriver(IN PUNICODE_STRING RegistryPath);

/* --- */

static const wchar_t g_ipfilterdriver[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\IpFilterDriver";

static BOOLEAN g_ipfilterdriver_loaded = FALSE;

PDEVICE_OBJECT g_devpfhook = NULL;
static PDEVICE_OBJECT g_org_devpfhook = NULL;

/* chain of post-installed hooks */

struct pfhook_entry {
    STAILQ_ENTRY(pfhook_entry) next;
    PF_SET_EXTENSION_HOOK_INFO hook_nfo;
};

STAILQ_HEAD(pfhook_head, pfhook_entry);

static struct pfhook_head g_pfhook_head;
static KSPIN_LOCK g_pfhook_guard;


NTSTATUS
pfhook_init(void)
{
    NTSTATUS status;
    UNICODE_STRING drvname;

    KeInitializeSpinLock(&g_pfhook_guard);

    status = set_hook(main_hook_proc);
    if (status == STATUS_INVALID_PARAMETER) {
        /*
         * on XP (don't known about another OSes) it means another driver has hook
         * we must break this (pfhook interfaces gives us no choise)
         */

        KdPrint(("[wipfw] pfhook_init: removing another hook...\n"));
        status = set_hook(NULL);
        if (status != STATUS_SUCCESS)
            KdPrint(("[wipfw] pfhook_init: set_hook(NULL): 0x%x\n", status));

        // next try...
        status = set_hook(main_hook_proc);
    }
    
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        // try to dynamically load ipfilterdriver! (cool)
        RtlInitUnicodeString(&drvname, g_ipfilterdriver);
        
        status = ZwLoadDriver(&drvname);
        if (status == STATUS_SUCCESS) {
            status = set_hook(main_hook_proc);
            if (status == STATUS_SUCCESS)
                g_ipfilterdriver_loaded = TRUE;
            else
                ZwUnloadDriver(&drvname);       // is it safe?
        }
    }

    return status;
}

void
pfhook_free(void)
{
    UNICODE_STRING drvname;

    set_hook(NULL);

    if (g_ipfilterdriver_loaded) {
        // is it safe?
        RtlInitUnicodeString(&drvname, g_ipfilterdriver);
        ZwUnloadDriver(&drvname);
    }
}

NTSTATUS
set_hook(PacketFilterExtensionPtr hook_fn)
{
    UNICODE_STRING ipfilter_name;
    NTSTATUS status;
    PFILE_OBJECT fileobj = NULL;
    PDEVICE_OBJECT devobj;
    PF_SET_EXTENSION_HOOK_INFO hook_nfo;
    PIRP irp = NULL;
    IO_STATUS_BLOCK isb;

    RtlInitUnicodeString(&ipfilter_name, DD_IPFLTRDRVR_DEVICE_NAME);
    
    if (g_org_devpfhook != NULL) {
        struct pfhook_entry *pfhe;
        KIRQL irql;

        // remove filter! (see attaching code below)
        KdPrint(("[wipfw] set_hook: detaching device...\n"));
        IoDetachDevice(g_org_devpfhook);

        // cleanup filter chain
        KeAcquireSpinLock(&g_pfhook_guard, &irql);

        for (pfhe = STAILQ_FIRST(&g_pfhook_head); pfhe != NULL; ) {
            struct pfhook_entry *pfhe2 = STAILQ_NEXT(pfhe, next);
            ExFreePool(pfhe);
            pfhe = pfhe2;
        }

        STAILQ_INIT(&g_pfhook_head);

        KeReleaseSpinLock(&g_pfhook_guard, irql);
    }

    status = IoGetDeviceObjectPointer(
            &ipfilter_name,
            STANDARD_RIGHTS_ALL,
            &fileobj,
            &devobj);
    if (status != STATUS_SUCCESS)
        goto done;

    hook_nfo.ExtensionPointer = hook_fn;
    
    irp = IoBuildDeviceIoControlRequest(IOCTL_PF_SET_EXTENSION_POINTER,
            devobj, &hook_nfo, sizeof(hook_nfo),
            NULL, 0, FALSE, NULL, &isb);
    if (irp == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }
    
    status = IoCallDriver(devobj, irp);
    if (status != STATUS_SUCCESS) {
        KdPrint(("[wipfw] set_hook: IoCallDriver: 0x%x\n", status));
        goto done;
    }

    if (hook_fn != NULL) {

        // using cowboy hi-tek! to break single filter restriction setup filter on device object!!!

        status = IoCreateDevice(g_driver_object, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_devpfhook);
        if (status != STATUS_SUCCESS) {
            KdPrint(("[wipfw] set_hook: IoCreateDevice: 0x%x\n", status));
            goto done;
        }

        status = IoAttachDevice(g_devpfhook, &ipfilter_name, &g_org_devpfhook);
        if (status != STATUS_SUCCESS) {
            KdPrint(("[wipfw] set_hook: IoAttachDevice: 0x%x\n", status));
            status = STATUS_UNSUCCESSFUL;
            goto done;
        }

    }

done:
    if (((hook_fn != NULL && status != STATUS_SUCCESS) || (hook_fn == NULL)) &&
        g_devpfhook != NULL) {
        // delete attached device
        IoDeleteDevice(g_devpfhook);
        g_devpfhook = NULL;
    }
    
    if (fileobj != NULL)
        ObDereferenceObject(fileobj);
    
    return status;
}

NTSTATUS
pfhook_DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);
    PF_SET_EXTENSION_HOOK_INFO *hook_nfo;
    struct pfhook_entry *new_entry, *pfhe;
    KIRQL irql;

    if (irps->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
        irps->Parameters.DeviceIoControl.IoControlCode == IOCTL_PF_SET_EXTENSION_POINTER) {
        
        // don't pass request! but append/remove into chain of filters
        
        if (irps->Parameters.DeviceIoControl.InputBufferLength != sizeof(*hook_nfo)) {
            irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        
        hook_nfo = (PF_SET_EXTENSION_HOOK_INFO *)irp->AssociatedIrp.SystemBuffer;

        if (hook_nfo->ExtensionPointer != NULL) {

            // prepare entry

            new_entry = ExAllocatePool(NonPagedPool, sizeof(*new_entry));
            if (new_entry == NULL) {
                irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            memset(new_entry, 0, sizeof(*new_entry));
            memcpy(&new_entry->hook_nfo, hook_nfo, sizeof(*hook_nfo));

            // insert entry into chain (first, try to find the same)

            KeAcquireSpinLock(&g_pfhook_guard, &irql);

            STAILQ_FOREACH(pfhe, &g_pfhook_head, next)
                if (pfhe->hook_nfo.ExtensionPointer == hook_nfo->ExtensionPointer)
                    break;

            if (pfhe == NULL) { 
            	;;
                // append new entry - - BUGBUG !!!
                // STAILQ_INSERT_TAIL(&g_pfhook_head, new_entry, next);
            }  else {
                // if the entry exists we don't increment usage counter because ipfilterdriver API doesn't support it
                ExFreePool(new_entry);
            }

            KeReleaseSpinLock(&g_pfhook_guard, irql);
        
        } else {

            // we don't have any information about the calling driver! so we just clear all handlers in chain :-(

            KeAcquireSpinLock(&g_pfhook_guard, &irql);

            for (pfhe = STAILQ_FIRST(&g_pfhook_head); pfhe != NULL; ) {
                struct pfhook_entry *pfhe2 = STAILQ_NEXT(pfhe, next);
                if (pfhe != NULL)
                	ExFreePool(pfhe);
                pfhe = pfhe2;
            }

            STAILQ_INIT(&g_pfhook_head);

            KeReleaseSpinLock(&g_pfhook_guard, irql);
        }

        irp->IoStatus.Status = STATUS_SUCCESS;

        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;

    } else {
        // pass request
        IoSkipCurrentIrpStackLocation(irp);
        return IoCallDriver(g_org_devpfhook, irp);
    }
}

/* firewall callback hook proc */
PF_FORWARD_ACTION
main_hook_proc(
    unsigned char *PacketHeader,
    unsigned char *Packet,
    unsigned int PacketLength,
    unsigned int RecvInterfaceIndex,
    unsigned int SendInterfaceIndex,
    IPAddr RecvLinkNextHop,
    IPAddr SendLinkNextHop)
{
    PF_FORWARD_ACTION result;
    struct pfhook_entry *pfhe;
    KIRQL irql;

    // first, call ipfw_hook_proc
    result = ipfw_hook_proc(PacketHeader, Packet, PacketLength, RecvInterfaceIndex, SendInterfaceIndex,
        RecvLinkNextHop, SendLinkNextHop);

    /*
     * To work with chain of filters according to DDK documentation: if filter in chain returns PF_PASS we break the
     * chain and return PF_PASS. If the filter returns PF_FORWARD we go to the next filter (forward packet). If the
     * filter returns another value we break the chain and return the value too.
     * ??? is this correct ???
     */
    
    if (result == PF_FORWARD) {
        KeAcquireSpinLock(&g_pfhook_guard, &irql);

        STAILQ_FOREACH(pfhe, &g_pfhook_head, next) {
            result = pfhe->hook_nfo.ExtensionPointer(PacketHeader, Packet, PacketLength,
                RecvInterfaceIndex, SendInterfaceIndex, RecvLinkNextHop, SendLinkNextHop);
            if (result != PF_FORWARD)
                break;
        }

        KeReleaseSpinLock(&g_pfhook_guard, irql);
    }

    return result;
}

PF_FORWARD_ACTION
ipfw_hook_proc(
    unsigned char *PacketHeader,
    unsigned char *Packet,
    unsigned int PacketLength,
    unsigned int RecvInterfaceIndex,
    unsigned int SendInterfaceIndex,
    IPAddr RecvLinkNextHop,
    IPAddr SendLinkNextHop)
{
    PF_FORWARD_ACTION result;
    struct mbuf m;
    char *data = NULL;
    struct ip *ip = (struct ip *)PacketHeader;
    unsigned int hlen = (ip->ip_hl << 2);
    int off;
    struct ip_fw_args args;
    KIRQL irql;
    BOOLEAN iflist_acquired = FALSE;
    struct sockaddr_in next_hop;
    
    KdPrint(("[wipfw] ipfw_hook_proc: hlen = %u, RecvLinkNextHop = 0x%x, SendLinkNextHop = 0x%x\n",
        hlen, RecvLinkNextHop, SendLinkNextHop));

    // prepare mbuf as 1 chain (to avoid m_pullup usage)

    memset(&m, 0, sizeof(m));

    m.m_flags = M_PKTHDR;
    m.m_len = m.m_pkthdr.len = hlen + PacketLength;

    if (hlen + PacketLength < MHLEN) {
        // quick case
        m.m_data = m.m_pktdat;
    } else {
        // slow case
        data = ExAllocatePool(NonPagedPool, m.m_len);
        if (data == NULL) {
            result = PF_DROP;
            goto done;
        }

        m.m_data = data;
    }

    memcpy(m.m_data, ip, hlen);
    memcpy(m.m_data + hlen, Packet, PacketLength);

    if (RecvInterfaceIndex != INVALID_PF_IF_INDEX) {
        m.m_pkthdr.rcvif = get_if_by_index(RecvInterfaceIndex, &irql);
        if (m.m_pkthdr.rcvif == NULL) {
#ifdef DBG
            KdPrint(("[wipfw] ipfw_hook_proc: can't find recv interface by index %d!\n", RecvInterfaceIndex));
#endif
            result = PF_DROP;
            goto done;
        }
        iflist_acquired = TRUE;
    }

    // mbuf is ready

    memset(&args, 0, sizeof(args));

    args.m = &m;            /* the packet we are looking at */
    args.oif = NULL;        /* this is an input packet */

    if (SendInterfaceIndex != INVALID_PF_IF_INDEX) {
        args.oif = get_if_by_index(SendInterfaceIndex, (iflist_acquired ? NULL : &irql));
        if (args.oif == NULL) {
#ifdef DBG
            KdPrint(("[wipfw] ipfw_hook_proc: can't find out interface by index %d!\n", SendInterfaceIndex));
#endif
            result = PF_DROP;
            goto done;
        }
        iflist_acquired = TRUE;
    }

    // ??? is it correct ???
    if (SendLinkNextHop != ZERO_PF_IP_ADDR) {

        memset(&next_hop, 0, sizeof(next_hop));

        next_hop.sin_family = AF_INET;
        next_hop.sin_addr.s_addr = SendLinkNextHop;

        args.next_hop = &next_hop;

    } else
        args.next_hop = NULL;

    // calling ip_fw_chk_ptr with iflist spinlock acquired (ip_fw_chk_ptr can safely call INADDR_TO_IFP)

    off = ip_fw_chk_ptr(&args);

    KdPrint(("[wipfw] ipfw_hook_proc: ip_fw_chk_ptr: %d\n", off));

    if (args.m == NULL || off == IP_FW_PORT_DENY_FLAG)
        result = PF_DROP;
    else if (args.next_hop == NULL)
        result = PF_PASS;
    else
        result = PF_FORWARD;

done:
    if (iflist_acquired)
        KeReleaseSpinLock(&g_iflist_guard, irql);
    if (data != NULL)
        ExFreePool(data);
#ifdef DBG
    KdPrint(("[wipfw] ipfw_hook_proc: result = %d\n", result));
#endif
    return result;
}

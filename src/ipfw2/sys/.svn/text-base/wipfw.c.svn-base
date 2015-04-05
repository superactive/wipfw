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
#include <wdmsec.h>

#include "ip_fw_nt.h"
#include <netinet/ip_fw.h>

#include "if_list.h"
#include "ip_pfhook.h"
#include "ndis_hook.h"
#include "log.h"
#include "wipfw.h"

extern struct moduledata *module_ipfw;

extern int *_fw_enable;
extern int *_fw_one_pass;
extern int *_fw_debug;
extern int *_fw_verbose;
extern int *_fw_verbose_limit;
extern int *_fw_dyn_buckets;
extern int *_fw_curr_dyn_buckets;
extern int *_fw_dyn_count;
extern int *_fw_dyn_max;
extern int *_fw_static_count;
extern int *_fw_dyn_ack_lifetime;
extern int *_fw_dyn_syn_lifetime;
extern int *_fw_dyn_fin_lifetime;
extern int *_fw_dyn_rst_lifetime;
extern int *_fw_dyn_udp_lifetime;
extern int *_fw_dyn_short_lifetime;
#ifndef IPFW2
extern int *_fw_dyn_grace_time;
#else
extern int *_fw_dyn_keepalive;
#endif

ip_fw_chk_t *ip_fw_chk_ptr = NULL;
ip_fw_ctl_t *ip_fw_ctl_ptr = NULL;

#ifdef KLD_MODULE
static VOID         OnUnload(IN PDRIVER_OBJECT DriverObject);
#endif

static NTSTATUS     DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);
static NTSTATUS     DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

PDRIVER_OBJECT   g_driver_object = NULL;

static PDEVICE_OBJECT   g_devcontrol = NULL;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT theDriverObject,
    IN PUNICODE_STRING theRegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devname, linkname;
    BOOLEAN ip_fw_started = FALSE, pfhook_started = FALSE;
    int i;

    g_driver_object = theDriverObject;

    log_init();

    /* before starting ip_fw init ip_fw_nt wrappers */
    ip_fw_nt_init();
    rn_init();
    init_tables();
    iflist_init();
    init_packet();
    
    /* send load event to ip_fw */
    
    status = module_ipfw->modevent(theDriverObject, MOD_LOAD, NULL);
    if (status != STATUS_SUCCESS) {
        KdPrint(("[wipfw] DriverEntry: ip_fw MOD_LOAD: 0x%x!\n", status));
        goto done;
    }

    ip_fw_started = TRUE;

    /* setup pfhook */

    status = pfhook_init();
    if (status != STATUS_SUCCESS) {
        KdPrint(("[wipfw] DriverEntry: pfhook_init: 0x%x!\n", status));
        goto done;
    }

    pfhook_started = TRUE;

    /* create control device and symbolic link */

    RtlInitUnicodeString(&devname, L"\\Device\\ip_fw");

    status = IoCreateDeviceSecure(theDriverObject, 0, &devname, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, (BOOLEAN) FALSE, \
    	&SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &g_devcontrol);
    if (status != STATUS_SUCCESS) {
        KdPrint(("[wipfw] DriverEntry: IoCreateDevice: 0x%x!\n", status));
        goto done;
    }
    
    g_devcontrol->Flags |= DO_POWER_PAGABLE;

    RtlInitUnicodeString(&linkname, L"\\??\\ip_fw");

    status = IoCreateSymbolicLink(&linkname, &devname);
    if (status != STATUS_SUCCESS) {
        KdPrint(("[wipfw] DriverEntry: IoCreateSymbolicLink: 0x%x!\n", status));
        goto done;
    }

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        theDriverObject->MajorFunction[i] = DeviceDispatch;
        
    theDriverObject->MajorFunction[IRP_MJ_PNP] = DeviceDispatch;

#ifdef KLD_MODULE
    theDriverObject->DriverUnload = OnUnload;
#endif

    status = STATUS_SUCCESS;

done:
    if (status != STATUS_SUCCESS) {
        if (g_devcontrol != NULL)
            IoDeleteDevice(g_devcontrol);
        if (pfhook_started)
            pfhook_free();
        if (ip_fw_started)
            module_ipfw->modevent(theDriverObject, MOD_UNLOAD, NULL);
        
        iflist_free();
        log_free();
    }

    return status;
}

#ifdef KLD_MODULE
VOID
OnUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING linkname;
    
    free_packet();

    RtlInitUnicodeString(&linkname, L"\\??\\ip_fw");
    IoDeleteSymbolicLink(&linkname);

    IoDeleteDevice(g_devcontrol);

    pfhook_free();
    module_ipfw->modevent(g_driver_object, MOD_UNLOAD, NULL);
    iflist_free();
    log_free();
}
#endif

NTSTATUS
DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    if (g_devpfhook != NULL && DeviceObject == g_devpfhook) {
        // ioctl for pfhook filter
        return pfhook_DeviceDispatch(DeviceObject, irp);
    
    } else if (g_devcontrol != NULL && DeviceObject == g_devcontrol) {
        // ioctl for ip_fw control device
        PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);
        
        if (irps->MajorFunction == IRP_MJ_DEVICE_CONTROL)
            return DispatchIoctl(DeviceObject, irp);
        else {
            // complete with success
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);

            return STATUS_SUCCESS;
        }
    } else {
        // unknown device object
        KdPrint(("[wipfw] DeviceDispatch: unknown device object %p\n", DeviceObject));

        irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        
        return STATUS_NOT_SUPPORTED;
    }
}

/* IRP_MJ_DEVICE_CONTROL for control device dispatcher */
NTSTATUS
DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);
    
    ULONG ioctl = irps->Parameters.DeviceIoControl.IoControlCode,
        len = irps->Parameters.DeviceIoControl.InputBufferLength,
        size = irps->Parameters.DeviceIoControl.OutputBufferLength;
    
    void *buf = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status;

    irp->IoStatus.Information = 0;      // neccessary?

    switch (ioctl) {
    case IP_FW_SETSOCKOPT:
    case IP_FW_GETSOCKOPT: {
        
        struct sockopt *sopt;

        if (len < sizeof(struct sockopt)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        sopt = (struct sockopt *)buf;

        // setup sopt->sopt_val
        if (sopt->sopt_valsize > 0)
            sopt->sopt_val = sopt->sopt_val_buf;
        else
            sopt->sopt_val = NULL;

        if (ip_fw_ctl_ptr != NULL) {
            status = ip_fw_ctl_ptr(sopt);
            if (status == STATUS_SUCCESS && ioctl == IP_FW_GETSOCKOPT) {
                irp->IoStatus.Information = sizeof(struct sockopt) + sopt->sopt_valsize;
            }

        } else
            status = STATUS_INVALID_PARAMETER;      // ??? good status ???

        break;
    }

    case IP_FW_SET_IFLIST:

        if (len < sizeof(struct ip_fw_iflist_entry)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        status = iflist_setup((struct ip_fw_iflist_entry *)buf);

        break;
    
    case IP_FW_SYSCTL_IO: {
    
    	struct sysctl *ctldata;
    	int *n;
    	
    	if (len < sizeof(struct sysctl)) {
    		status = STATUS_INFO_LENGTH_MISMATCH;
    		break;
    	}
    	
    	ctldata = (struct sysctl *)buf;
    	
    	switch (ctldata->sysctl_name) {
    	case FW_ONE_PASS:
    		n = _fw_one_pass;
    		break;
    	case FW_DEBUG:
    		n = _fw_debug;
    		break;
    	case FW_VERBOSE:
    		n = _fw_verbose;
    		break;	
    	case FW_VERBOSE_LIMIT:
    		n = _fw_verbose_limit;
    		break;
    	case DYN_BUCKETS:
    		n = _fw_dyn_buckets;
    		break;
    	case CURR_DYN_BUCKETS:
    		n = _fw_curr_dyn_buckets;
    		ctldata->sopt_dir = SOPT_GET;
    		break;
    	case DYN_COUNT:
    		n = _fw_dyn_count;
    		ctldata->sopt_dir = SOPT_GET;
    		break;
    	case DYN_MAX:
    		n = _fw_dyn_max;
    		break;
    	case STATIC_COUNT:
    		n = _fw_static_count;
    		ctldata->sopt_dir = SOPT_GET;
    		break;
    	case DYN_ACK_LIFETIME:
    		n = _fw_dyn_ack_lifetime;
    		break;
    	case DYN_SYN_LIFETIME:
    		n = _fw_dyn_syn_lifetime;
    		break;
    	case DYN_FIN_LIFETIME:
    		n = _fw_dyn_fin_lifetime;
    		break;
    	case DYN_RST_LIFETIME:
    		n = _fw_dyn_rst_lifetime;
    		break;
    	case DYN_UDP_LIFETIME:
    		n = _fw_dyn_udp_lifetime;
    		break;
    	case DYN_SHORT_LIFETIME:
    		n = _fw_dyn_short_lifetime;
    		break;
#ifndef IPFW2
    	case DYN_GRACE_TIME:
    		n = _fw_dyn_grace_time;
    		ctldata->sopt_dir = SOPT_GET;
#else
        case DYN_KEEPALIVE:
    		n = _fw_dyn_keepalive;
#endif
    		break;
       	default:
    		break;
    	}
    	
    	if (ctldata->sopt_dir == SOPT_SET) {
    		*n = ctldata->sysctl_val;
    	}
    	
    	ctldata->sysctl_val = *n;
    	irp->IoStatus.Information = sizeof(struct sysctl);
    	
    	status = STATUS_SUCCESS;
        break;
    }
    
    default:
        status = STATUS_NOT_SUPPORTED;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

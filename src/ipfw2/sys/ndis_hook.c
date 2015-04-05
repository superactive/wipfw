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

#include <ndis.h>
#include "ndis_hk_ioctl.h"
#include "ndis_hook.h"

static BOOLEAN filter_packet(int direction, int iface, PNDIS_PACKET packet, struct filter_nfo *self, 
                              BOOLEAN packet_unchanged); 
static BOOLEAN process_ip(int direction, struct ip *ip, struct ip *Packet, int iface);
                              
#pragma pack(1)
struct ether_hdr {
	UCHAR	ether_dhost[6];
	UCHAR	ether_shost[6];
	USHORT	ether_type;
};

#define	ETHERTYPE_IP		0x0800	/* IP protocol */

#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */

#pragma pack()

static PDEVICE_OBJECT g_ndis_hk_devobj = NULL;
static PFILE_OBJECT g_ndis_hk_fileobj = NULL;
                              
static struct filter_nfo g_tdi_fw = {
	sizeof(g_tdi_fw),
	filter_packet,
	NULL,
	NULL,
	NULL,
	NULL
};

// interface of ndis_hk
struct ndis_hk_interface *g_ndis_hk;

NTSTATUS
get_iface(void)
{
	PIRP irp;
	IO_STATUS_BLOCK isb;

	irp = IoBuildDeviceIoControlRequest(IOCTL_CMD_GET_KM_IFACE,
		g_ndis_hk_devobj,
		NULL, 0,
		&g_ndis_hk, sizeof(g_ndis_hk),
		TRUE, NULL, &isb);
	if (irp == NULL) {
		KdPrint(("[wipfw-ndis] get_iface: IoBuildDeviceIoControlRequest!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return IoCallDriver(g_ndis_hk_devobj, irp);
}

void
free_packet(void)
{
	if (g_ndis_hk_fileobj != NULL) {
		// detach our filter!
		if (g_ndis_hk != NULL) {
			g_ndis_hk->attach_filter(&g_tdi_fw, FALSE, FALSE);
			g_ndis_hk = NULL;
		}

		ObDereferenceObject(g_ndis_hk_fileobj);
		g_ndis_hk_fileobj = NULL;
	}
}

NTSTATUS
init_packet(void)
{
	NTSTATUS status;
	UNICODE_STRING devname;

	// connect with ndis_hk
	RtlInitUnicodeString(&devname, L"\\Device\\ndis_hk");
	
	status = IoGetDeviceObjectPointer(
		&devname,
		STANDARD_RIGHTS_ALL,
		&g_ndis_hk_fileobj,
		&g_ndis_hk_devobj);
	if (status == STATUS_SUCCESS) {

		/* using ndis_hk driver */

		status = get_iface();
		if (status != STATUS_SUCCESS) {
			KdPrint(("[wipfw-ndis] init_packet get_iface: 0x%x!\n", status));
			goto done;
		}

		// attach our filter!
		g_ndis_hk->attach_filter(&g_tdi_fw, TRUE, FALSE);	// to bottom of filter stack
	
	} 

	if (status != STATUS_SUCCESS) {
		// cleanup
		free_packet();
	}

done:
	return status;
}

BOOLEAN
filter_packet(int direction, int iface, PNDIS_PACKET packet, struct filter_nfo *self,
			  BOOLEAN packet_unchanged)
{
    struct ip *ip_hdr;
    
    BOOLEAN result;
    PNDIS_BUFFER buffer;
    UINT packet_len, buffer_len, buffer_offset, hdr_len;
    void *pointer;
    struct ether_hdr *ether_hdr;
    
     KdPrint(("[wipfw-ndis] direction:%s |interface %i", direction ? "out" : "in", iface));
    
    // parse packet

    NdisQueryPacket(packet, NULL, NULL, &buffer, &packet_len);
   
    if (packet_len < sizeof(struct ether_hdr)) {
		KdPrint(("[wipfw-ndis] filter_packet: too small packet for ether_hdr! (%u)\n", packet_len));
		goto done;
	}

	/* process ether_hdr */

	NdisQueryBuffer(buffer, &ether_hdr, &buffer_len);

	if (buffer_len < sizeof(struct ether_hdr)) {
		KdPrint(("[wipfw-ndis] filter_packet: too small buffer for ether_hdr! (%u)\n", buffer_len));
		goto done;
	}
	buffer_offset = 0;
	
	// go to the next header
	if (buffer_len > sizeof(struct ether_hdr)) {

		pointer = (char *)ether_hdr + sizeof(struct ether_hdr);
		buffer_offset += sizeof(struct ether_hdr);

		buffer_len -= sizeof(struct ether_hdr);

	} else {
		// use next buffer in chain

		do {
			NdisGetNextBuffer(buffer, &buffer);
			NdisQueryBuffer(buffer, &pointer, &buffer_len);
		} while (buffer_len == 0);		// sometimes there're buffers with zero size in chain
		
		buffer_offset = 0;
	}

	if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {

		/* process ip_hdr */

		if (buffer_len < sizeof(struct ip)) {
			KdPrint(("[wipfw-ndis] filter_packet: too small buffer for ip_hdr! (%u)\n",
				buffer_len));
			goto done;
		}

		ip_hdr = (struct ip *)pointer;
		hdr_len = ip_hdr->ip_hl * 4;

		if (buffer_len < hdr_len) {
			KdPrint(("[wipfw-ndis] filter_packet: too small buffer for ip_hdr! (%u vs. %u)\n",
				buffer_len, hdr_len));
			goto done;
		}

		// check we've got the first fragment (don't work with another!)
		if ((ntohs(ip_hdr->ip_off) & IP_OFFMASK) != 0 && (ip_hdr->ip_off & IP_DF) == 0) {

			KdPrint(("[wipfw-ndis] filter_packet: got not first fragment\n"));

			result = TRUE;
			goto done;
		}
		
		result = process_ip(direction, ip_hdr, ip_hdr, iface);
	}

done:    
    
    return TRUE; //accept currently
}

BOOLEAN
process_ip(int direction, struct ip *ip, struct ip *Packet, int iface)
{
    
    struct mbuf m;
    char *data = NULL;
    unsigned int hlen = (ip->ip_hl << 2);
    int off;
    struct ip_fw_args args;
    KIRQL irql;
    BOOLEAN iflist_acquired = FALSE;
    struct sockaddr_in next_hop;
     
    BOOLEAN PF_DROP = FALSE;
    BOOLEAN PF_PASS = FALSE;
    BOOLEAN PF_FORWARD = TRUE;
    BOOLEAN result;
    
    unsigned int PacketLength = ntohs(ip->ip_len);
    
    KdPrint(("hlen = %i", hlen));
    KdPrint(("PacketLength = %i", PacketLength));
   
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

    // mbuf is ready

    memset(&args, 0, sizeof(args));

    args.m = &m;            /* the packet we are looking at */
    args.oif = NULL;        /* this is an input packet */
    args.next_hop = NULL;

    // calling ip_fw_chk_ptr with iflist spinlock acquired (ip_fw_chk_ptr can safely call INADDR_TO_IFP)
    off = ip_fw_chk_ptr(&args);

    KdPrint(("[wipfw-ndis] ipfw_NDISK_hook_proc: ip_fw_chk_ptr: %d\n", off));

    if (args.m == NULL || off == IP_FW_PORT_DENY_FLAG)
        result = PF_DROP;
    else if (args.next_hop == NULL)
        result = PF_PASS;
    else
        result = PF_FORWARD;

done:
    if (data != NULL)
        ExFreePool(data);

    KdPrint(("[wipfw-ndis] ipfw_NDISK_hook_proc: result = %d\n", result));

    return result;
}

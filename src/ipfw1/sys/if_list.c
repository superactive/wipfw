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
#include <stdarg.h>
#include <stdio.h>

#include "ip_fw_nt.h"
#include "wipfw.h"

KSPIN_LOCK  g_iflist_guard;

static struct ifnet     *g_iflist;
static unsigned int     g_iflist_count;

struct in_ifaddrhead    in_ifaddr;

void
iflist_init(void)
{
    KeInitializeSpinLock(&g_iflist_guard);

    g_iflist = NULL;
    g_iflist_count = 0;

    TAILQ_INIT(&in_ifaddr);
}

void
iflist_free(void)
{
    KIRQL irql;
    unsigned int i;
    struct ifaddr *ia, *ia2;

    // cleanup all interfaces information
    KeAcquireSpinLock(&g_iflist_guard, &irql);

    if (g_iflist != NULL) {
        for (i = 0; i < g_iflist_count; i++) {
            for (ia = TAILQ_FIRST(&g_iflist[i].if_addrhead); ia != NULL; ) {
                ia2 = TAILQ_NEXT(ia, ifa_link);
                ExFreePool(ia);
                ia = ia2;
            }
        }
    }
    
    if (g_iflist != NULL) {
       ExFreePool(g_iflist);
       g_iflist = NULL;
    }
    g_iflist_count = 0;

    TAILQ_INIT(&in_ifaddr);

    KeReleaseSpinLock(&g_iflist_guard, irql);
}

NTSTATUS
iflist_setup(struct ip_fw_iflist_entry *list)
{
    NTSTATUS status;
    KIRQL irql;
    unsigned int i, j, count;
    struct ip_fw_iflist_entry *l;
    struct ifaddr *ia, *ia2;
    struct in_ifaddr *new_ia;

    // count new entries

    for (count = 0, l = list; l->size != 0; count++, (char *)l += l->size)
        ;

    KeAcquireSpinLock(&g_iflist_guard, &irql);

    // first, cleanup all interfaces information
   
    if (g_iflist != NULL) {
    	for (i = 0; i < g_iflist_count; i++) {
    	    for (ia = TAILQ_FIRST(&g_iflist[i].if_addrhead); ia != NULL; ) {
    	        ia2 = TAILQ_NEXT(ia, ifa_link);
    	        if (ia != NULL)
    	        	ExFreePool(ia);
     	       ia = ia2;
     	   }
    	}
    }

    if (g_iflist != NULL)
        ExFreePool(g_iflist);

    TAILQ_INIT(&in_ifaddr);

    // next, create new information

    g_iflist_count = count;

    if (count > 0) {

        g_iflist = ExAllocatePool(NonPagedPool, count * sizeof(struct ifnet));
        if (g_iflist == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }

        memset(g_iflist, 0, count * sizeof(struct ifnet));

        for (i = 0, l = list; i < count && l->size != 0; i++, (char *)l += l->size) {
            strcpy(g_iflist[i].if_name, l->name);
            
            g_iflist[i].if_unit = l->unit;
            g_iflist[i].if_indx = l->indx;
            
            TAILQ_INIT(&g_iflist[i].if_addrhead);

            for (j = 0; j < l->addr_count; j++) {

                new_ia = ExAllocatePool(NonPagedPool, sizeof(*new_ia));
                if (new_ia == NULL) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto done;
                }

                memset(new_ia, 0, sizeof(*new_ia));

                new_ia->ia_ifp = &g_iflist[i];
                memcpy(&new_ia->ia_addr, &l->addr[j], sizeof(struct sockaddr_in));
                new_ia->ia_ifa.ifa_addr = (struct sockaddr *)&new_ia->ia_addr;

                // append to g_iflist[i] list
                TAILQ_INSERT_TAIL(&g_iflist[i].if_addrhead, (struct ifaddr *)new_ia, ifa_link);

                // append to in_ifaddr list
                TAILQ_INSERT_TAIL(&in_ifaddr, new_ia, ia_list);
            }
        }

    } else
        g_iflist = NULL;

    status = STATUS_SUCCESS;

done:
    KeReleaseSpinLock(&g_iflist_guard, irql);
    return status;
}

struct ifnet *
get_if_by_index(u_int32_t indx, KIRQL *old_irql)
{
    struct ifnet *result = NULL;
    unsigned int i;

    if (old_irql != NULL)
        KeAcquireSpinLock(&g_iflist_guard, old_irql);

    if (g_iflist != NULL) {
	for (i = 0; i < g_iflist_count; i++)
		if (g_iflist[i].if_indx == indx)
			return &g_iflist[i];            // don't release spinlock
    }
    
    if (old_irql != NULL)
        KeReleaseSpinLock(&g_iflist_guard, *old_irql);
    
    return NULL;
}

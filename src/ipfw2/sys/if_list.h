#ifndef _if_list_h_
#define _if_list_h_

void    iflist_init(void);
void    iflist_free(void);

NTSTATUS    iflist_setup(struct ip_fw_iflist_entry *list);

struct ifnet    *get_if_by_index(u_int32_t indx, KIRQL *old_irql);

extern KSPIN_LOCK   g_iflist_guard;


#endif

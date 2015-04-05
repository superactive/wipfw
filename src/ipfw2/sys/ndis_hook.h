#ifndef _ndis_hook_h_
#define _ndisk_hook_h_

NTSTATUS init_packet(void);
void free_packet(void);

extern PDEVICE_OBJECT g_ndis_hk_devobj;
extern PFILE_OBJECT g_ndis_hk_fileobj;


#endif
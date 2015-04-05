#ifndef _ip_pfhook_h_
#define _ip_pfhook_h_

NTSTATUS    pfhook_init(void);
void        pfhook_free(void);

extern PDEVICE_OBJECT g_devpfhook;

NTSTATUS    pfhook_DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

#endif

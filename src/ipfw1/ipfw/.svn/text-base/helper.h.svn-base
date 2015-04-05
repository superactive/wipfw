#ifndef _wipfw_helper_h_
#define _wipfw_helper_h_

#define SERVICE	TEXT("ipfw")
#define DRIVER	TEXT("ip_fw")

#define SERVICE_DESCRIPTION	TEXT("ipfw_helper")
#define DRIVER_DESCRIPTION	TEXT("ipfw kernel-mode driver")

#define CONFIG_SUBKEY	"SYSTEM\\CurrentControlSet\\Services\\" SERVICE

BOOL    start(const char *config, BOOL exec);
void    stop(void);
void    wait(void);
int update_if_info(BOOL cfile);

extern BOOL     g_console;

#endif /* _wipfw_helper_h_ */

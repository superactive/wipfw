#ifndef _log_h_
#define _log_h_

NTSTATUS    log_init(void);
void        log_free(void);

void        log_printf(const char *fmt, ...);
void        log_vprintf(const char *fmt, va_list ap);

#endif

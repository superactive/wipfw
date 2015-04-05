#ifndef _types_h_
#define _types_h_

#define CHAR_BIT        8

#ifndef ULONG_MAX
# define ULONG_MAX  (~0UL)
#endif

#ifdef __LCC__
typedef long long           _int64;
typedef unsigned long long  uint64_t;
typedef unsigned int        uint32_t;
#endif  /* __LCC__ */

#define ULONG   unsigned long
#define USHORT  unsigned short
#define UCHAR   unsigned char

#ifdef _MSC_VER
typedef int                 int32_t;
typedef unsigned int        uint32_t;
typedef unsigned short      u_short;
typedef unsigned short      uint16_t;
typedef unsigned __int64    uint64_t;
typedef unsigned char       u_char;
typedef unsigned int        u_int;
typedef unsigned short      u_short;
typedef unsigned long       u_long;
typedef unsigned char       uint8_t;
typedef char                int8_t;
#endif  /* _MSC_VER */

typedef unsigned char           u_int8_t;
typedef unsigned short          u_int16_t;
typedef unsigned int            u_int32_t;
typedef unsigned __int64        u_int64_t;

typedef unsigned int            uint;

#define uintptr_t               unsigned long

/*
 * Network types.
 *
 * Internally the system keeps counters in the headers with the bytes
 * swapped so that VAX instructions will work on them.  It reverses
 * the bytes before transmission at each protocol level.  The n_ types
 * represent the types with the bytes in ``high-ender'' order.
 */
typedef u_int16_t n_short;              /* short as received from the net */
typedef u_int32_t n_long;               /* long as received from the net */

typedef u_int32_t n_time;               /* ms since 00:00 GMT, byte rev */

typedef u_int32_t       uid_t;  // Vlad: TODO: replace to GUID
typedef u_int32_t       gid_t;  // Vlad: TODO: replace to GUID

#define LITTLE_ENDIAN   1234
#define BIG_ENDIAN      4321

#endif

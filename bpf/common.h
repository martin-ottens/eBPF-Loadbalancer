#ifndef __LB_COMMON_H
#define __LB_COMMON_H

#define LB_SERVICE_LEN 30
#define LB_LOOKUP_LEN 60
#define CONNTRACK_MAP_PERCPU_LEN 1000
#define IPV4_STR_LEN 16

typedef struct __service_entry {
    __u32 addr;
    __u8 active;
} service_entry_t;

#endif // __LB_COMMON_H

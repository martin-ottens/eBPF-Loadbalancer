#define _GNU_SOURCE

#include <stdio.h>
#include <libconfig.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "loadbalancer.skel.h"
#include "common.h"

#define KEEPALIVE_DOWN_MILLIS 10 * 1000
#define KEEPALIVE_CHECK_INTERVAL_SECS 5
#define ARPING_INTERVAL 30
#define WATCHDOG_LISTEN_PORT 4242
#define DECREMENT_TTL 1

static struct lb_config {
    char virtual_ip[IPV4_STR_LEN];
    __u32 virtual_ip_int;
    char service_ips[LB_SERVICE_LEN][IPV4_STR_LEN];
    __u32 service_ips_int[LB_SERVICE_LEN];
    size_t service_ip_count;
    char keepalive_listen[IPV4_STR_LEN];
    char keepalive_interface[IPV4_STR_LEN];
} lb_config;

static struct watchdog_socket {
    int sockfd;
    struct sockaddr_in local_addr;
    struct ip_mreq mreq;
} watchdog_socket;

typedef struct __lb_services {
    service_entry_t *bpf_service;
    __u32 key;
    __u64 last_contact;
} lb_services_t;

static service_entry_t bpf_services[LB_SERVICE_LEN];
static lb_services_t services[LB_SERVICE_LEN];

static __u32 ip_to_int(const char *ip_str)
{
    struct in_addr ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return 0;
    }

    return ntohl(ip.s_addr);
}

static __u64 current_time_millis()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

static __s32 load_config(const char *filename, struct lb_config *config)
{
    config_t cfg;
    config_init(&cfg);

    if (!config_read_file(&cfg, filename)) {
        fprintf(stderr, "Error reading config: %s (at %s:%d)\n", 
            config_error_text(&cfg),
            config_error_file(&cfg),
            config_error_line(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    const char *tmp;

    if (config_lookup_string(&cfg, "virtual_ip", &tmp)) {
        strncpy(config->virtual_ip, tmp, IPV4_STR_LEN);
        config->virtual_ip_int = ip_to_int(tmp);
        if (config->virtual_ip_int == 0) {
            goto err;
        }
    } else {
        goto err;
    }

    if (config_lookup_string(&cfg, "keepalive_listen", &tmp)) {
        strncpy(config->keepalive_listen, tmp, IPV4_STR_LEN);
        if (ip_to_int(tmp) == 0)
            goto err;
    } else {
        goto err;
    }

    if (config_lookup_string(&cfg, "keepalive_interface", &tmp)) {
        strncpy(config->keepalive_interface, tmp, IPV4_STR_LEN);
        if (ip_to_int(tmp) == 0)
            goto err;
    } else {
        goto err;
    }

    config_setting_t *ip_list = config_lookup(&cfg, "service_ips");
    if (ip_list == NULL || !config_setting_is_array(ip_list))
        goto err;
    
    config->service_ip_count = config_setting_length(ip_list);
    if (config->service_ip_count == 0 || config->service_ip_count > LB_SERVICE_LEN)
        goto err;

    for (__u32 i = 0; i < config->service_ip_count; i++) {
        tmp = config_setting_get_string_elem(ip_list, i);
        strncpy(config->service_ips[i], tmp, IPV4_STR_LEN);
        config->service_ips_int[i] = ip_to_int(tmp);
        if (config->service_ips_int[i] == 0)
            goto err;
    }

    config_destroy(&cfg);
    return 0;

err:
    fprintf(stderr, "Unable to parse config!\n");
    config_destroy(&cfg);
    return -1;
}

static void *watchdog_thread_fn(void *arg)
{
    struct watchdog_socket *watchdog_socket = (struct watchdog_socket *) arg;

    fprintf(stderr, "Watchdog thread is listening.\n");

    while (1) {
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        __u32 data;
        ssize_t len = recvfrom(watchdog_socket->sockfd, &data, sizeof(data), 0, 
                               (struct sockaddr *) &sender_addr, &sender_addr_len);

        if (len < 0 || len != sizeof(data))
            continue;
        char sender_ip[IPV4_STR_LEN];
        inet_ntop(AF_INET, &(sender_addr.sin_addr), sender_ip, IPV4_STR_LEN);

        fprintf(stderr, "Got keepalive from %s for %u.\n", sender_ip, data);

        for (__u32 i = 0; i < lb_config.service_ip_count; i++) {
            if (lb_config.service_ips_int[i] == data) {
                services[i].last_contact = current_time_millis();
                break;
            }
        }
    }

    return NULL;
}

// TODO: Only do ARPs when required
// Quick & dirty: Let the kernel do ARPs for our service IPs
static void *arping_thread_fn(void *arg)
{
    (void) arg;

    char cmd[256];

    while (1) {
        for (__u32 i = 0; i < lb_config.service_ip_count; i++) {
            snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s > /dev/null", lb_config.service_ips[i]);
            system(cmd);
        }

        sleep(ARPING_INTERVAL);
    }

    return NULL;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct loadbalancer_bpf *skel;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path/to/config.cfg>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (load_config(argv[1], &lb_config) != 0)
        exit(EXIT_FAILURE);

    fprintf(stderr, "Virtual Service IP: %s (%u)\n", lb_config.virtual_ip, lb_config.virtual_ip_int);
    fprintf(stderr, "Service IPs:\n");
    for (__u32 i = 0; i < lb_config.service_ip_count; i++) {
        fprintf(stderr, " - %s (%u)\n", lb_config.service_ips[i], lb_config.service_ips_int[i]);
    }

    fprintf(stderr, "\nConfig OK, starting ...\n\n");

    watchdog_socket.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (watchdog_socket.sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    setsockopt(watchdog_socket.sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse, sizeof(reuse));

    memset(&watchdog_socket.local_addr, 0, sizeof(watchdog_socket.local_addr));
    watchdog_socket.local_addr.sin_family = AF_INET;
    watchdog_socket.local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    watchdog_socket.local_addr.sin_port = htons(WATCHDOG_LISTEN_PORT);

    int rc = bind(watchdog_socket.sockfd, (struct sockaddr *) &watchdog_socket.local_addr, 
                 sizeof(watchdog_socket.local_addr));
    if (rc < 0) {
        perror("bind");
        close(watchdog_socket.sockfd);
        exit(EXIT_FAILURE);
    }

    watchdog_socket.mreq.imr_multiaddr.s_addr = inet_addr(lb_config.keepalive_listen);
    watchdog_socket.mreq.imr_interface.s_addr = inet_addr(lb_config.keepalive_interface);

    rc = setsockopt(watchdog_socket.sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                    (char *) &watchdog_socket.mreq, 
                    sizeof(watchdog_socket.mreq));
    if (rc < 0) {
        perror("Multicast group add membership failed");
        close(watchdog_socket.sockfd);
        exit(EXIT_FAILURE);
    }

    pthread_t watchdog;
    pthread_t arping;

    pthread_create(&watchdog, NULL, watchdog_thread_fn, &watchdog_socket);
    pthread_create(&arping, NULL, arping_thread_fn, NULL);

    libbpf_set_print(libbpf_print_fn);

    skel = loadbalancer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        exit(EXIT_FAILURE);
    }
    skel->bss->vip = lb_config.virtual_ip_int;
    skel->data->ttl_dec_en = DECREMENT_TTL;

    err = loadbalancer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
    
    for (__u32 i = 0; i < LB_SERVICE_LEN; i++) {
        if (i < lb_config.service_ip_count) {
            bpf_services[i].addr = lb_config.service_ips_int[i];
            bpf_services[i].active = 1;

            services[i].bpf_service = &bpf_services[i];
            services[i].last_contact = current_time_millis();
            services[i].key = i;
        } else {
            bpf_services[i].addr = 0;
            bpf_services[i].active = 0;

            services[i].bpf_service = NULL;
        }
    }

    err = loadbalancer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    for (__u32 i = 0; i < LB_SERVICE_LEN; i++) {
        bpf_map__update_elem(skel->maps.service_map, &i, sizeof(i), 
                             &bpf_services[i], sizeof(service_entry_t), 
                             BPF_ANY);
    }

    for (__u32 i = 0; i < LB_LOOKUP_LEN; i++) {
        __u32 service_id = i % lb_config.service_ip_count;
        bpf_map__update_elem(skel->maps.lookup_map, &i, sizeof(i), 
                             &service_id, sizeof(service_id), 
                             BPF_ANY);
    }

    bpf_program__attach_xdp(skel->progs.xdp_lb, 3);

    fprintf(stderr, "Successfully started!\n");

    for (;;) {
        sleep(KEEPALIVE_CHECK_INTERVAL_SECS);

        __u64 time = current_time_millis();

        for (__u32 i = 0; i < lb_config.service_ip_count; i++) {
            lb_services_t *service = &services[i];
            if (service->bpf_service == NULL)
                continue;
            
            if (service->bpf_service->active) {
                if (service->last_contact + KEEPALIVE_DOWN_MILLIS < time) {
                    service->bpf_service->active = 0;
                    bpf_map__update_elem(skel->maps.service_map, 
                                         &service->key, sizeof(__u32), 
                                         service->bpf_service, sizeof(service_entry_t), 
                                         BPF_EXIST);
                    fprintf(stderr, "Disabling service %u: Down.\n", i);
                }
            } else {
                if (service->last_contact + KEEPALIVE_DOWN_MILLIS >= time) {
                    service->bpf_service->active = 1;
                    bpf_map__update_elem(skel->maps.service_map, 
                                         &service->key, sizeof(__u32), 
                                         service->bpf_service, sizeof(service_entry_t), 
                                         BPF_EXIST);
                    fprintf(stderr, "Enabling service %u: Up.\n", i);
                }
            }
        }
    }

cleanup:
    loadbalancer_bpf__destroy(skel);

    pthread_kill(arping, 15);
    fprintf(stderr, "Waiting for arping thread to terminate\n");
    pthread_join(arping, NULL);

    pthread_kill(watchdog, 15);
    fprintf(stderr, "Waiting for watchdog thread to terminate\n");
    pthread_join(watchdog, NULL);

    setsockopt(watchdog_socket.sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, 
               (char *) &watchdog_socket.mreq, 
               sizeof(watchdog_socket.mreq));
    close(watchdog_socket.sockfd);
    return -err;
}

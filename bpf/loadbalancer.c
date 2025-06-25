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
#include <poll.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include "loadbalancer.skel.h"
#include "common.h"

#define KEEPALIVE_DOWN_MILLIS 10 * 1000
#define KEEPALIVE_CHECK_INTERVAL_SECS 5
#define ARPING_INTERVAL 30
#define WATCHDOG_LISTEN_PORT 4242
#define DECREMENT_TTL 1

#define NUM_FRAMES 8192
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

static struct lb_config {
    char virtual_ip[IPV4_STR_LEN];
    __u32 virtual_ip_int;
    char interface_name[INTNAME_MAX_LEN];
    __u32 interface_id;
    char service_ips[LB_SERVICE_LEN][IPV4_STR_LEN];
    bool enable_af_xdp;
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

static struct xsk_umem_info {
    void *buf;
    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
} umem;

static struct xsk_socket_info {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;

    __u64 umem_frame_addr[NUM_FRAMES];
    __u32 umem_frame_free;

    __u32 outstanding_tx;
} xsk_socket;

static service_entry_t bpf_services[LB_SERVICE_LEN];
static lb_services_t services[LB_SERVICE_LEN];
static struct loadbalancer_bpf *skel;
static struct xdp_program *prog;
static pthread_t arping;
static pthread_t xdp_thread;

static volatile sig_atomic_t exiting = 0;

static void signal_hanlder(int signal)
{
    exiting = 1;
}

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
    int bool_tmp;

    if (config_lookup_string(&cfg, "virtual_ip", &tmp)) {
        strncpy(config->virtual_ip, tmp, IPV4_STR_LEN);
        config->virtual_ip_int = ip_to_int(tmp);
        if (config->virtual_ip_int == 0) {
            goto err;
        }
    } else {
        goto err;
    }

    if (config_lookup_string(&cfg, "interface", &tmp)) {
        strncpy(config->interface_name, tmp, INTNAME_MAX_LEN);
        config->interface_id = if_nametoindex(config->interface_name);
        if (config->interface_id == 0) {
            goto err;
        }
    } else {
        goto err;
    }

    if (config_lookup_bool(&cfg, "enable_af_xdp", &bool_tmp)) {
        config->enable_af_xdp = (bool_tmp != 0);
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

    if (config_lookup_string(&cfg, "keepalive_address", &tmp)) {
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
    signal(SIGUSR1, signal_hanlder);
    struct watchdog_socket *watchdog_socket = (struct watchdog_socket *) arg;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000;
    setsockopt(watchdog_socket->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    fprintf(stderr, "Watchdog thread is listening.\n");

    while (!exiting) {
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        __u32 data;
        ssize_t len = recvfrom(watchdog_socket->sockfd, &data, sizeof(data), 0, 
                               (struct sockaddr *) &sender_addr, &sender_addr_len);

        if ((len < 0 && errno == EAGAIN) || len != sizeof(data))
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

static void *arping_thread_fn(void *arg)
{
    (void) arg;
    char cmd[256];

    signal(SIGUSR1, signal_hanlder);

    while (!exiting) {
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

static void *xdp_handle_pkts(void *args) {
    struct pollfd pollfds[2];
    int ret;
    int npoll = 1;
    __u32 rcvd;
    __u32 stock_frames;
    __u32 idx_rx = 0;
    __u32 idx_fq = 0;
    __u64 ring_addr;
    __u32 ring_len;

    memset(pollfds, 0, sizeof(pollfds));
    pollfds[0].fd = xsk_socket__fd(xsk_socket.xsk);
    pollfds[0].events = POLLIN;

    while (!exiting) {
        ret = poll(pollfds, npoll, -1);
        if (ret <= 0 || ret < 1)
            continue;

        rcvd = xsk_ring_cons__peek(&xsk_socket.rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd)
            continue;
        
        stock_frames = xsk_prod_nb_free(&umem.fq, xsk_socket.umem_frame_free);

        if (stock_frames > 0) {

            ret = xsk_ring_prod__reserve(&umem.fq, stock_frames, &idx_fq);

            for (__u32 i = 0; i < stock_frames; i++) {
                __u64 *addr = xsk_ring_prod__fill_addr(&umem.fq, idx_fq++);
                if (xsk_socket.umem_frame_free == 0) {
                    *addr = INVALID_UMEM_FRAME;
                } else {
                    xsk_socket.umem_frame_free--;
                    xsk_socket.umem_frame_addr[xsk_socket.umem_frame_free] = INVALID_UMEM_FRAME;
                    *addr = xsk_socket.umem_frame_addr[xsk_socket.umem_frame_free];
                }
            }

            xsk_ring_prod__submit(&umem.fq, stock_frames);
        }

        for (__u32 i = 0; i < rcvd; i++) {
            ring_addr = xsk_ring_cons__rx_desc(&xsk_socket.rx, idx_rx)->addr;
            ring_len = xsk_ring_cons__rx_desc(&xsk_socket.rx, idx_rx)->len;

            (void) ring_addr;
            (void) ring_len;

            // TODO: React to forwarded packet & send back out after ARP
        }

        xsk_ring_cons__release(&xsk_socket.rx, rcvd);
    }

    return NULL;
}

static int setup_arping_mode()
{
    int err = loadbalancer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return -1;
    }

    bpf_program__attach_xdp(skel->progs.xdp_lb, lb_config.interface_id);

    pthread_create(&arping, NULL, arping_thread_fn, NULL);

    return 0;
}

static int setup_af_xdp_mode()
{
    int err;
    char errmsg[1024];
    int xsk_map_fd;
    struct xsk_socket_config xsk_config;
    __u32 prod_idx;

    prog = xdp_program__from_bpf_obj(skel->obj, "xdp");
    err = libxdp_get_error(prog);

    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Unable to load XDP program from BPF skel: %s\n", errmsg);
        return -1;
    }

    err = xdp_program__attach(prog, lb_config.interface_id, XDP_MODE_UNSPEC, 0);

    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Unable to attach XDP program: %s\n", errmsg);
        return -1;
    }

    xsk_map_fd = bpf_map__fd(skel->maps.xsks_map);
    if (xsk_map_fd < 0) {
        fprintf(stderr, "Unable to get xsks map fd: %s\n", strerror(xsk_map_fd));
        err = -1;
        goto xdp_setup_failed;
    }

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        err = -1;
        goto xdp_setup_failed;
    }

    err = posix_memalign(umem.buf, getpagesize(), (__u64) NUM_FRAMES * FRAME_SIZE);
    if (err) {
        perror("posix_memalign");
        err = -1;
        goto xdp_setup_failed;
    }

    err = xsk_umem__create(&umem.umem, umem.buf, (__u64) NUM_FRAMES * FRAME_SIZE, 
                           &umem.fq, &umem.cq, NULL);
    if (err) {
        perror("xsk_umem__create");
        err = -1;
        goto xdp_setup_failed;
    }

    xsk_config.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_config.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_config.bind_flags = XDP_COPY;
    xsk_config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_socket.umem = &umem;

    err = xsk_socket__create(&xsk_socket.xsk, lb_config.interface_name,
                             0, umem.umem, &xsk_socket.rx, &xsk_socket.tx,
                             &xsk_config);
    if (err) {
        perror("xsk_socket__create");
        err = -1;
        goto xdp_setup_failed_umem;
    }

    err = xsk_socket__update_xskmap(xsk_socket.xsk, xsk_map_fd);
    if (err) {
        perror("xsk_socket__update_xskmap");
        err = -1;
        goto xdp_setup_failed_socket;
    }

    for (__u32 i = 0; i < NUM_FRAMES; i++) {
        xsk_socket.umem_frame_addr[i] = i * FRAME_SIZE;
    }
    xsk_socket.umem_frame_free = NUM_FRAMES;

    err = xsk_ring_prod__reserve(&umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, 
                                 &prod_idx);
    if (err != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        perror("xsk_ring_prod__reserve");
        err = -1;
        goto xdp_setup_failed_socket;
    }

    for (__u32 i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
        __u64 *addr = xsk_ring_prod__fill_addr(&umem.fq, prod_idx++);
        
        if (xsk_socket.umem_frame_free == 0) {
            *addr = INVALID_UMEM_FRAME;
        } else {
            xsk_socket.umem_frame_free--;
            xsk_socket.umem_frame_addr[xsk_socket.umem_frame_free] = INVALID_UMEM_FRAME;
            *addr = xsk_socket.umem_frame_addr[xsk_socket.umem_frame_free];
        }
    }

    xsk_ring_prod__submit(&umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    pthread_create(&xdp_thread, NULL, xdp_handle_pkts, NULL);

    return 0;

xdp_setup_failed_socket:
    xsk_socket__delete(xsk_socket.xsk);
xdp_setup_failed_umem:
    xsk_umem__delete(umem.umem);
xdp_setup_failed:
    xdp_program__detach(prog, lb_config.interface_id, XDP_MODE_UNSPEC, 0);
    return err;
}

static void destory_arping_mode()
{
    loadbalancer_bpf__destroy(skel);

    pthread_kill(arping, SIGUSR1);
    fprintf(stderr, "Waiting for arping thread to terminate\n");
    pthread_join(arping, NULL);
}

static void destory_af_xdp_mode()
{
    int err = libxdp_get_error(prog);
    if (!err) {
        xdp_program__detach(prog, lb_config.interface_id, XDP_MODE_UNSPEC, 0);
    }

    xsk_socket__delete(xsk_socket.xsk);
    xsk_umem__delete(umem.umem);
}

int main(int argc, char **argv)
{
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path/to/config.cfg>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (load_config(argv[1], &lb_config) != 0)
        exit(EXIT_FAILURE);

    fprintf(stderr, "Virtual Service IP: %s (%u @ %u)\n", 
        lb_config.virtual_ip, 
        lb_config.virtual_ip_int, 
        lb_config.interface_id);
    fprintf(stderr, "Service IPs:\n");
    for (__u32 i = 0; i < lb_config.service_ip_count; i++) {
        fprintf(stderr, " - %s (%u)\n", 
            lb_config.service_ips[i], 
            lb_config.service_ips_int[i]);
    }

    fprintf(stderr, "\nConfig OK, starting ...\n\n");

    signal(SIGINT, signal_hanlder);
    signal(SIGTERM, signal_hanlder);

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
    pthread_create(&watchdog, NULL, watchdog_thread_fn, &watchdog_socket);

    libbpf_set_print(libbpf_print_fn);

    skel = loadbalancer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        exit(EXIT_FAILURE);
    }
    skel->bss->vip = lb_config.virtual_ip_int;
    skel->data->ttl_dec_en = DECREMENT_TTL;
    skel->bss->af_xdp_en = lb_config.enable_af_xdp;

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

    if (lb_config.enable_af_xdp) {
        if (setup_af_xdp_mode() != 0)
            goto cleanup;
    } else {
        if (setup_arping_mode() != 0)
            goto cleanup;
    }

    fprintf(stderr, "Successfully started!\n");

    while (!exiting) {
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

    if (lb_config.enable_af_xdp)
        destory_af_xdp_mode();
    else
        destory_arping_mode();

cleanup:
    pthread_kill(watchdog, SIGUSR1);
    fprintf(stderr, "Waiting for watchdog thread to terminate\n");
    pthread_join(watchdog, NULL);

    setsockopt(watchdog_socket.sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, 
               (char *) &watchdog_socket.mreq, 
               sizeof(watchdog_socket.mreq));
    close(watchdog_socket.sockfd);
    return -err;
}

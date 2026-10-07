#ifndef ZEPTUN_H
#define ZEPTUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZEPTUN_VERSION_MAJOR 1
#define ZEPTUN_VERSION_MINOR 1
#define ZEPTUN_VERSION_PATCH 3

#define ZEPTUN_OK 0
#define ZEPTUN_ERR_INVALID_ARGUMENT -1
#define ZEPTUN_ERR_OUT_OF_MEMORY -2
#define ZEPTUN_ERR_PERMISSION_DENIED -3
#define ZEPTUN_ERR_NOT_SUPPORTED -4
#define ZEPTUN_ERR_DEVICE -5
#define ZEPTUN_ERR_IO -6
#define ZEPTUN_ERR_ALREADY_RUNNING -7
#define ZEPTUN_ERR_NOT_RUNNING -8
#define ZEPTUN_ERR_WOULD_BLOCK -9
#define ZEPTUN_ERR_NOT_FOUND -10
#define ZEPTUN_ERR_LIMIT_EXCEEDED -11
#define ZEPTUN_ERR_ADDRESS_IN_USE -12
#define ZEPTUN_ERR_SYSTEM_OUTDATED -13
#define ZEPTUN_ERR_CLOSED -14
#define ZEPTUN_ERR_TIMEOUT -15
#define ZEPTUN_ERR_CONFIG -16
#define ZEPTUN_ERR_ROUTE -17
#define ZEPTUN_ERR_BUSY -18
#define ZEPTUN_ERR_UNKNOWN -99

#define ZEPTUN_PRESET_DESKTOP 0
#define ZEPTUN_PRESET_MOBILE 1
#define ZEPTUN_PRESET_SERVER 2

#define ZEPTUN_DEVICE_TUN 0
#define ZEPTUN_DEVICE_FD 1
#define ZEPTUN_DEVICE_EXTERNAL 2

#define ZEPTUN_STACK_SYSTEM 0
#define ZEPTUN_STACK_USERSPACE 1
#define ZEPTUN_STACK_HYBRID 2

#define ZEPTUN_HANDLER_DIRECT 0
#define ZEPTUN_HANDLER_SOCKS5 1
#define ZEPTUN_HANDLER_PASSTHROUGH 2

#define ZEPTUN_SOCKS5_PIPELINE_AUTO 0
#define ZEPTUN_SOCKS5_PIPELINE_ON 1
#define ZEPTUN_SOCKS5_PIPELINE_OFF 2

#define ZEPTUN_IO_AUTO 0
#define ZEPTUN_IO_URING 1
#define ZEPTUN_IO_EPOLL 2
#define ZEPTUN_IO_KQUEUE 3
#define ZEPTUN_IO_IOCP 4

#define ZEPTUN_LOG_ERROR 0
#define ZEPTUN_LOG_WARN 1
#define ZEPTUN_LOG_INFO 2
#define ZEPTUN_LOG_DEBUG 3
#define ZEPTUN_LOG_TRACE 4

typedef struct Zeptun Zeptun;

typedef struct ZeptunPacket {
    const uint8_t *data;
    size_t len;
} ZeptunPacket;

typedef void (*zeptun_packets_cb)(void *ctx, const ZeptunPacket *packets, size_t count);
typedef bool (*zeptun_protect_cb)(void *ctx, int fd);

typedef struct {
    uint8_t protocol;
    uint8_t family;
    uint8_t source[16];
    uint8_t destination[16];
    uint16_t source_port;
    uint16_t destination_port;
} ZeptunFlow;

#define ZEPTUN_FLOW_PROXY 0u
#define ZEPTUN_FLOW_DIRECT 1u
#define ZEPTUN_FLOW_DROP 2u
#define ZEPTUN_FLOW_REJECT 3u

typedef uint32_t (*zeptun_flow_cb)(void *ctx, const ZeptunFlow *flow);
typedef void (*zeptun_log_cb)(void *ctx, int level, const char *message, size_t len);

typedef struct ZeptunConfig {
    uint32_t struct_size;
    uint32_t preset;
    uint32_t device_kind;
    int32_t tun_fd;
    char tun_name[16];
    uint32_t mtu;
    uint16_t queues;
    uint8_t offload;
    uint8_t configure;
    char address4[64];
    char address6[64];
    uint32_t stack_mode;
    uint32_t handler_kind;
    char socks5_server[64];
    char socks5_username[256];
    char socks5_password[256];
    uint8_t socks5_udp;
    uint8_t socks5_pipeline;
    uint8_t auto_route;
    uint8_t passthrough_gso;
    uint32_t fwmark;
    uint32_t route_table;
    uint32_t rule_priority;
    uint32_t io_backend;
    uint32_t max_tcp_sessions;
    uint32_t max_udp_sessions;
    uint32_t tcp_rx_window;
    uint32_t tcp_tx_buffer;
    uint32_t udp_idle_timeout_ms;
    uint32_t tcp_idle_timeout_ms;
    uint32_t pad0;
    uint64_t memory_budget_bytes;
    uint32_t log_level;
    uint32_t workers;
    uint32_t reserved[8];
} ZeptunConfig;

typedef struct ZeptunStats {
    uint32_t version;
    uint32_t workers;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t parse_errors;
    uint64_t pool_exhausted;
    uint64_t gso_rx_packets;
    uint64_t gso_tx_packets;
    uint64_t gso_segments;
    uint64_t gro_merged;
    uint64_t tcp_active;
    uint64_t tcp_opened;
    uint64_t tcp_closed;
    uint64_t tcp_reset;
    uint64_t tcp_retransmits;
    uint64_t tcp_connect_failed;
    uint64_t tcp_evicted;
    uint64_t udp_active;
    uint64_t udp_opened;
    uint64_t udp_closed;
    uint64_t udp_evicted;
    uint64_t udp_dropped;
    uint64_t icmp_echo;
    uint64_t icmp_time_exceeded;
    uint64_t nat_active;
    uint64_t handoffs;
    uint64_t upstream_rx_bytes;
    uint64_t upstream_tx_bytes;
    uint64_t fragments_reassembled;
    uint64_t timeouts;
    uint64_t socks5_pool_hits;
    uint64_t socks5_pool_retries;
    uint64_t dns_fake_answers;
    uint64_t dns_hijacked;
    uint64_t tcp_migrated;
    uint64_t udp_migrated;
} ZeptunStats;

typedef struct ZeptunMemory {
    uint32_t version;
    uint32_t workers;
    uint64_t buffers;
    uint64_t in_use;
    uint64_t resident_bytes;
    uint64_t released_bytes;
    uint64_t starved_flows;
    uint64_t exhausted;
} ZeptunMemory;

uint32_t zeptun_version(void);
const char *zeptun_version_string(void);
const char *zeptun_strerror(int code);

int zeptun_config_init(ZeptunConfig *config, uint32_t preset);
int zeptun_create(const ZeptunConfig *config, Zeptun **out);
int zeptun_create_from_json(const char *json, size_t len, Zeptun **out);
int zeptun_create_from_toml(const char *toml, size_t len, Zeptun **out);
void zeptun_destroy(Zeptun *tun);

int zeptun_set_log_callback(zeptun_log_cb callback, void *ctx, int level);
int zeptun_set_read_callback(Zeptun *tun, zeptun_packets_cb callback, void *ctx);
int zeptun_set_passthrough_callback(Zeptun *tun, zeptun_packets_cb callback, void *ctx);
int zeptun_set_protect_callback(Zeptun *tun, zeptun_protect_cb callback, void *ctx);
int zeptun_set_flow_callback(Zeptun *tun, zeptun_flow_cb callback, void *ctx);
int zeptun_set_device_fd(Zeptun *tun, int fd);
int zeptun_set_adapter_guid(Zeptun *tun, const char *guid);

int zeptun_start(Zeptun *tun);
int zeptun_run(Zeptun *tun);
int zeptun_stop(Zeptun *tun);

int zeptun_write_packet(Zeptun *tun, const uint8_t *data, size_t len);
int zeptun_write_packets(Zeptun *tun, const ZeptunPacket *packets, size_t count);
int zeptun_inject_packets(Zeptun *tun, const ZeptunPacket *packets, size_t count);

int zeptun_network_changed(Zeptun *tun, uint32_t interface_index);
int zeptun_stats(Zeptun *tun, ZeptunStats *out);
int zeptun_memory(Zeptun *tun, ZeptunMemory *out);
int zeptun_interface_name(Zeptun *tun, char *buffer, size_t len);

#ifdef __cplusplus
}
#endif

#endif

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/*
 * Simple NexmonCSI pcap stream generator for testing test-json.py.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o pcap-gen main.c
 *
 * Example:
 *   ./pcap-gen --count 100000 --rate 0 | python3 test-json.py --count 100000
 *
 * The generated stream is classic little-endian pcap with linktype 1
 * (Ethernet). Each pcap record contains:
 *   Ethernet(type=0x0800) + IPv4 + UDP(dst=5500) + NexmonCSI payload.
 */

#define PCAP_LINKTYPE_ETHERNET 1
#define UDP_PORT 5500
#define ETH_LEN 14
#define IPV4_LEN 20
#define UDP_LEN 8
#define CSI_TONES_20MHZ 64
#define CSI_BYTES (CSI_TONES_20MHZ * 4)
#define NEXMON_HEADER_LEN 18
#define NEXMON_PAYLOAD_LEN (NEXMON_HEADER_LEN + CSI_BYTES)
#define FRAME_LEN (ETH_LEN + IPV4_LEN + UDP_LEN + NEXMON_PAYLOAD_LEN)

struct config {
    uint64_t count;
    unsigned expected_cores;
    unsigned rate_pps;
    unsigned drop_core;
    int drop_core_enabled;
    unsigned drop_every;
    int realtime_ts;
    const char *output_path;
};

static FILE *pcap_output;

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--count N] [--cores N] [--rate PPS] "
            "[--drop-core C --drop-every N] [--synthetic-ts] "
            "[--output FILE]\n"
            "\n"
            "defaults: --count 1000 --cores 4 --rate 0\n"
            "rate 0 writes as fast as possible\n",
            prog);
}

static uint16_t ip_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1) {
        sum += (uint16_t)data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void write_pcap_global_header(void)
{
    uint8_t h[24];
    memset(h, 0, sizeof(h));
    put_le32(h + 0, 0xa1b2c3d4u);
    put_le16(h + 4, 2);
    put_le16(h + 6, 4);
    put_le32(h + 16, 65535);
    put_le32(h + 20, PCAP_LINKTYPE_ETHERNET);
    if (fwrite(h, 1, sizeof(h), pcap_output) != sizeof(h)) {
        perror("write pcap global header");
        exit(1);
    }
}

static void write_pcap_packet_header(uint32_t ts_sec, uint32_t ts_usec)
{
    uint8_t h[16];
    put_le32(h + 0, ts_sec);
    put_le32(h + 4, ts_usec);
    put_le32(h + 8, FRAME_LEN);
    put_le32(h + 12, FRAME_LEN);
    if (fwrite(h, 1, sizeof(h), pcap_output) != sizeof(h)) {
        perror("write pcap packet header");
        exit(1);
    }
}

static void fill_frame(uint8_t frame[FRAME_LEN], uint16_t seq, uint8_t core)
{
    uint8_t *eth = frame;
    uint8_t *ip = frame + ETH_LEN;
    uint8_t *udp = ip + IPV4_LEN;
    uint8_t *nex = udp + UDP_LEN;
    uint16_t ip_total_len = IPV4_LEN + UDP_LEN + NEXMON_PAYLOAD_LEN;
    uint16_t udp_total_len = UDP_LEN + NEXMON_PAYLOAD_LEN;
    uint16_t sequence_control = (uint16_t)(seq << 4);
    uint16_t css = (uint16_t)(core << 8);
    uint16_t chanspec = 6;
    uint16_t chip_version = 0x4366;

    memset(frame, 0, FRAME_LEN);

    /* Ethernet: broadcast destination, fixed source, IPv4 ethertype. */
    memset(eth + 0, 0xff, 6);
    eth[6] = 0x00;
    eth[7] = 0x11;
    eth[8] = 0x22;
    eth[9] = 0x33;
    eth[10] = 0x44;
    eth[11] = 0x55;
    eth[12] = 0x08;
    eth[13] = 0x00;

    /* IPv4: 10.10.10.10 -> 255.255.255.255, protocol UDP. */
    ip[0] = 0x45;
    ip[1] = 0x00;
    *(uint16_t *)(void *)(ip + 2) = htons(ip_total_len);
    *(uint16_t *)(void *)(ip + 4) = htons(seq);
    *(uint16_t *)(void *)(ip + 6) = htons(0);
    ip[8] = 64;
    ip[9] = 17;
    ip[12] = 10;
    ip[13] = 10;
    ip[14] = 10;
    ip[15] = 10;
    ip[16] = 255;
    ip[17] = 255;
    ip[18] = 255;
    ip[19] = 255;
    *(uint16_t *)(void *)(ip + 10) = htons(ip_checksum(ip, IPV4_LEN));

    *(uint16_t *)(void *)(udp + 0) = htons(UDP_PORT);
    *(uint16_t *)(void *)(udp + 2) = htons(UDP_PORT);
    *(uint16_t *)(void *)(udp + 4) = htons(udp_total_len);
    *(uint16_t *)(void *)(udp + 6) = htons(0);

    /* NexmonCSI compact payload expected by receiving_csi/nexmon.py. */
    nex[0] = 0x11;
    nex[1] = 0x11;
    nex[2] = (uint8_t)-42;      /* RSSI */
    nex[3] = 0x88;              /* frame control placeholder */
    nex[4] = 0x02;
    nex[5] = 0x1a;
    nex[6] = 0x2b;
    nex[7] = 0x3c;
    nex[8] = 0x4d;
    nex[9] = 0x5e;
    put_le16(nex + 10, sequence_control);
    put_le16(nex + 12, css);
    put_le16(nex + 14, chanspec);
    put_le16(nex + 16, chip_version);

    for (unsigned i = 0; i < CSI_TONES_20MHZ; i++) {
        uint32_t word = ((uint32_t)core << 24) | ((uint32_t)seq << 8) | i;
        put_le32(nex + NEXMON_HEADER_LEN + i * 4, word);
    }
}

static void packet_timestamp(const struct config *cfg, uint64_t packet_index,
                             uint32_t *sec, uint32_t *usec)
{
    if (cfg->realtime_ts) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        *sec = (uint32_t)tv.tv_sec;
        *usec = (uint32_t)tv.tv_usec;
        return;
    }

    *sec = 1;
    *usec = (uint32_t)packet_index;
}

static unsigned parse_unsigned(const char *arg, const char *name)
{
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(arg, &end, 10);
    if (errno || !end || *end != '\0' || value > 0xfffffffful) {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        exit(2);
    }
    return (unsigned)value;
}

static uint64_t parse_u64(const char *arg, const char *name)
{
    char *end = NULL;
    unsigned long long value;
    errno = 0;
    value = strtoull(arg, &end, 10);
    if (errno || !end || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        exit(2);
    }
    return (uint64_t)value;
}

static struct config parse_args(int argc, char **argv)
{
    struct config cfg;
    cfg.count = 1000;
    cfg.expected_cores = 4;
    cfg.rate_pps = 0;
    cfg.drop_core = 0;
    cfg.drop_core_enabled = 0;
    cfg.drop_every = 0;
    cfg.realtime_ts = 1;
    cfg.output_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--count") && i + 1 < argc) {
            cfg.count = parse_u64(argv[++i], "count");
        } else if (!strcmp(argv[i], "--cores") && i + 1 < argc) {
            cfg.expected_cores = parse_unsigned(argv[++i], "cores");
        } else if (!strcmp(argv[i], "--rate") && i + 1 < argc) {
            cfg.rate_pps = parse_unsigned(argv[++i], "rate");
        } else if (!strcmp(argv[i], "--drop-core") && i + 1 < argc) {
            cfg.drop_core = parse_unsigned(argv[++i], "drop-core");
            cfg.drop_core_enabled = 1;
        } else if (!strcmp(argv[i], "--drop-every") && i + 1 < argc) {
            cfg.drop_every = parse_unsigned(argv[++i], "drop-every");
        } else if (!strcmp(argv[i], "--synthetic-ts")) {
            cfg.realtime_ts = 0;
        } else if (!strcmp(argv[i], "--output") && i + 1 < argc) {
            cfg.output_path = argv[++i];
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            exit(0);
        } else {
            usage(argv[0]);
            exit(2);
        }
    }

    if (cfg.expected_cores < 1 || cfg.expected_cores > 4) {
        fprintf(stderr, "--cores must be between 1 and 4\n");
        exit(2);
    }
    if (cfg.drop_core_enabled && cfg.drop_core >= cfg.expected_cores) {
        fprintf(stderr, "--drop-core must be less than --cores\n");
        exit(2);
    }
    return cfg;
}

int main(int argc, char **argv)
{
    struct config cfg = parse_args(argc, argv);
    uint8_t frame[FRAME_LEN];
    uint64_t packet_index = 0;
    uint64_t written = 0;
    useconds_t sleep_us = cfg.rate_pps ? (useconds_t)(1000000u / cfg.rate_pps) : 0;

    pcap_output = stdout;
    if (cfg.output_path) {
        pcap_output = fopen(cfg.output_path, "wb");
        if (!pcap_output) {
            perror("open output");
            return 1;
        }
    }

    write_pcap_global_header();

    for (uint64_t group = 0; group < cfg.count; group++) {
        uint16_t seq = (uint16_t)(group & 0x0fffu);
        for (unsigned core = 0; core < cfg.expected_cores; core++) {
            uint32_t ts_sec;
            uint32_t ts_usec;
            if (cfg.drop_core_enabled && cfg.drop_every &&
                core == cfg.drop_core && group % cfg.drop_every == 0) {
                continue;
            }

            packet_timestamp(&cfg, packet_index, &ts_sec, &ts_usec);
            fill_frame(frame, seq, (uint8_t)core);
            write_pcap_packet_header(ts_sec, ts_usec);
            if (fwrite(frame, 1, sizeof(frame), pcap_output) != sizeof(frame)) {
                perror("write frame");
                return 1;
            }
            packet_index++;
            written++;

            if (sleep_us) {
                usleep(sleep_us);
            }
        }
    }

    fflush(pcap_output);
    fprintf(stderr, "pcap-gen wrote %llu packets in %llu groups\n",
            (unsigned long long)written,
            (unsigned long long)cfg.count);
    if (ferror(pcap_output)) {
        return 1;
    }
    if (cfg.output_path && fclose(pcap_output) != 0) {
        perror("close output");
        return 1;
    }
    return 0;
}

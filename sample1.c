/*
 * security_monitor.c
 * Cloud-Native Network Security Monitoring Microservice
 * Simulates: packet inspection, intrusion detection,
 * IP blocking, alert management, traffic analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_PACKETS     500
#define MAX_BLOCKED_IPS 100
#define MAX_ALERTS      200
#define MAX_RULES       50
#define MONITOR_VERSION "3.0.1"

/* ─── Data Structures ─── */

typedef struct {
    char   src_ip[16];
    char   dst_ip[16];
    int    src_port;
    int    dst_port;
    char   protocol[8];   /* TCP, UDP, ICMP */
    int    payload_size;
    char   payload[256];
    time_t timestamp;
    int    is_flagged;
} Packet;

typedef struct {
    char   ip[16];
    char   reason[128];
    time_t blocked_at;
    int    hit_count;
    int    is_permanent;
} BlockedIP;

typedef struct {
    int    alert_id;
    char   severity[16];  /* LOW, MEDIUM, HIGH, CRITICAL */
    char   message[256];
    char   source_ip[16];
    time_t created_at;
    int    is_resolved;
} Alert;

typedef struct {
    int    rule_id;
    char   name[64];
    char   pattern[128];
    char   action[16];    /* BLOCK, ALERT, LOG */
    int    is_active;
    int    match_count;
} DetectionRule;

typedef struct {
    long   total_packets;
    long   flagged_packets;
    long   blocked_packets;
    int    active_alerts;
    float  threat_score;
} MonitorMetrics;

/* ─── Global State ─── */
static Packet        g_packets[MAX_PACKETS];
static BlockedIP     g_blocked[MAX_BLOCKED_IPS];
static Alert         g_alerts[MAX_ALERTS];
static DetectionRule g_rules[MAX_RULES];
static MonitorMetrics g_metrics = {0, 0, 0, 0, 0.0f};
static int           g_packet_count  = 0;
static int           g_blocked_count = 0;
static int           g_alert_count   = 0;
static int           g_rule_count    = 0;

/* ─── Utility Functions ─── */

int is_valid_ip(const char *ip) {
    int parts = 0;
    int val   = 0;
    int dots  = 0;
    const char *p = ip;

    while (*p) {
        if (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            if (val > 255) return 0;
            parts++;
        } else if (*p == '.') {
            if (parts == 0) return 0;
            dots++;
            val   = 0;
            parts = 0;
        } else {
            return 0;
        }
        p++;
    }
    return (dots == 3 && parts > 0);
}

int string_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    return strstr(haystack, needle) != NULL;
}

float calculate_threat_score(int flagged, int total) {
    if (total == 0) return 0.0f;
    return ((float)flagged / (float)total) * 100.0f;
}

void log_event(const char *level, const char *message) {
    time_t now = time(NULL);
    char   buf[32];
    struct tm *tm_info = localtime(&now);
    strftime(buf, 32, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("[%s] [%s] %s\n", buf, level, message);
}

/* ─── Rule Management ─── */

int add_detection_rule(const char *name, const char *pattern,
                       const char *action) {
    if (g_rule_count >= MAX_RULES) {
        log_event("ERROR", "Rule store full");
        return -1;
    }
    DetectionRule *r = &g_rules[g_rule_count];
    r->rule_id     = g_rule_count + 1;
    r->is_active   = 1;
    r->match_count = 0;
    strncpy(r->name,    name,    63);
    strncpy(r->pattern, pattern, 127);
    strncpy(r->action,  action,  15);

    char msg[128];
    snprintf(msg, 128, "Rule added: %s -> %s [%s]", name, pattern, action);
    log_event("INFO", msg);
    return g_rule_count++;
}

int check_rules(const char *payload, const char *src_ip) {
    int triggered = 0;
    for (int i = 0; i < g_rule_count; i++) {
        if (!g_rules[i].is_active) continue;
        if (string_contains(payload, g_rules[i].pattern)) {
            g_rules[i].match_count++;
            triggered++;
            char msg[256];
            snprintf(msg, 256, "Rule '%s' triggered by %s",
                     g_rules[i].name, src_ip);
            log_event("WARN", msg);
        }
    }
    return triggered;
}

/* ─── IP Blocking ─── */

int block_ip(const char *ip, const char *reason, int permanent) {
    if (!is_valid_ip(ip)) {
        log_event("ERROR", "Invalid IP address format");
        return -1;
    }
    for (int i = 0; i < g_blocked_count; i++) {
        if (strcmp(g_blocked[i].ip, ip) == 0) {
            g_blocked[i].hit_count++;
            log_event("INFO", "IP already blocked - incrementing hit count");
            return 0;
        }
    }
    if (g_blocked_count >= MAX_BLOCKED_IPS) {
        log_event("ERROR", "Blocked IP list full");
        return -2;
    }
    BlockedIP *b = &g_blocked[g_blocked_count];
    strncpy(b->ip,     ip,     15);
    strncpy(b->reason, reason, 127);
    b->blocked_at  = time(NULL);
    b->hit_count   = 1;
    b->is_permanent= permanent;

    char msg[128];
    snprintf(msg, 128, "IP blocked: %s | Reason: %s", ip, reason);
    log_event("WARN", msg);
    return g_blocked_count++;
}

int is_ip_blocked(const char *ip) {
    for (int i = 0; i < g_blocked_count; i++) {
        if (strcmp(g_blocked[i].ip, ip) == 0) {
            g_blocked[i].hit_count++;
            return 1;
        }
    }
    return 0;
}

int unblock_ip(const char *ip) {
    for (int i = 0; i < g_blocked_count; i++) {
        if (strcmp(g_blocked[i].ip, ip) == 0) {
            if (g_blocked[i].is_permanent) {
                log_event("WARN", "Cannot unblock permanent IP");
                return -1;
            }
            /* Shift array left */
            for (int j = i; j < g_blocked_count - 1; j++) {
                g_blocked[j] = g_blocked[j + 1];
            }
            g_blocked_count--;
            log_event("INFO", "IP unblocked");
            return 0;
        }
    }
    return -2;
}

/* ─── Alert Management ─── */

int create_alert(const char *severity, const char *message,
                 const char *source_ip) {
    if (g_alert_count >= MAX_ALERTS) {
        log_event("ERROR", "Alert store full");
        return -1;
    }
    Alert *a = &g_alerts[g_alert_count];
    a->alert_id   = g_alert_count + 1;
    a->created_at = time(NULL);
    a->is_resolved= 0;
    strncpy(a->severity,  severity,  15);
    strncpy(a->message,   message,   255);
    strncpy(a->source_ip, source_ip, 15);

    g_metrics.active_alerts++;
    char msg[256];
    snprintf(msg, 256, "[%s] Alert #%d: %s from %s",
             severity, a->alert_id, message, source_ip);
    log_event("ALERT", msg);
    return g_alert_count++;
}

int resolve_alert(int alert_id) {
    for (int i = 0; i < g_alert_count; i++) {
        if (g_alerts[i].alert_id == alert_id) {
            if (g_alerts[i].is_resolved) {
                log_event("WARN", "Alert already resolved");
                return -1;
            }
            g_alerts[i].is_resolved = 1;
            g_metrics.active_alerts--;
            log_event("INFO", "Alert resolved");
            return 0;
        }
    }
    return -2;
}

/* ─── Packet Inspection ─── */

int inspect_packet(const char *src_ip, const char *dst_ip,
                   int src_port, int dst_port,
                   const char *protocol, const char *payload,
                   int payload_size) {
    if (g_packet_count >= MAX_PACKETS) {
        log_event("WARN", "Packet buffer full - dropping packet");
        return -1;
    }

    /* Check if source IP is blocked */
    if (is_ip_blocked(src_ip)) {
        g_metrics.blocked_packets++;
        char msg[64];
        snprintf(msg, 64, "Blocked packet from: %s", src_ip);
        log_event("BLOCK", msg);
        return -2;
    }

    /* Store packet */
    Packet *pkt = &g_packets[g_packet_count];
    strncpy(pkt->src_ip,   src_ip,   15);
    strncpy(pkt->dst_ip,   dst_ip,   15);
    strncpy(pkt->protocol, protocol, 7);
    strncpy(pkt->payload,  payload,  255);
    pkt->src_port    = src_port;
    pkt->dst_port    = dst_port;
    pkt->payload_size= payload_size;
    pkt->timestamp   = time(NULL);
    pkt->is_flagged  = 0;

    g_metrics.total_packets++;

    /* Check detection rules */
    int rule_hits = check_rules(payload, src_ip);
    if (rule_hits > 0) {
        pkt->is_flagged = 1;
        g_metrics.flagged_packets++;

        /* Auto-block after 3 rule violations */
        int violations = 0;
        for (int i = 0; i < g_packet_count; i++) {
            if (strcmp(g_packets[i].src_ip, src_ip) == 0 &&
                g_packets[i].is_flagged) {
                violations++;
            }
        }
        if (violations >= 3) {
            block_ip(src_ip, "Auto-blocked: repeated rule violations", 0);
            create_alert("HIGH",
                         "IP auto-blocked after repeated violations",
                         src_ip);
        }
    }

    /* Check for port scan (many different ports from same IP) */
    int unique_ports = 0;
    int port_map[65536] = {0};
    for (int i = 0; i < g_packet_count; i++) {
        if (strcmp(g_packets[i].src_ip, src_ip) == 0) {
            if (!port_map[g_packets[i].dst_port]) {
                port_map[g_packets[i].dst_port] = 1;
                unique_ports++;
            }
        }
    }
    if (unique_ports > 100) {
        create_alert("CRITICAL", "Port scan detected", src_ip);
        block_ip(src_ip, "Port scan detected", 1);
    }

    g_metrics.threat_score = calculate_threat_score(
        g_metrics.flagged_packets, g_metrics.total_packets);

    return g_packet_count++;
}

/* ─── Traffic Analysis ─── */

void analyze_traffic(void) {
    int    tcp_count  = 0;
    int    udp_count  = 0;
    int    icmp_count = 0;
    long   total_bytes= 0;
    char   top_src[16]= "";
    int    top_count  = 0;

    for (int i = 0; i < g_packet_count; i++) {
        if (strcmp(g_packets[i].protocol, "TCP") == 0)  tcp_count++;
        if (strcmp(g_packets[i].protocol, "UDP") == 0)  udp_count++;
        if (strcmp(g_packets[i].protocol, "ICMP") == 0) icmp_count++;
        total_bytes += g_packets[i].payload_size;

        /* Find top talker */
        int src_count = 0;
        for (int j = 0; j < g_packet_count; j++) {
            if (strcmp(g_packets[j].src_ip, g_packets[i].src_ip) == 0)
                src_count++;
        }
        if (src_count > top_count) {
            top_count = src_count;
            strncpy(top_src, g_packets[i].src_ip, 15);
        }
    }

    printf("\n=== TRAFFIC ANALYSIS ===\n");
    printf("Total Packets : %d\n",   g_packet_count);
    printf("TCP Packets   : %d\n",   tcp_count);
    printf("UDP Packets   : %d\n",   udp_count);
    printf("ICMP Packets  : %d\n",   icmp_count);
    printf("Total Bytes   : %ld\n",  total_bytes);
    printf("Top Talker    : %s (%d packets)\n", top_src, top_count);
    printf("========================\n\n");
}

/* ─── Security Dashboard ─── */

void security_dashboard(void) {
    printf("\n=============================\n");
    printf("  SECURITY MONITOR v%s\n", MONITOR_VERSION);
    printf("=============================\n");
    printf("Total Packets   : %ld\n",  g_metrics.total_packets);
    printf("Flagged Packets : %ld\n",  g_metrics.flagged_packets);
    printf("Blocked Packets : %ld\n",  g_metrics.blocked_packets);
    printf("Active Alerts   : %d\n",   g_metrics.active_alerts);
    printf("Blocked IPs     : %d\n",   g_blocked_count);
    printf("Detection Rules : %d\n",   g_rule_count);
    printf("Threat Score    : %.1f%%\n",g_metrics.threat_score);
    printf("Status          : %s\n",
           g_metrics.threat_score > 50.0f ? "CRITICAL" :
           g_metrics.threat_score > 20.0f ? "WARNING"  : "NORMAL");
    printf("=============================\n\n");
}

/* ─── Main ─── */

int main(int argc, char *argv[]) {
    printf("=== Security Monitor v%s Starting ===\n\n", MONITOR_VERSION);

    /* Load detection rules */
    add_detection_rule("SQL Injection",     "SELECT * FROM",  "BLOCK");
    add_detection_rule("XSS Attack",        "<script>",       "BLOCK");
    add_detection_rule("Shell Injection",   "/bin/sh",        "BLOCK");
    add_detection_rule("Directory Traversal","../../../",     "ALERT");
    add_detection_rule("Suspicious Agent",  "nikto",          "ALERT");

    /* Simulate normal traffic */
    inspect_packet("192.168.1.10", "10.0.0.1", 54321, 80,
                   "TCP", "GET /index.html HTTP/1.1", 512);
    inspect_packet("192.168.1.11", "10.0.0.1", 54322, 443,
                   "TCP", "GET /api/data HTTP/1.1", 256);
    inspect_packet("192.168.1.12", "10.0.0.1", 54323, 53,
                   "UDP", "DNS query", 64);

    /* Simulate attacks */
    inspect_packet("10.10.10.99", "10.0.0.1", 12345, 80,
                   "TCP", "SELECT * FROM users WHERE id=1", 128);
    inspect_packet("10.10.10.99", "10.0.0.1", 12346, 80,
                   "TCP", "SELECT * FROM passwords", 128);
    inspect_packet("10.10.10.99", "10.0.0.1", 12347, 80,
                   "TCP", "SELECT * FROM admin", 128);

    inspect_packet("172.16.0.55", "10.0.0.1", 9999, 8080,
                   "TCP", "<script>alert('xss')</script>", 64);
    inspect_packet("172.16.0.66", "10.0.0.1", 8888, 22,
                   "TCP", "/bin/sh -i", 32);

    /* Create manual alert */
    create_alert("MEDIUM", "Unusual traffic pattern detected", "192.168.1.50");
    create_alert("LOW",    "Failed login attempts from subnet", "192.168.2.0");

    /* Block a known bad IP */
    block_ip("185.220.101.1", "Known Tor exit node", 1);
    block_ip("10.10.10.99",   "SQL injection source", 0);

    /* Resolve one alert */
    resolve_alert(1);

    /* Show results */
    analyze_traffic();
    security_dashboard();

    return 0;
}

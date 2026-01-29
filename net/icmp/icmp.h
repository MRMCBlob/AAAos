/**
 * AAAos Network Stack - Internet Control Message Protocol (ICMP)
 *
 * Implements RFC 792 ICMP protocol handling.
 * Features:
 *   - Echo Request/Reply (ping functionality)
 *   - Destination Unreachable messages
 *   - Time Exceeded messages
 *   - High-level ping interface with RTT statistics
 */

#ifndef _AAAOS_NET_ICMP_H
#define _AAAOS_NET_ICMP_H

#include "../../kernel/include/types.h"

/* ICMP Protocol Constants */
#define ICMP_PROTOCOL           1           /* IP protocol number for ICMP */
#define ICMP_HEADER_LEN         8           /* ICMP header is 8 bytes */
#define ICMP_MAX_PAYLOAD        65507       /* Max ICMP payload (65535 - IP - ICMP headers) */
#define ICMP_DEFAULT_PAYLOAD    56          /* Default ping payload size */
#define ICMP_MAX_ECHO_DATA      1472        /* Max echo data (MTU - IP - ICMP headers) */

/* ICMP Message Types */
#define ICMP_TYPE_ECHO_REPLY            0   /* Echo Reply */
#define ICMP_TYPE_DEST_UNREACHABLE      3   /* Destination Unreachable */
#define ICMP_TYPE_SOURCE_QUENCH         4   /* Source Quench (deprecated) */
#define ICMP_TYPE_REDIRECT              5   /* Redirect */
#define ICMP_TYPE_ECHO_REQUEST          8   /* Echo Request */
#define ICMP_TYPE_TIME_EXCEEDED         11  /* Time Exceeded */
#define ICMP_TYPE_PARAM_PROBLEM         12  /* Parameter Problem */
#define ICMP_TYPE_TIMESTAMP             13  /* Timestamp */
#define ICMP_TYPE_TIMESTAMP_REPLY       14  /* Timestamp Reply */
#define ICMP_TYPE_INFO_REQUEST          15  /* Information Request (obsolete) */
#define ICMP_TYPE_INFO_REPLY            16  /* Information Reply (obsolete) */

/* ICMP Destination Unreachable Codes */
#define ICMP_CODE_NET_UNREACHABLE       0   /* Network Unreachable */
#define ICMP_CODE_HOST_UNREACHABLE      1   /* Host Unreachable */
#define ICMP_CODE_PROTO_UNREACHABLE     2   /* Protocol Unreachable */
#define ICMP_CODE_PORT_UNREACHABLE      3   /* Port Unreachable */
#define ICMP_CODE_FRAG_NEEDED           4   /* Fragmentation Needed and DF set */
#define ICMP_CODE_SRC_ROUTE_FAILED      5   /* Source Route Failed */
#define ICMP_CODE_NET_UNKNOWN           6   /* Destination Network Unknown */
#define ICMP_CODE_HOST_UNKNOWN          7   /* Destination Host Unknown */
#define ICMP_CODE_SRC_ISOLATED          8   /* Source Host Isolated */
#define ICMP_CODE_NET_ADMIN_PROHIB      9   /* Network Administratively Prohibited */
#define ICMP_CODE_HOST_ADMIN_PROHIB     10  /* Host Administratively Prohibited */
#define ICMP_CODE_NET_TOS_UNREACHABLE   11  /* Network Unreachable for ToS */
#define ICMP_CODE_HOST_TOS_UNREACHABLE  12  /* Host Unreachable for ToS */
#define ICMP_CODE_COMM_ADMIN_PROHIB     13  /* Communication Administratively Prohibited */

/* ICMP Time Exceeded Codes */
#define ICMP_CODE_TTL_EXCEEDED          0   /* TTL exceeded in transit */
#define ICMP_CODE_FRAG_REASSEMBLY       1   /* Fragment reassembly time exceeded */

/* Ping configuration */
#define PING_DEFAULT_COUNT              4   /* Default number of pings */
#define PING_DEFAULT_TIMEOUT_MS         1000 /* Default timeout in milliseconds */
#define PING_DEFAULT_INTERVAL_MS        1000 /* Default interval between pings */
#define PING_MAX_OUTSTANDING            16  /* Maximum outstanding ping requests */

/**
 * ICMP Header Structure (8 bytes)
 *
 * Format:
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Code      |          Checksum             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Rest of Header                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct PACKED icmp_header {
    uint8_t  type;              /* ICMP message type */
    uint8_t  code;              /* ICMP message code */
    uint16_t checksum;          /* ICMP checksum */
    uint32_t rest_of_header;    /* Rest of header (varies by type) */
} icmp_header_t;

/**
 * ICMP Echo Request/Reply specific header
 * The rest_of_header field contains identifier and sequence number
 */
typedef struct PACKED icmp_echo {
    uint8_t  type;              /* ICMP type (0 = reply, 8 = request) */
    uint8_t  code;              /* Code (always 0 for echo) */
    uint16_t checksum;          /* ICMP checksum */
    uint16_t identifier;        /* Identifier (to match requests/replies) */
    uint16_t sequence;          /* Sequence number */
    /* Payload data follows */
} icmp_echo_t;

/**
 * ICMP Destination Unreachable / Time Exceeded header
 * Contains the original IP header + first 8 bytes of original datagram
 */
typedef struct PACKED icmp_error {
    uint8_t  type;              /* ICMP type (3 or 11) */
    uint8_t  code;              /* Error code */
    uint16_t checksum;          /* ICMP checksum */
    uint32_t unused;            /* Unused (must be zero) */
    /* Original IP header + first 8 bytes of original payload follows */
} icmp_error_t;

/**
 * Ping statistics structure
 * Tracks sent, received, lost packets and RTT measurements
 */
typedef struct ping_stats {
    uint32_t packets_sent;      /* Number of echo requests sent */
    uint32_t packets_received;  /* Number of echo replies received */
    uint32_t packets_lost;      /* Number of lost packets (sent - received) */
    uint32_t errors;            /* Number of error responses received */

    /* Round Trip Time statistics (in milliseconds) */
    uint32_t rtt_min;           /* Minimum RTT */
    uint32_t rtt_max;           /* Maximum RTT */
    uint32_t rtt_sum;           /* Sum of all RTTs (for average calculation) */
    uint32_t rtt_avg;           /* Average RTT */

    /* Timing */
    uint64_t start_time;        /* Start time (ticks) */
    uint64_t end_time;          /* End time (ticks) */

    /* Target information */
    uint32_t dest_ip;           /* Destination IP address */
    bool     active;            /* Whether ping is currently active */
} ping_stats_t;

/**
 * Pending echo request tracking
 */
typedef struct icmp_pending_echo {
    uint32_t dest_ip;           /* Destination IP address */
    uint16_t identifier;        /* Echo identifier */
    uint16_t sequence;          /* Sequence number */
    uint64_t send_time;         /* Time when request was sent (ticks) */
    bool     active;            /* Whether this slot is in use */
} icmp_pending_echo_t;

/* Error codes */
#define ICMP_OK                 0
#define ICMP_ERR_NOMEM         -1       /* Out of memory */
#define ICMP_ERR_INVALID       -2       /* Invalid argument */
#define ICMP_ERR_TIMEOUT       -3       /* Request timed out */
#define ICMP_ERR_UNREACHABLE   -4       /* Destination unreachable */
#define ICMP_ERR_NOROUTE       -5       /* No route to destination */
#define ICMP_ERR_BUSY          -6       /* Too many outstanding requests */

/*
 * API Functions
 */

/**
 * Initialize the ICMP subsystem
 * Must be called before any other ICMP functions
 */
void icmp_init(void);

/**
 * Send an ICMP echo request (ping)
 * @param dest_ip Destination IP address (host byte order)
 * @param identifier Echo identifier (used to match replies)
 * @param sequence Sequence number
 * @param data Optional payload data (can be NULL)
 * @param len Payload data length
 * @return ICMP_OK on success, negative error code on failure
 */
int icmp_send_echo_request(uint32_t dest_ip, uint16_t identifier,
                           uint16_t sequence, const void *data, size_t len);

/**
 * Send an ICMP echo reply
 * @param dest_ip Destination IP address (host byte order)
 * @param identifier Echo identifier (copied from request)
 * @param sequence Sequence number (copied from request)
 * @param data Payload data (copied from request)
 * @param len Payload data length
 * @return ICMP_OK on success, negative error code on failure
 */
int icmp_send_echo_reply(uint32_t dest_ip, uint16_t identifier,
                         uint16_t sequence, const void *data, size_t len);

/**
 * Process incoming ICMP packet from IP layer
 * @param src_ip Source IP address (host byte order)
 * @param packet Raw ICMP packet data
 * @param len Packet length
 * @return 0 on success, negative error code on failure
 */
int icmp_input(uint32_t src_ip, const void *packet, size_t len);

/**
 * Send an ICMP Destination Unreachable message
 * @param dest_ip Original packet source IP (where to send the error)
 * @param orig_packet Original IP packet that caused the error
 * @param orig_len Length of original packet
 * @param code Unreachable code (ICMP_CODE_*)
 * @return ICMP_OK on success, negative error code on failure
 */
int icmp_send_dest_unreachable(uint32_t dest_ip, const void *orig_packet,
                               size_t orig_len, uint8_t code);

/**
 * Send an ICMP Time Exceeded message
 * @param dest_ip Original packet source IP (where to send the error)
 * @param orig_packet Original IP packet that caused the error
 * @param orig_len Length of original packet
 * @param code Time exceeded code (ICMP_CODE_TTL_EXCEEDED or ICMP_CODE_FRAG_REASSEMBLY)
 * @return ICMP_OK on success, negative error code on failure
 */
int icmp_send_time_exceeded(uint32_t dest_ip, const void *orig_packet,
                            size_t orig_len, uint8_t code);

/**
 * Perform a ping operation (high-level interface)
 * Sends specified number of echo requests and waits for replies.
 * This is a blocking operation.
 *
 * @param dest_ip Destination IP address (host byte order)
 * @param count Number of echo requests to send (0 = use default)
 * @param timeout_ms Timeout for each request in milliseconds (0 = use default)
 * @return Pointer to ping statistics, or NULL on error
 */
ping_stats_t *ping(uint32_t dest_ip, uint32_t count, uint32_t timeout_ms);

/**
 * Start continuous ping operation (non-blocking)
 * Starts sending periodic echo requests in the background.
 * Use ping_stop() to stop and ping_get_stats() to retrieve statistics.
 *
 * @param dest_ip Destination IP address (host byte order)
 * @return ICMP_OK on success, negative error code on failure
 */
int ping_start(uint32_t dest_ip);

/**
 * Stop continuous ping operation
 * Stops the background ping and finalizes statistics.
 *
 * @return ICMP_OK on success, negative error code on failure
 */
int ping_stop(void);

/**
 * Get current ping statistics
 * Returns a copy of the current ping statistics.
 *
 * @return Pointer to ping statistics structure
 */
const ping_stats_t *ping_get_stats(void);

/**
 * Check if a ping operation is currently active
 * @return true if ping is active, false otherwise
 */
bool ping_is_active(void);

/**
 * Calculate ICMP checksum
 * @param data ICMP packet data (header + payload)
 * @param len Total length
 * @return Checksum value
 */
uint16_t icmp_checksum(const void *data, size_t len);

/**
 * Convert ICMP type to string description
 * @param type ICMP message type
 * @return String description of the type
 */
const char *icmp_type_to_string(uint8_t type);

/**
 * Convert ICMP unreachable code to string description
 * @param code Unreachable code
 * @return String description of the code
 */
const char *icmp_unreachable_code_to_string(uint8_t code);

/**
 * Print ICMP statistics for debugging
 */
void icmp_debug_stats(void);

#endif /* _AAAOS_NET_ICMP_H */

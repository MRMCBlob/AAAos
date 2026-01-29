/**
 * AAAos Network Stack - HTTP/1.1 Client
 *
 * Provides an HTTP/1.1 client implementation supporting:
 *   - GET, POST, HEAD requests
 *   - HTTP headers parsing
 *   - Chunked transfer encoding
 *   - Basic response handling
 */

#ifndef _AAAOS_NET_HTTP_H
#define _AAAOS_NET_HTTP_H

#include "../../kernel/include/types.h"

/* HTTP Constants */
#define HTTP_DEFAULT_PORT           80
#define HTTP_MAX_HEADERS            32
#define HTTP_MAX_HEADER_NAME        64
#define HTTP_MAX_HEADER_VALUE       256
#define HTTP_MAX_URL_LEN            2048
#define HTTP_MAX_HOST_LEN           256
#define HTTP_MAX_PATH_LEN           1024
#define HTTP_MAX_STATUS_TEXT        64
#define HTTP_BUFFER_SIZE            8192
#define HTTP_MAX_BODY_SIZE          (1 * 1024 * 1024)  /* 1MB max body */
#define HTTP_TIMEOUT_MS             30000              /* 30 second timeout */

/* HTTP Version string */
#define HTTP_VERSION                "HTTP/1.1"

/* HTTP Methods */
typedef enum http_method {
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_POST,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE
} http_method_t;

/* HTTP Error codes */
#define HTTP_OK                     0
#define HTTP_ERR_INVALID_URL        -1
#define HTTP_ERR_DNS_FAILED         -2
#define HTTP_ERR_CONNECT_FAILED     -3
#define HTTP_ERR_SEND_FAILED        -4
#define HTTP_ERR_RECV_FAILED        -5
#define HTTP_ERR_TIMEOUT            -6
#define HTTP_ERR_NO_MEMORY          -7
#define HTTP_ERR_PARSE_FAILED       -8
#define HTTP_ERR_BUFFER_OVERFLOW    -9
#define HTTP_ERR_INVALID_RESPONSE   -10
#define HTTP_ERR_NOT_INITIALIZED    -11

/**
 * HTTP Header structure
 * Represents a single HTTP header (name: value)
 */
typedef struct http_header {
    char name[HTTP_MAX_HEADER_NAME];
    char value[HTTP_MAX_HEADER_VALUE];
} http_header_t;

/**
 * HTTP Request structure
 * Contains all information needed to build an HTTP request
 */
typedef struct http_request {
    http_method_t method;                           /* Request method (GET, POST, etc.) */
    char url[HTTP_MAX_URL_LEN];                     /* Full URL */
    char host[HTTP_MAX_HOST_LEN];                   /* Host from URL */
    uint16_t port;                                  /* Port (default 80) */
    char path[HTTP_MAX_PATH_LEN];                   /* Path component of URL */

    http_header_t headers[HTTP_MAX_HEADERS];        /* Request headers */
    int header_count;                               /* Number of headers set */

    const void *body;                               /* Request body (for POST) */
    size_t body_len;                                /* Body length in bytes */

    uint32_t timeout_ms;                            /* Request timeout in ms */
} http_request_t;

/**
 * HTTP Response structure
 * Contains the parsed HTTP response
 */
typedef struct http_response {
    int status_code;                                /* HTTP status code (200, 404, etc.) */
    char status_text[HTTP_MAX_STATUS_TEXT];         /* Status text ("OK", "Not Found", etc.) */

    http_header_t headers[HTTP_MAX_HEADERS];        /* Response headers */
    int header_count;                               /* Number of headers received */

    void *body;                                     /* Response body (dynamically allocated) */
    size_t body_len;                                /* Body length in bytes */
    size_t body_capacity;                           /* Allocated body buffer size */

    bool chunked;                                   /* True if chunked transfer encoding */
    size_t content_length;                          /* Content-Length header value (-1 if not present) */
} http_response_t;

/* ============================================================================
 * HTTP Client API Functions
 * ============================================================================ */

/**
 * Initialize the HTTP client subsystem
 * Must be called before any HTTP operations.
 *
 * @return HTTP_OK on success, negative error code on failure
 */
int http_init(void);

/**
 * Perform an HTTP GET request
 *
 * @param url Full URL to request (e.g., "http://example.com/path")
 * @param response Pointer to response structure to fill
 * @return HTTP_OK on success, negative error code on failure
 */
int http_get(const char *url, http_response_t *response);

/**
 * Perform an HTTP POST request
 *
 * @param url Full URL to request
 * @param body Request body data
 * @param body_len Length of body data in bytes
 * @param response Pointer to response structure to fill
 * @return HTTP_OK on success, negative error code on failure
 */
int http_post(const char *url, const void *body, size_t body_len, http_response_t *response);

/**
 * Perform an HTTP HEAD request
 *
 * @param url Full URL to request
 * @param response Pointer to response structure to fill (body will be empty)
 * @return HTTP_OK on success, negative error code on failure
 */
int http_head(const char *url, http_response_t *response);

/**
 * Perform a generic HTTP request
 *
 * @param request Pointer to fully populated request structure
 * @param response Pointer to response structure to fill
 * @return HTTP_OK on success, negative error code on failure
 */
int http_request(http_request_t *request, http_response_t *response);

/**
 * Free resources associated with an HTTP response
 *
 * @param response Pointer to response structure to free
 */
void http_free_response(http_response_t *response);

/* ============================================================================
 * Request Building Functions
 * ============================================================================ */

/**
 * Initialize an HTTP request structure with defaults
 *
 * @param request Pointer to request structure to initialize
 * @param method HTTP method to use
 * @param url URL to request
 * @return HTTP_OK on success, negative error code on failure
 */
int http_init_request(http_request_t *request, http_method_t method, const char *url);

/**
 * Add a header to an HTTP request
 *
 * @param request Pointer to request structure
 * @param name Header name
 * @param value Header value
 * @return HTTP_OK on success, HTTP_ERR_BUFFER_OVERFLOW if too many headers
 */
int http_set_header(http_request_t *request, const char *name, const char *value);

/**
 * Build the HTTP request string
 *
 * @param request Pointer to request structure
 * @param buffer Buffer to write request string to
 * @param buffer_size Size of buffer
 * @return Number of bytes written, or negative error code
 */
int http_build_request(const http_request_t *request, char *buffer, size_t buffer_size);

/* ============================================================================
 * URL Parsing Functions
 * ============================================================================ */

/**
 * Parse a URL into its components
 *
 * @param url Full URL string
 * @param host Buffer to receive host (at least HTTP_MAX_HOST_LEN bytes)
 * @param port Pointer to receive port number
 * @param path Buffer to receive path (at least HTTP_MAX_PATH_LEN bytes)
 * @return HTTP_OK on success, HTTP_ERR_INVALID_URL on failure
 */
int http_parse_url(const char *url, char *host, uint16_t *port, char *path);

/* ============================================================================
 * Response Parsing Functions
 * ============================================================================ */

/**
 * Parse an HTTP response from raw data
 *
 * @param data Raw response data
 * @param len Length of data
 * @param response Pointer to response structure to fill
 * @return HTTP_OK on success, negative error code on failure
 */
int http_parse_response(const void *data, size_t len, http_response_t *response);

/**
 * Get a header value from a response
 *
 * @param response Pointer to response structure
 * @param name Header name to find (case-insensitive)
 * @return Pointer to header value string, or NULL if not found
 */
const char *http_get_header(const http_response_t *response, const char *name);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get string name for HTTP method
 *
 * @param method HTTP method enum value
 * @return Static string (e.g., "GET", "POST")
 */
const char *http_method_string(http_method_t method);

/**
 * Get error string for HTTP error code
 *
 * @param error HTTP error code
 * @return Static string describing the error
 */
const char *http_error_string(int error);

/**
 * URL-encode a string
 *
 * @param input Input string to encode
 * @param output Buffer to write encoded string
 * @param output_size Size of output buffer
 * @return Length of encoded string, or negative error code
 */
int http_url_encode(const char *input, char *output, size_t output_size);

/**
 * URL-decode a string
 *
 * @param input Input string to decode
 * @param output Buffer to write decoded string
 * @param output_size Size of output buffer
 * @return Length of decoded string, or negative error code
 */
int http_url_decode(const char *input, char *output, size_t output_size);

#endif /* _AAAOS_NET_HTTP_H */

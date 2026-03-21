/*
 * Coverity Scan behavioral model file for embedded_linux_audit.
 *
 * This file is NOT compiled into the project. It is submitted to
 * Coverity Scan to teach the analyzer how custom functions behave,
 * reducing false positives and improving true-positive detection.
 *
 * Valid primitives used:
 *   __coverity_panic__()               — function never returns
 *   __coverity_tainted_data_sink__(arg) — arg is a safe sink for tainted data
 *   __coverity_writeall__(ptr)          — function writes to the buffer *ptr
 *   malloc(n) / free(p)                — model heap allocation / deallocation
 */

/* Coverity model files cannot include system headers; declare malloc directly. */
void *malloc(unsigned long size);

/* -----------------------------------------------------------------------
 * Heap-allocating functions
 * Modeled using malloc() so Coverity knows:
 *   (a) the returned pointer is heap-allocated and must be freed, and
 *   (b) it may be NULL (malloc can return NULL).
 * ----------------------------------------------------------------------- */

/*
 * Builds a URI string for HTTP upload. Returns a malloc'd string that the
 * caller must free, or NULL on allocation failure.
 */
char *ela_http_build_upload_uri(const char *base_uri,
                                const char *upload_type,
                                const char *file_path)
{
    size_t n;
    return (char *)malloc(n);
}

/*
 * Percent-encodes a URL path component. Returns a malloc'd string or NULL.
 */
char *url_percent_encode(const char *text)
{
    size_t n;
    return (char *)malloc(n);
}

/*
 * Script-context URL percent-encoder. Same ownership as url_percent_encode.
 */
char *ela_script_url_percent_encode(const char *text)
{
    size_t n;
    return (char *)malloc(n);
}

/*
 * Normalises an HTTP URI by inserting an explicit default port.
 * Returns a malloc'd string (caller must free) or NULL.
 */
char *ela_http_uri_normalize_default_port(const char *uri,
                                          unsigned short default_port)
{
    size_t n;
    return (char *)malloc(n);
}

/*
 * Builds a short human-readable command summary from argv.
 * Returns a malloc'd string (caller must free) or NULL.
 */
char *ela_build_command_summary(int argc, char **argv, int start_idx)
{
    size_t n;
    return (char *)malloc(n);
}

/*
 * Constructs a symlink upload URI. Returns malloc'd string or NULL.
 */
char *ela_remote_copy_build_symlink_upload_uri(const char *upload_uri,
                                               const char *target_path)
{
    size_t n;
    return (char *)malloc(n);
}

/* -----------------------------------------------------------------------
 * Tainted-data sink functions
 * Network/output functions that are safe destinations for data read from
 * the filesystem or network. Marking them as sinks stops Coverity from
 * propagating taint through the send/write paths into unrelated checkers.
 * ----------------------------------------------------------------------- */

/*
 * Sends all bytes in buf to sock. Buffer contents come from the device
 * being audited; they are intentionally forwarded to the remote collector.
 */
int ela_send_all(int sock, const unsigned char *buf, unsigned long len)
{
    __coverity_tainted_data_sink__(buf);
    __coverity_tainted_data_sink__(len);
    return 0;
}

/*
 * Posts data over HTTP(S) to a remote collector.
 * data/len come from device reads and are the intended payload.
 */
int ela_http_post(const char *uri,
                  const unsigned char *data, unsigned long len,
                  const char *content_type,
                  int insecure, int verbose,
                  char *errbuf, unsigned long errbuf_len)
{
    __coverity_tainted_data_sink__(data);
    __coverity_tainted_data_sink__(len);
    __coverity_writeall__(errbuf);
    return 0;
}

/*
 * Downloads URI content to a local file. uri is caller-controlled.
 */
int ela_http_get_to_file(const char *uri, const char *output_path,
                         int insecure, int verbose,
                         char *errbuf, unsigned long errbuf_len)
{
    __coverity_tainted_data_sink__(uri);
    __coverity_writeall__(errbuf);
    return 0;
}

/*
 * Retrieves the MAC address associated with a collector URI.
 * mac_buf is an output buffer written by this function.
 */
int ela_http_get_upload_mac(const char *base_uri,
                            char *mac_buf, unsigned long mac_buf_len)
{
    __coverity_writeall__(mac_buf);
    return 0;
}

/* -----------------------------------------------------------------------
 * Error-buffer writing functions
 * Functions that accept (char *errbuf, size_t errbuf_len) pairs and write
 * diagnostic text into errbuf on failure.
 * ----------------------------------------------------------------------- */

int ela_parse_http_output_uri(const char *uri,
                              const char **output_http,
                              const char **output_https,
                              char *errbuf, unsigned long errbuf_len)
{
    __coverity_writeall__(errbuf);
    return 0;
}

/* -----------------------------------------------------------------------
 * Size-guessing functions
 * These read device metadata from /sys and /proc. The values are not
 * user-controlled; callers are responsible for capping results before
 * use as loop bounds or allocation sizes.
 * ----------------------------------------------------------------------- */

unsigned long long uboot_guess_size_any(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_step_any(const char *dev)
{
    unsigned long long step;
    return step;
}

unsigned long long uboot_guess_size_from_sysfs(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_size_from_proc_mtd(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_size_from_ubi_sysfs(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_size_from_block_sysfs(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_erasesize_from_sysfs(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_erasesize_from_proc_mtd(const char *dev)
{
    unsigned long long sz;
    return sz;
}

unsigned long long uboot_guess_step_from_ubi_sysfs(const char *dev)
{
    unsigned long long step;
    return step;
}

unsigned long long uboot_guess_step_from_block_sysfs(const char *dev)
{
    unsigned long long step;
    return step;
}

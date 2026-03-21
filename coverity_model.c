/*
 * Coverity Scan behavioral model file for embedded_linux_audit.
 *
 * This file is NOT compiled into the project. It is submitted to
 * Coverity Scan to teach the analyzer how custom functions behave,
 * reducing false positives and improving true-positive detection.
 *
 * Primitives used:
 *   __coverity_return_null_on_error__() — function may return NULL on failure
 *   __coverity_alloc__(size)            — return value is a heap allocation
 *   __coverity_free__(ptr)              — function frees ptr
 *   __coverity_tainted_data_sink__(arg) — arg is a safe sink; stop taint propagation
 *   __coverity_writeall__(ptr)          — function writes to the buffer *ptr
 *   __coverity_panic__()               — function never returns
 */

/* -----------------------------------------------------------------------
 * Heap-allocating functions
 * Tell Coverity these return caller-owned heap memory (may be NULL).
 * ----------------------------------------------------------------------- */

/*
 * Builds a URI string for HTTP upload. Returns a malloc'd string that the
 * caller must free, or NULL on allocation failure.
 */
char *ela_http_build_upload_uri(const char *base_uri,
                                const char *upload_type,
                                const char *file_path)
{
    char *p;
    __coverity_return_null_on_error__();
    return p;
}

/*
 * Percent-encodes a URL path component. Returns a malloc'd string that the
 * caller must free, or NULL on failure.
 */
char *url_percent_encode(const char *text)
{
    char *p;
    __coverity_return_null_on_error__();
    return p;
}

/*
 * Script-context URL percent-encoder. Same ownership as url_percent_encode.
 */
char *ela_script_url_percent_encode(const char *text)
{
    char *p;
    __coverity_return_null_on_error__();
    return p;
}

/*
 * Normalises an HTTP URI by inserting an explicit default port.
 * Returns a malloc'd string (caller must free) or NULL.
 */
char *ela_http_uri_normalize_default_port(const char *uri,
                                          unsigned short default_port)
{
    char *p;
    __coverity_return_null_on_error__();
    return p;
}

/*
 * Builds a short human-readable command summary from argv.
 * Returns a malloc'd string (caller must free) or NULL.
 */
char *ela_build_command_summary(int argc, char **argv, int start_idx)
{
    char *p;
    __coverity_return_null_on_error__();
    return p;
}

/*
 * Constructs a symlink upload URI. Returns malloc'd string or NULL.
 */
char *ela_remote_copy_build_symlink_upload_uri(const char *upload_uri,
                                               const char *target_path)
{
    char *p;
    __coverity_return_null_on_error__();
    return p;
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
 * diagnostic text into errbuf on failure. Modeling writeall prevents
 * Coverity from flagging the buffer as potentially uninitialized after
 * an error-path call.
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
 * These read device metadata from /sys and /proc. The values are bounded
 * by the physical device and are not user-controlled; they are tainted
 * only in the sense that they are external. We model them as returning an
 * unsigned 64-bit value to help Coverity understand the type contract.
 * Callers are responsible for capping the result before use as a loop
 * bound or allocation size (see existing ELA_GDB_MAX_PHNUM-style caps).
 * ----------------------------------------------------------------------- */

/*
 * Returns the detected size of a flash/block/UBI device in bytes, or 0
 * if the size cannot be determined. Not a user-controlled value.
 */
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

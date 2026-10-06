#pragma once
#include <stdint.h>

/* All header words are unsigned 32-bit integers in network byte order. Each
 * connection owns one request and response, so callers cannot consume another
 * caller's result. Strings are length-delimited UTF-8, without terminating NUL. */
#define CE_MONO_MAGIC 0x43454d31u
#define CE_MONO_MAX_REQUEST (1024u * 1024u)
#ifndef CE_MONO_MAX_RESPONSE
#define CE_MONO_MAX_RESPONSE (64u * 1024u * 1024u)
#endif
enum { CE_MONO_DUMP = 1, CE_MONO_METHOD = 2 };
enum { CE_MONO_OK = 0, CE_MONO_ERROR = 1 };
/* Request: magic, command, namespace bytes, class bytes, method bytes, paramCount.
 * Response: magic, status, payload bytes; then the dump, hex address or error. */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if the text passes guardrails, 0 if sensitive content is detected.
int edge_guardrail_check(const char *text, size_t len);

#ifdef __cplusplus
}
#endif

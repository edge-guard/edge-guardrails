/* EdgeGuard - on-device AI guardrails. C ABI.
 *
 * Link against libedgeguard.a (staticlib) or libedgeguard.dylib/.so (cdylib):
 *
 *     cargo build --release
 *     cc demo.c -I include -L target/release -ledgeguard -lm -o demo
 *
 * On Linux add -lpthread -ldl; on macOS add -framework CoreFoundation
 * -framework Security.
 *
 * ---------------------------------------------------------------------------
 * MEMORY CONTRACT - read this before using the API
 * ---------------------------------------------------------------------------
 *
 *  1. edgeguard_decision_t owns nothing. It is plain old data, it is filled
 *     in by value, and there is no function to free it. Put it on the stack.
 *
 *  2. Every const char* returned by this API is a static string compiled into
 *     the library. NEVER free() one. They are valid for the process lifetime.
 *
 *  3. edgeguard_last_error() writes into a buffer YOU own. Nothing is
 *     allocated on your behalf.
 *
 *  4. The ONLY thing you must release is the engine handle, exactly once,
 *     with edgeguard_engine_free().
 *
 * There is deliberately no other ownership to get wrong. The engine never
 * hands you an allocation you are expected to give back.
 *
 * ---------------------------------------------------------------------------
 * FAIL-CLOSED CONTRACT
 * ---------------------------------------------------------------------------
 *
 * edgeguard_scan() writes a BLOCKING decision into *out before it does
 * anything else. If it returns an error, or if you ignore the return code
 * entirely, *out still says block. A guardrail that fails open because the
 * caller forgot to check a return value is not a guardrail.
 *
 * ---------------------------------------------------------------------------
 * THREADING
 * ---------------------------------------------------------------------------
 *
 * Construct one engine at startup and share the pointer with every worker.
 * edgeguard_scan() on a shared handle is safe from any number of threads
 * simultaneously. edgeguard_engine_free() must happen after the last scan has
 * returned.
 */
#ifndef EDGEGUARD_H
#define EDGEGUARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- status codes ------------------------------------------------------- */
#define EDGEGUARD_OK                     0
#define EDGEGUARD_ERR_NULL_ARG          (-1)
#define EDGEGUARD_ERR_INVALID_UTF8      (-2)
#define EDGEGUARD_ERR_BAD_RULES         (-3)
#define EDGEGUARD_ERR_INTERNAL          (-4)
#define EDGEGUARD_ERR_BUFFER_TOO_SMALL  (-5)

/* --- verdicts ----------------------------------------------------------- */
#define EDGEGUARD_VERDICT_ALLOW  0
#define EDGEGUARD_VERDICT_FLAG   1  /* suspicious; host decides policy */
#define EDGEGUARD_VERDICT_BLOCK  2

/* --- deciding stage ----------------------------------------------------- */
#define EDGEGUARD_STAGE_SIZE_GUARD            0
#define EDGEGUARD_STAGE_OBFUSCATION           1
#define EDGEGUARD_STAGE_TIER1_RULE            2
#define EDGEGUARD_STAGE_TIER1_ALLOWLIST       3
#define EDGEGUARD_STAGE_TIER1_DETERMINISTIC   4
#define EDGEGUARD_STAGE_TIER1_NO_SIGNAL       5
#define EDGEGUARD_STAGE_TIER2_MODEL           6
#define EDGEGUARD_STAGE_TIER2_UNAVAILABLE     7
#define EDGEGUARD_STAGE_TIER2_FAILED          8
#define EDGEGUARD_STAGE_TIER2_SHED            9
#define EDGEGUARD_STAGE_INTERNAL_ERROR       10
/* Appended, not inserted: these values reach SIEM rules, so renumbering an
 * existing stage would silently relabel historical events. */
#define EDGEGUARD_STAGE_TIER2_DEFERRED       11

/* --- obfuscation bits (see edgeguard_obfuscation_name) ------------------ */
#define EDGEGUARD_OBF_PERCENT_ENCODED      (1u << 0)
#define EDGEGUARD_OBF_ZERO_WIDTH           (1u << 1)
#define EDGEGUARD_OBF_BIDI_OVERRIDE        (1u << 2)
#define EDGEGUARD_OBF_COMBINING_MARKS      (1u << 3)
#define EDGEGUARD_OBF_COMPAT_FOLDED        (1u << 4)
#define EDGEGUARD_OBF_HOMOGLYPH            (1u << 5)
#define EDGEGUARD_OBF_LEETSPEAK            (1u << 6)
#define EDGEGUARD_OBF_STRETCHED            (1u << 7)
#define EDGEGUARD_OBF_WHITESPACE_SQUEEZED  (1u << 8)
#define EDGEGUARD_OBF_LETTER_SPACED        (1u << 9)
#define EDGEGUARD_OBF_CASE_FOLDED          (1u << 10)
#define EDGEGUARD_OBF_INVALID_UTF8         (1u << 11)
#define EDGEGUARD_OBF_SEPARATOR_SPLIT      (1u << 12)

typedef struct edgeguard_engine_t edgeguard_engine_t;

typedef struct {
    uint64_t latency_ns;
    /* Byte offsets into YOUR prompt buffer. Valid only when has_span != 0.
     * Already mapped back through every normalization stage, so they can be
     * used to redact the original bytes in place. */
    uint64_t span_start;
    uint64_t span_end;
    int      verdict;            /* EDGEGUARD_VERDICT_*  */
    int      decided_by;         /* EDGEGUARD_STAGE_*    */
    uint32_t violation_code;
    uint32_t rule_id;            /* only for STAGE_TIER1_RULE */
    uint32_t obfuscation_bits;   /* EDGEGUARD_OBF_* bitfield  */
    uint32_t obfuscation_layers; /* popcount of the above     */
    int      model_bypassed;
    int      has_span;
} edgeguard_decision_t;

/* Create an engine. rules_yaml may be NULL for the built-in baseline only.
 * Returns NULL on failure; see edgeguard_last_error().
 *
 * Equivalent to edgeguard_engine_new_ex(rules_yaml, rules_len, NULL, NULL).
 * Both constructors attach the full deterministic detector set (Luhn card,
 * national ID, email, AWS key) - a C host gets exactly the same verdicts as
 * the Python binding for the same input. */
edgeguard_engine_t *edgeguard_engine_new(const char *rules_yaml, size_t rules_len);

/* As above, plus the operator-editable layers:
 *   policy_path   - NUL-terminated path to a policy.yaml, hot reloaded in the
 *                   background, or NULL.
 *   audit_db_path - NUL-terminated path for the SQLite audit trail, or NULL to
 *                   keep the trail in memory and write nothing to disk.
 * Note rules_yaml is NOT NUL-terminated (rules_len is authoritative) while the
 * two paths are - they are ordinary C strings. */
edgeguard_engine_t *edgeguard_engine_new_ex(const char *rules_yaml,
                                            size_t rules_len,
                                            const char *policy_path,
                                            const char *audit_db_path);

/* Release an engine. NULL is a no-op. Call exactly once. */
void edgeguard_engine_free(edgeguard_engine_t *engine);

/* Scan prompt[0..len). Need not be NUL-terminated. Must be valid UTF-8.
 * *out is filled with a BLOCKING decision before any other work, so it is
 * safe even on the error paths. */
int edgeguard_scan(const edgeguard_engine_t *engine,
                   const char *prompt,
                   size_t len,
                   edgeguard_decision_t *out);

/* Static strings. Do NOT free. */
const char *edgeguard_decided_by_name(int stage);
const char *edgeguard_obfuscation_name(uint32_t single_bit); /* NULL if not exactly one known bit */
const char *edgeguard_version(void);

/* snprintf convention: writes at most cap bytes including the NUL, returns
 * the length the full message needs. Pass (NULL, 0) to probe. */
size_t edgeguard_last_error(char *buf, size_t cap);

/* Largest prompt that will be analyzed; bigger is refused with code 413. */
size_t edgeguard_max_input_bytes(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* EDGEGUARD_H */

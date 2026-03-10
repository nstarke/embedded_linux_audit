#include <stdint.h>

/*
 * Zig's older 32-bit ARM musl targets can emit references to legacy __sync
 * builtins through compiler-rt's __atomic helpers, but do not provide the
 * underlying symbols at link time.  This project is single-process and these
 * fallback implementations are only used for cross-built static binaries on
 * old arm32 targets, so a simple non-locking implementation is sufficient to
 * unblock linking.
 */

#define DEFINE_SYNC_LOCK_TEST_AND_SET(bits, type)                          \
    type legacy_sync_lock_test_and_set_##bits(volatile type *p, type v)   \
        __asm__("__sync_lock_test_and_set_" #bits);                       \
    type legacy_sync_lock_test_and_set_##bits(volatile type *p, type v)   \
    {                                                      \
        type old = *p;                                     \
        *p = v;                                            \
        return old;                                        \
    }

#define DEFINE_SYNC_FETCH_AND_OP(name, bits, type, op)                     \
    type legacy_sync_fetch_and_##name##_##bits(volatile type *p, type v)  \
        __asm__("__sync_fetch_and_" #name "_" #bits);                    \
    type legacy_sync_fetch_and_##name##_##bits(volatile type *p, type v)  \
    {                                                      \
        type old = *p;                                     \
        *p = (type)(old op v);                             \
        return old;                                        \
    }

#define DEFINE_SYNC_VAL_CAS(bits, type)                                    \
    type legacy_sync_val_compare_and_swap_##bits(volatile type *p,         \
                                                 type oldv, type newv)     \
        __asm__("__sync_val_compare_and_swap_" #bits);                    \
    type legacy_sync_val_compare_and_swap_##bits(volatile type *p,         \
                                                 type oldv, type newv)     \
    {                                                      \
        type old = *p;                                     \
        if (old == oldv)                                   \
            *p = newv;                                     \
        return old;                                        \
    }

#define DEFINE_SYNC_FETCH_AND_UMIN(bits, type)                             \
    type legacy_sync_fetch_and_umin_##bits(volatile type *p, type v)      \
        __asm__("__sync_fetch_and_umin_" #bits);                          \
    type legacy_sync_fetch_and_umin_##bits(volatile type *p, type v)      \
    {                                                      \
        type old = *p;                                     \
        *p = old < v ? old : v;                            \
        return old;                                        \
    }

#define DEFINE_SYNC_FETCH_AND_UMAX(bits, type)                             \
    type legacy_sync_fetch_and_umax_##bits(volatile type *p, type v)      \
        __asm__("__sync_fetch_and_umax_" #bits);                          \
    type legacy_sync_fetch_and_umax_##bits(volatile type *p, type v)      \
    {                                                      \
        type old = *p;                                     \
        *p = old > v ? old : v;                            \
        return old;                                        \
    }

DEFINE_SYNC_LOCK_TEST_AND_SET(1, uint8_t)
DEFINE_SYNC_LOCK_TEST_AND_SET(2, uint16_t)
DEFINE_SYNC_LOCK_TEST_AND_SET(4, uint32_t)

DEFINE_SYNC_FETCH_AND_OP(add, 1, uint8_t, +)
DEFINE_SYNC_FETCH_AND_OP(add, 2, uint16_t, +)
DEFINE_SYNC_FETCH_AND_OP(add, 4, uint32_t, +)
DEFINE_SYNC_FETCH_AND_OP(sub, 1, uint8_t, -)
DEFINE_SYNC_FETCH_AND_OP(sub, 2, uint16_t, -)
DEFINE_SYNC_FETCH_AND_OP(sub, 4, uint32_t, -)
DEFINE_SYNC_FETCH_AND_OP(and, 1, uint8_t, &)
DEFINE_SYNC_FETCH_AND_OP(and, 2, uint16_t, &)
DEFINE_SYNC_FETCH_AND_OP(and, 4, uint32_t, &)
DEFINE_SYNC_FETCH_AND_OP(or, 1, uint8_t, |)
DEFINE_SYNC_FETCH_AND_OP(or, 2, uint16_t, |)
DEFINE_SYNC_FETCH_AND_OP(or, 4, uint32_t, |)
DEFINE_SYNC_FETCH_AND_OP(xor, 1, uint8_t, ^)
DEFINE_SYNC_FETCH_AND_OP(xor, 2, uint16_t, ^)
DEFINE_SYNC_FETCH_AND_OP(xor, 4, uint32_t, ^)

uint8_t legacy_sync_fetch_and_nand_1(volatile uint8_t *p, uint8_t v)
    __asm__("__sync_fetch_and_nand_1");
uint8_t legacy_sync_fetch_and_nand_1(volatile uint8_t *p, uint8_t v)
{
    uint8_t old = *p;
    *p = (uint8_t)~(old & v);
    return old;
}

uint16_t legacy_sync_fetch_and_nand_2(volatile uint16_t *p, uint16_t v)
    __asm__("__sync_fetch_and_nand_2");
uint16_t legacy_sync_fetch_and_nand_2(volatile uint16_t *p, uint16_t v)
{
    uint16_t old = *p;
    *p = (uint16_t)~(old & v);
    return old;
}

uint32_t legacy_sync_fetch_and_nand_4(volatile uint32_t *p, uint32_t v)
    __asm__("__sync_fetch_and_nand_4");
uint32_t legacy_sync_fetch_and_nand_4(volatile uint32_t *p, uint32_t v)
{
    uint32_t old = *p;
    *p = ~(old & v);
    return old;
}

DEFINE_SYNC_FETCH_AND_UMIN(1, uint8_t)
DEFINE_SYNC_FETCH_AND_UMIN(2, uint16_t)
DEFINE_SYNC_FETCH_AND_UMIN(4, uint32_t)
DEFINE_SYNC_FETCH_AND_UMAX(1, uint8_t)
DEFINE_SYNC_FETCH_AND_UMAX(2, uint16_t)
DEFINE_SYNC_FETCH_AND_UMAX(4, uint32_t)

DEFINE_SYNC_VAL_CAS(1, uint8_t)
DEFINE_SYNC_VAL_CAS(2, uint16_t)
DEFINE_SYNC_VAL_CAS(4, uint32_t)

void legacy_sync_synchronize(void) __asm__("__sync_synchronize");
void legacy_sync_synchronize(void)
{
}
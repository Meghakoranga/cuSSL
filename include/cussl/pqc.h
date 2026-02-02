#ifndef CUPQC_SHIM_H
#define CUPQC_SHIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 1. Key Generation
// Returns 1 on success, 0 on failure
int cupqc_shim_keygen_768(uint8_t *pk, uint8_t *sk);

// 2. Encapsulation
int cupqc_shim_encaps_768(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

// 3. Decapsulation
int cupqc_shim_decaps_768(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif

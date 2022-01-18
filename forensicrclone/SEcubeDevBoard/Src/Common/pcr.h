#pragma once
/*  LICENSE  */

/**
 * @file pcr.h
 * @date 2021
 * @brief This file includes the definition of return values, constant parameters, and public functions used to implement pcr algorithms.
 *
 */
//frclone
#include "se3_security_core.h"
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef __cplusplus
extern "C" {
#endif


/** \defgroup ChaCha20Poly1305 return values
 * @{
 */
/** \name ChaCha20Poly1305 return values */
///@{
#define MV_PCR_RES_OK                                    ( 0)
#define MV_PCR_RES_INVALID_CONTEXT                       (-1)
#define MV_PCR_RES_CANNOT_ALLOCATE_CONTEXT               (-2)
#define MV_PCR_RES_INVALID_KEY_SIZE                      (-3)
#define MV_PCR_RES_INVALID_ARGUMENT                      (-4)
#define MV_PCR_RES_INVALID_MODE                          (-5)
///@}
/** @} */

/** \defgroup Oath2 access token baking - pcr extension part
 * @{
 */
/** \name Oath2 access token baking  - pcr extension part */
///@{
#define MV_PCRSIZE 32

/**
 *
* @brief Extend PCR - flashkey number PCR_ID
* @param datain_len - length of data to hash and extend
* @param datain - data to hash and extend
* @param flashkey_pcr - BEFORE: pointer to pcr old value; AFTER: PCR new value = Digest of (PCR old value || data to extend)
* @return See \ref Return .
*/
int32_t    MV_PCR_Extend  (const uint16_t datain_len, const uint8_t* datain, se3_flash_key *flashkey_pcr);

#ifdef __cplusplus
}
#endif

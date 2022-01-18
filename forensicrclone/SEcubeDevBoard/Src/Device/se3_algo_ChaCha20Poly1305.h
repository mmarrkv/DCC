/**
 *  \file se3_algo_ChaCha20Poly1305.h
 *  \author Mark Vella
 *  \brief SE3_ALGO_ChaCha20Poly1305 crypto handlers
 */

//frclone
#pragma once
#include "se3_security_core.h"

/** \brief MV_ALGO_ChaCha20Poly1305 init handler
 *  
 *  Supported modes
 *  Any combination of one of {SE3_DIR_ENCRYPT, SE3_DIR_DECRYPT} possible composed with SE3_FEEDBACK_DOBAKE
 *  
 *  Supported key sizes
 *  256-bit
 */
uint16_t mv_algo_ChaCha20Poly1305_init(
    se3_flash_key* key, uint16_t mode, uint8_t* ctx);


/** \brief MV_ALGO_ChaCha20Poly1305 update handler
 *
 *  Supported operations
 *  (default): encrypt/decrypt datain2. Not executed
 *    if datain2 is empty (zero-length)
 *  SE3_CRYPTO_FLAG_SETIV: set new IV from datain1
 *  SE3_CRYPTO_FLAG_FINIT: release session
 *
 *  Combined operations are executed in the following order:
 *    SE3_CRYPTO_FLAG_SETIV
 *    (default)
 *    SE3_CRYPTO_FLAG_FINIT
 *
 *  Contribution of each operation to the output size:
 *    (default): + datain2_len + len(Authorization HTTP header) if SE3_FEEDBACK_DOBAKE is set
 *    Others: + 0
 */
uint16_t mv_algo_ChaCha20Poly1305_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout);

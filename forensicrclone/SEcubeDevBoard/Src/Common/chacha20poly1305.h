#pragma once
/*  LICENSE  */

/**
 * @file chacha20poly1305.h
 * @date 2021
 * @brief This file includes the definition of return values, constant parameters, and public functions used to implement ChaCha20Poly1305 algorithms.
 *
 */
//frclone
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#ifdef __cplusplus
extern "C" {
#endif


/** \defgroup ChaCha20Poly1305 return values
 * @{
 */
/** \name ChaCha20Poly1305 return values */
///@{
#define MV_CHACHA20POLY1305_RES_OK                                    ( 0)
#define MV_CHACHA20POLY1305_RES_INVALID_CONTEXT                       (-1)
#define MV_CHACHA20POLY1305_RES_CANNOT_ALLOCATE_CONTEXT               (-2)
#define MV_CHACHA20POLY1305_RES_INVALID_KEY_SIZE                      (-3)
#define MV_CHACHA20POLY1305_RES_INVALID_ARGUMENT                      (-4)
#define MV_CHACHA20POLY1305_RES_INVALID_MODE                          (-5)
///@}
/** @} */

/** \defgroup ChaCha20Poly1305 Key, IV, Block Sizes
 * @{
 */
/** \name CHACHA20 Key, IV, MAC Sizes */
///@{
// Ref to https://datatracker.ietf.org/doc/html/rfc7539#section-2.8
#define MV_CHACHA20POLY1305_KEY_256          32  /**< Key Size in Bytes. */
#define MV_CHACHA20POLY1305_IV_SIZE          12  /**< IV Size in Bytes. */
#define MV_CHACHA20POLY1305_MAC_SIZE         16  /**< MAC Size in Bytes. */
///@}
/** @} */


/** \defgroup Oath2 access token baking
 * @{
 */
/** \name Oath2 access token baking */
///@{

// Google implementation maximum (RFC does not define any maximum)
#define MV_ACCTOKENSIZEMAX 2048
#define MV_RFRSHTOKENSIZEMAX 512


//CHAPOLY custom modes
enum {
    MV_CHACHA20POLY1305_ENC = 1,
    MV_CHACHA20POLY1305_DOBAKE_ENC = 2, /**Payload to be encrypted is an HTTP request requiring an access token header line to be baked in prior to encyrption */
    MV_CHACHA20POLY1305_DEC = 3,
    MV_CHACHA20POLY1305_DOBAKE_DEC = 4, /**Payload to be decrypted is an HTTP response and which may contain a refresh token response, in which case it has to be replaced by its corresponding placeholder, and the access/refresh tokens updated accordingly */
    MV_CHACHA20POLY1305_GETPCR = 5 /**Read extended pcr value from secube */
};

enum{
    ACC_TKN_PLCHLDR_ID = 5,
    RFRSH_TKN_PLCHLDR_ID = 6,
    ACC_TKN_ID = 7,
    RFRSH_TKN_ID = 8,
    PCR_ID = 9
};
///@}
/** @} */




/** \defgroup ChaCha20Poly1305 data structures
 * @{
 */
/** \name ChaCha20Poly1305 data structures */
///@{
typedef struct {
    ChaChaPoly_Aead aead;
    uint8_t  Key[MV_CHACHA20POLY1305_KEY_256];               /**< Key */
    uint8_t  InitVector[MV_CHACHA20POLY1305_IV_SIZE];       /**< IV  */
    uint8_t  mode;                 /**< Active mode ENC/ENC+DOBAKE/DEC */
} MV_tChaCha20Poly1305Ctx;
///@}
/** @} */


/** \defgroup ChaCha20Poly1305 functions
 * @{
 */
/** \name ChaCha20Poly1305 functions */
///@{

/**
 *
 * @brief Initialize the ChaCha20Poly1305 context.
 * @param ctx Pointer to the ChaCha20Poly1305 data structure to be initialized.
 * @param Key Pointer to the Key that must be used for encryption/decryption.
 * @param Mode Chacha20poly13056 mode.
 * @return See \ref Return .
 */
int32_t    MV_ChaCha20Poly1305_Init   (MV_tChaCha20Poly1305Ctx *ctx, const uint8_t *Key, uint8_t mode);

/**
 *
 * @brief Set the IV for the current ChaCha20Poly1305 context.
 * @param ctx Pointer to the ChaCha20Poly1305 data structure to be initialized.
 * @param IV Pointer to the IV.
 * @return See \ref Return .
 */
int32_t    MV_ChaCha20Poly1305_SetIV  (MV_tChaCha20Poly1305Ctx *ctx, const uint8_t *IV);

/**
 *
 * @brief Set the IV for the current ChaCha20Poly1305 context.
 * @param ctx Pointer to the ChaCha20Poly1305 data structure to be initialized.
 * @param AAD Pointer to the AAD.
 * @param nSize bytes to process.
 * @return See \ref Return .
 */
int32_t    MV_ChaCha20Poly1305_SetAAD  (MV_tChaCha20Poly1305Ctx *ctx, const uint8_t *AAD, uint16_t nSize);

/**
 *
 * @brief Encrypt/Decrypt data based on the status of current ChaCha20Poly1305 context.
 * @param ctx Pointer to the current ChaCha20Poly1305 context.
 * @param encData Encrypted data.
 * @param clrData Clear data.
 * @param nSize in bytes to process.
 * @return See \ref Return .
 */
int32_t    MV_ChaCha20Poly1305_Update (MV_tChaCha20Poly1305Ctx *ctx, uint8_t *encData, uint8_t *clrData, uint16_t nSize, uint16_t *outSize);

/**
 *
 * @brief De-initialize the current ChaCha20Poly1305 context.
 * @param ctx Pointer to the ChaCha20Poly1305 context to de-initialize.
 *  @param outAuthTag Computed Final Authentication Tag.
 * @return See \ref Return .
 */
int32_t    MV_ChaCha20Poly1305_Finit  (MV_tChaCha20Poly1305Ctx *ctx, uint8_t *outData, uint16_t *outSize);
    
///@}
/** @} */

#ifdef __cplusplus
}
#endif

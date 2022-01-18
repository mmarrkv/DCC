/*  LICENSE  */

//frclone
/**
 * @file chacha20poly1305.c
 * @date 2021
 * @brief This file includes the implementation of the functions for computing the ChaCha20Poly1305 algorithm..
 *
 */

#include "chacha20poly1305.h"

int32_t MV_ChaCha20Poly1305_Init (MV_tChaCha20Poly1305Ctx *ctx, const uint8_t *Key, uint8_t mode)
{
    if(Key == NULL)
        return MV_CHACHA20POLY1305_RES_INVALID_ARGUMENT;
    
    if(ctx == NULL)
        return  MV_CHACHA20POLY1305_RES_INVALID_CONTEXT;
    
    memset(ctx, 0, sizeof(MV_tChaCha20Poly1305Ctx));
    
    if ((mode < MV_CHACHA20POLY1305_ENC) || (mode > MV_CHACHA20POLY1305_GETPCR ))
        return MV_CHACHA20POLY1305_RES_INVALID_MODE;


    ctx->mode = mode;
    memcpy(ctx->Key, Key, MV_CHACHA20POLY1305_KEY_256);

    //dummy initialize - IV initialized by SetIV (next)
    memset(ctx->InitVector, 0x55, MV_CHACHA20POLY1305_IV_SIZE);

    //We cannot call wc_ChaCha20Poly1305_Init() as of now since SE3 L1 API is designed in a manner to accept a VI only on update
    //Rather, we call in update MV_ChaCha20Poly1305_Update based on (ctx->aead).state
    //However we initialize ctx->aead to zero
    memset(&(ctx->aead), 0x00, sizeof(ctx->aead));

    return MV_CHACHA20POLY1305_RES_OK;
}



int32_t    MV_ChaCha20Poly1305_SetIV  (MV_tChaCha20Poly1305Ctx *ctx, const uint8_t *IV)
{
    if(ctx == NULL)
        return  MV_CHACHA20POLY1305_RES_INVALID_CONTEXT;

    if(IV == NULL) 
        return MV_CHACHA20POLY1305_RES_INVALID_ARGUMENT;
    
    
    if ( (ctx->mode != MV_CHACHA20POLY1305_ENC) && (ctx->mode != MV_CHACHA20POLY1305_DOBAKE_ENC) && (ctx->mode != MV_CHACHA20POLY1305_DEC) && (ctx->mode != MV_CHACHA20POLY1305_DOBAKE_DEC)  )
        return MV_CHACHA20POLY1305_RES_INVALID_MODE;


    memcpy(ctx->InitVector, IV, MV_CHACHA20POLY1305_IV_SIZE);

    // Now initialize
    //This check is intended to avoid errors in case cipher in re-inited a 2nd time
    if( (ctx->aead).state ==  CHACHA20_POLY1305_STATE_INIT )
    {
        wc_ChaCha20Poly1305_Init(&(ctx->aead),ctx->Key,ctx->InitVector,(ctx->mode == MV_CHACHA20POLY1305_ENC || ctx->mode == MV_CHACHA20POLY1305_DOBAKE_ENC) ? CHACHA20_POLY1305_AEAD_ENCRYPT: CHACHA20_POLY1305_AEAD_DECRYPT);
    }

    return MV_CHACHA20POLY1305_RES_OK;
}

int32_t    MV_ChaCha20Poly1305_SetAAD  (MV_tChaCha20Poly1305Ctx *ctx, const uint8_t *AAD, uint16_t nSize)
{

    int err;

    if(ctx == NULL)
        return  MV_CHACHA20POLY1305_RES_INVALID_CONTEXT;

    if(AAD == NULL)
        return MV_CHACHA20POLY1305_RES_INVALID_ARGUMENT;

    err = wc_ChaCha20Poly1305_UpdateAad(&(ctx->aead), AAD, nSize);

    if(err)
    {
        return MV_CHACHA20POLY1305_RES_INVALID_MODE;
    }

    return MV_CHACHA20POLY1305_RES_OK;
}


int32_t    MV_ChaCha20Poly1305_Update (MV_tChaCha20Poly1305Ctx *ctx, uint8_t *encData, uint8_t *clrData, uint16_t nSize, uint16_t *outSize)
{
    //local vars go here
    //uint8_t mode;
    int err;
    //byte myOutAuthTag[MV_CHACHA20POLY1305_MAC_SIZE];

    //const byte aad1[] = { 0x00 };

    if(ctx == NULL)
        return  MV_CHACHA20POLY1305_RES_INVALID_CONTEXT;
    
    
    if((encData == NULL) || (clrData == NULL) || (nSize <= 0))
        return MV_CHACHA20POLY1305_RES_INVALID_ARGUMENT;


        switch(ctx->mode) {

        case MV_CHACHA20POLY1305_ENC:
        case MV_CHACHA20POLY1305_DOBAKE_ENC:
        {
            //stub
            //memcpy(encData,(void *)"CHACHACIPHERTEXT",17);
            //*outSize = 17;

            //stub
            //memcpy(encData,(void *)"CHACHACIPHERTEXTWITHBAKE",24);
            //*outSize = 25;
            //break;

            /***
            err = wc_ChaCha20Poly1305_Encrypt(ctx->Key, ctx->InitVector,
                                              aad1, 0,
                                              clrData, nSize,
                                              encData, myOutAuthTag);

            memcpy(encData + nSize, myOutAuthTag, MV_CHACHA20POLY1305_MAC_SIZE);
            *outSize = nSize+MV_CHACHA20POLY1305_MAC_SIZE;
             ***/

            err = wc_ChaCha20Poly1305_UpdateData( &(ctx->aead), clrData,
                                                 encData, nSize);
            *outSize = nSize;

            if(err)
            {
                return MV_CHACHA20POLY1305_RES_INVALID_MODE;
            }

            break;
        }

        case MV_CHACHA20POLY1305_DEC:
        case MV_CHACHA20POLY1305_DOBAKE_DEC:
        {
            //stub
            //memcpy(clrData,(void *)"CHACHAPLAINTEXT",15);
            //*outSize = 15;

            /***
            memcpy(myOutAuthTag,encData+nSize-MV_CHACHA20POLY1305_MAC_SIZE,MV_CHACHA20POLY1305_MAC_SIZE);
            err = wc_ChaCha20Poly1305_Decrypt(ctx->Key, ctx->InitVector,
                                              aad1, 0,
                                              encData, nSize-MV_CHACHA20POLY1305_MAC_SIZE,
                                              myOutAuthTag, clrData);

            *outSize = nSize-MV_CHACHA20POLY1305_MAC_SIZE;
             ***/

            err = wc_ChaCha20Poly1305_UpdateData( &(ctx->aead), encData,
                                                  clrData, nSize);
            *outSize = nSize;

            if(err)
            {
                return MV_CHACHA20POLY1305_RES_INVALID_MODE;
            }

            break;
        }

        default:
        {
            return MV_CHACHA20POLY1305_RES_INVALID_MODE;
        }
        
    }
    
    
    return MV_CHACHA20POLY1305_RES_OK;
}




int32_t  MV_ChaCha20Poly1305_Finit  (MV_tChaCha20Poly1305Ctx *ctx, uint8_t *outData, uint16_t *outSize)
{
    int err;
    byte generatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    err = wc_ChaCha20Poly1305_Final( &(ctx->aead), generatedAuthTag);

    if(err)
    {
        return MV_CHACHA20POLY1305_RES_INVALID_MODE;
    }

    memcpy(outData+*outSize,generatedAuthTag, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    *outSize += CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;

    return MV_CHACHA20POLY1305_RES_OK;
}




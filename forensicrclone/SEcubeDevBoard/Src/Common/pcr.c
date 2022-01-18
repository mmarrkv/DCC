//frclone
/**
 * @file pcr.c
 * @date 2021
 * @brief This file includes the implementation of the functions for computing the pcr algorithms.
 *
 */

#include "pcr.h"

int32_t MV_PCR_Extend  (const uint16_t datain_len, const uint8_t* datain, se3_flash_key *flashkey_pcr)
{
    wc_Sha3  sha;
    byte  hash[WC_SHA3_256_DIGEST_SIZE];
    byte  hashcopy[WC_SHA3_256_DIGEST_SIZE];
    int ret;
    static int devId = INVALID_DEVID;
    se3_flash_it it;

    //init hash
    ret = wc_InitSha3_256(&sha, NULL, devId);
    if (ret != 0)
        return MV_PCR_RES_INVALID_MODE;

    // pass in pcr bytes
    ret = wc_Sha3_256_Update(&sha, (byte*)flashkey_pcr->data,
                             (word32)MV_PCRSIZE);
    if (ret != 0)
        return MV_PCR_RES_INVALID_MODE;

    //pass in datain bytes
    ret = wc_Sha3_256_Update(&sha, (byte*)datain,
                             (word32)datain_len);
    if (ret != 0)
        return MV_PCR_RES_INVALID_MODE;


    //gethash
    ret = wc_Sha3_256_GetHash(&sha, hashcopy);
    if (ret != 0)
        return MV_PCR_RES_INVALID_MODE;

    ret = wc_Sha3_256_Final(&sha, hash);
    if (ret != 0)
        return MV_PCR_RES_INVALID_MODE;

    //update pcr in memory
    memcpy(flashkey_pcr->data, hash, MV_PCRSIZE);

    //copy pcr to flash: findkey + write
    se3_flash_it_init(&it);
    if( !( se3_key_find(PCR_ID, &it) ) )
    {
        return SE3_ERR_RESOURCE;
    }

    if (!se3_flash_it_delete(&it)) {
        return SE3_ERR_HW;
    }
    it.addr = NULL;
    if (!se3_key_new(&it, flashkey_pcr)) {
        return SE3_ERR_MEMORY;
    }


    return MV_PCR_RES_OK;
}


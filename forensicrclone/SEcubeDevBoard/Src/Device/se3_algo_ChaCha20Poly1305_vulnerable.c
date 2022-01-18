/**
 *  \file se3_algo_ChaCha20Poly1305.h
 *  \author Mark Vella
 *  \brief SE3_ALGO_ChaCha20Poly1305 crypto handlers
 */

//frclone
#include "se3_algo_ChaCha20Poly1305.h"

//access/refresh token find+replace
uint8_t acc_tkn_plchldr[MV_ACCTOKENSIZEMAX];
uint8_t acc_tkn[MV_ACCTOKENSIZEMAX];
uint8_t acc_tkn_name[32];
uint8_t rfrsh_tkn_plchldr[MV_RFRSHTOKENSIZEMAX];
uint8_t rfrsh_tkn[MV_RFRSHTOKENSIZEMAX];
uint8_t rfrsh_tkn_name[32];
uint8_t pcr[MV_PCRSIZE];
uint8_t pcrname[32];

//https://github.com/antirez/hping/blob/master/memstr.c
static uint8_t *memstr(uint8_t *haystack, uint8_t *needle, uint16_t haystacksize, uint16_t needlesize)
{
    uint8_t *p;

    for (p = haystack; p <= (haystack-needlesize+haystacksize); p++)
    {
        if (memcmp(p, needle, needlesize) == 0)
            return p; /* found */
    }
    return NULL;
}


uint16_t mv_algo_ChaCha20Poly1305_init(
    se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    MV_tChaCha20Poly1305Ctx *chacha = (MV_tChaCha20Poly1305Ctx *) ctx;

    uint16_t feedback = mode & 0x07;
    uint16_t direction = (mode & SE3_DIR_ENCRYPT) ? SE3_DIR_ENCRYPT : SE3_DIR_DECRYPT;
    uint8_t mv_mode;


    if (key->data_size != MV_CHACHA20POLY1305_KEY_256) {
        // unsupported key size
        return SE3_ERR_PARAMS;
    }

    switch (direction) {
        case (SE3_DIR_ENCRYPT):
            switch (feedback) {
                case SE3_FEEDBACK_DOBAKE:
                    mv_mode = MV_CHACHA20POLY1305_DOBAKE_ENC;
                    break;
                case SE3_FEEDBACK_DONOTBAKE:
                    mv_mode = MV_CHACHA20POLY1305_ENC;
                    break;
                case SE3_FEEDBACK_GETPCR:
                    mv_mode = MV_CHACHA20POLY1305_GETPCR;
                    break;
                default:
                    return SE3_ERR_PARAMS;
            }
            break;
        case (SE3_DIR_DECRYPT):
            mv_mode = MV_CHACHA20POLY1305_DEC;
            if(feedback == SE3_FEEDBACK_DOBAKE) {
                mv_mode = MV_CHACHA20POLY1305_DOBAKE_DEC;
            }
            break;
        default:
            return SE3_ERR_PARAMS;
    }

    if (MV_CHACHA20POLY1305_RES_OK != MV_ChaCha20Poly1305_Init(chacha, key->data, (uint8_t) mv_mode)) {
        SE3_TRACE(("[chacha20poly1305.init] failed\n"));
        return SE3_ERR_PARAMS;
    }

	
    return SE3_OK;
}

uint16_t mv_algo_ChaCha20Poly1305_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout)
{
    MV_tChaCha20Poly1305Ctx* chacha = (MV_tChaCha20Poly1305Ctx*)ctx;
    //size_t nblocks = 0;
    uint8_t* data_enc, *data_dec;
    bool do_setiv = false;
    bool do_setaad = false;
    bool do_update = false;
    bool do_finit = false;

	do_setiv = flags & SE3_CRYPTO_FLAG_SETIV;
    do_setaad = flags & SE3_CRYPTO_FLAG_SETAAD;
	do_update = datain2_len > 0;
	do_finit = flags & SE3_CRYPTO_FLAG_FINIT;


	//stub access token
	//uint8_t acc_tkn_stub[12] = {'M','V','_','A','C','C','_','T','O','K','E','N'};
	//uint8_t *acc_tkn_start;

	//flash memory reading
    se3_flash_it it;
    se3_flash_key flashkey_acc_tkn_plchldr, flashkey_acc_tkn, flashkey_rfrsh_tkn_plchldr, flashkey_rfrsh_tkn, flashkey_pcr;

    //datascans
    uint8_t *search_ptr;
    uint16_t needlesize;

    // check params
	if (do_setiv && (datain1_len != MV_CHACHA20POLY1305_IV_SIZE)) {
		SE3_TRACE(("[chacha20poly1305.update] invalid IV size\n"));
		return SE3_ERR_PARAMS;
	}
    if (do_update) {
        if (datain2_len < 1) {
            SE3_TRACE(("[chacha20poly1305.update] no data to process\n"));
            return SE3_ERR_PARAMS;
        }
    }


    if (do_setiv && chacha->mode!= MV_CHACHA20POLY1305_GETPCR ) {
        // set IV
        if (MV_CHACHA20POLY1305_RES_OK  !=  MV_ChaCha20Poly1305_SetIV (chacha, datain1)) {
            SE3_TRACE(("[algo_chacha.update] SetIV failed\n"));
            return SE3_ERR_HW;
        }
    }

    if (do_setaad && chacha->mode!= MV_CHACHA20POLY1305_GETPCR) {
        // set AAD
        if (MV_CHACHA20POLY1305_RES_OK  !=  MV_ChaCha20Poly1305_SetAAD (chacha, datain1, datain1_len)) {
            SE3_TRACE(("[algo_chacha.update] SetAAD failed\n"));
            return SE3_ERR_HW;
        }
    }


    if (do_update) {
        // update

        //always (during update) get pcr + tokens -
        // favoring robustness, just in case memory gets corrupted for some reason
        // rather than efficiency
        se3_flash_it_init(&it);
        if( !( se3_key_find(PCR_ID, &it) ) )
        {
            return SE3_ERR_RESOURCE;
        }
        flashkey_pcr.data = pcr;
        flashkey_pcr.name = pcrname;
        flashkey_pcr.id=PCR_ID;
        se3_key_read(&it, &flashkey_pcr);

        se3_flash_it_init(&it);
        if( !( se3_key_find(ACC_TKN_PLCHLDR_ID, &it) ) )
        {
            return SE3_ERR_RESOURCE;
        }
        flashkey_acc_tkn_plchldr.data = acc_tkn_plchldr;
        flashkey_acc_tkn_plchldr.name = NULL;
        flashkey_acc_tkn_plchldr.id=ACC_TKN_PLCHLDR_ID;
        se3_key_read(&it, &flashkey_acc_tkn_plchldr);

        se3_flash_it_init(&it);
        if( !( se3_key_find(ACC_TKN_ID, &it) ) )
        {
            return SE3_ERR_RESOURCE;
        }
        flashkey_acc_tkn.data = acc_tkn;
        flashkey_acc_tkn.name = acc_tkn_name;
        flashkey_acc_tkn.id=ACC_TKN_ID;
        se3_key_read(&it, &flashkey_acc_tkn);

        se3_flash_it_init(&it);
        if( !( se3_key_find(RFRSH_TKN_PLCHLDR_ID, &it) ) )
        {
            return SE3_ERR_RESOURCE;
        }
        flashkey_rfrsh_tkn_plchldr.data = rfrsh_tkn_plchldr;
        flashkey_rfrsh_tkn_plchldr.name = NULL;
        flashkey_rfrsh_tkn_plchldr.id=RFRSH_TKN_PLCHLDR_ID;
        se3_key_read(&it, &flashkey_rfrsh_tkn_plchldr);

        se3_flash_it_init(&it);
        if( !( se3_key_find(RFRSH_TKN_ID, &it) ) )
        {
            return SE3_ERR_RESOURCE;
        }
        flashkey_rfrsh_tkn.data = rfrsh_tkn;
        flashkey_rfrsh_tkn.name = rfrsh_tkn_name;
        flashkey_rfrsh_tkn.id=RFRSH_TKN_ID;
        se3_key_read(&it, &flashkey_rfrsh_tkn);

        switch (chacha->mode) {
        case MV_CHACHA20POLY1305_GETPCR:
            memcpy(dataout,pcr, MV_PCRSIZE);
            *dataout_len = MV_PCRSIZE;
            return SE3_OK;
        case MV_CHACHA20POLY1305_DEC:
        case MV_CHACHA20POLY1305_DOBAKE_DEC:
            data_enc = (uint8_t*)datain2;
            data_dec = dataout;
            break;
        case MV_CHACHA20POLY1305_ENC:
            data_enc = dataout;
            data_dec = (uint8_t*)datain2;
            break;
        case MV_CHACHA20POLY1305_DOBAKE_ENC:
            data_enc = dataout;
            data_dec = (uint8_t*)datain2;


            //STUB append acc_tkn
            //acc_tkn_start = (uint8_t*) datain2;
            //acc_tkn_start += datain2_len;
            //memcpy(acc_tkn_start,acc_tkn_stub,MV_ACCTOKENSIZE);
            //datain2_len +=MV_ACCTOKENSIZE;


            // Extend PCR on the unmodified request - otherwise verification cannot take place
            MV_PCR_Extend(datain2_len, datain2, &flashkey_pcr);

            //NOTE: ASSUMING SAME-LENGTH SUBSTITUTION + SINGLE OCCURRENCE
            //NOTE: ASSUMING THAT BLOCK SIZE IS LARGE ENOUGH TO STORE AN ENTIRE HTTP HEADER ie token is not split!!!
            // scan datain2
            //search for access/refresh placeholders
            //if access token placeholder found - replace by stored access token
            //else - if refresh token placeholder found - replace by stored refresh token
            if((search_ptr = memstr(data_dec, flashkey_acc_tkn_plchldr.data,datain2_len, flashkey_acc_tkn_plchldr.data_size)))
            {
                memcpy(search_ptr,flashkey_acc_tkn.data, flashkey_acc_tkn.data_size);
            } else if((search_ptr = memstr(data_dec, flashkey_rfrsh_tkn_plchldr.data,datain2_len, flashkey_rfrsh_tkn_plchldr.data_size)))
            {
                memcpy(search_ptr,flashkey_rfrsh_tkn.data, flashkey_rfrsh_tkn.data_size);
            }

            break;
        default:
            data_enc = dataout;
            data_dec = (uint8_t*)datain2;
            break;
        }

        if (MV_CHACHA20POLY1305_RES_OK != MV_ChaCha20Poly1305_Update(chacha, data_enc, data_dec, datain2_len, dataout_len)) {
            SE3_TRACE(("[algo_chacha.update] update failed\n"));
            return SE3_ERR_HW;
        }

        //When decrypting (with DOBAKE) we need to search+replace+update_store for access/refresh tokens
        // ASSUMING same length tokens being generated by google authentication server
        if(chacha->mode == MV_CHACHA20POLY1305_DOBAKE_DEC)
        {
            //Search for "access_token": "
            //If found: forward strlen("\"access_token": \"")
            //Copy value from response to memory buffer (as per current token length)
            //Write to flash memory at the proper position
            //Replace by token holder
            needlesize = strlen("\"access_token\": \"");
            if((search_ptr = memstr(data_dec, (uint8_t *) "\"access_token\": \"" ,*dataout_len, needlesize)))
            {
                search_ptr+=needlesize;
                memcpy(acc_tkn, search_ptr, flashkey_acc_tkn.data_size);
                memcpy(search_ptr, acc_tkn_plchldr, flashkey_acc_tkn_plchldr.data_size);

                se3_flash_it_init(&it);
                if( !( se3_key_find(ACC_TKN_ID, &it) ) )
                {
                    return SE3_ERR_RESOURCE;
                }

                if (!se3_flash_it_delete(&it)) {
                    return SE3_ERR_HW;
                }
                it.addr = NULL;
                if (!se3_key_new(&it, &flashkey_acc_tkn)) {
                    return SE3_ERR_MEMORY;
                }
            }

            //Repeat the entire procedure above, this time for the refresh token
            needlesize = strlen("\"refresh_token\": \"");
            if((search_ptr = memstr(data_dec, (uint8_t *) "\"refresh_token\": \"" , *dataout_len, needlesize)))
            {
                search_ptr+=needlesize;
                memcpy(rfrsh_tkn, search_ptr, flashkey_rfrsh_tkn.data_size);
                memcpy(search_ptr, rfrsh_tkn_plchldr, flashkey_rfrsh_tkn_plchldr.data_size);

                se3_flash_it_init(&it);
                if( !( se3_key_find(RFRSH_TKN_ID, &it) ) )
                {
                    return SE3_ERR_RESOURCE;
                }

                if (!se3_flash_it_delete(&it)) {
                    return SE3_ERR_HW;
                }
                it.addr = NULL;
                if (!se3_key_new(&it, &flashkey_rfrsh_tkn)) {
                    return SE3_ERR_MEMORY;
                }
            }

        }

    }

    if (do_finit) {
        if (MV_CHACHA20POLY1305_RES_OK != MV_ChaCha20Poly1305_Finit(chacha, dataout, dataout_len)) {
            SE3_TRACE(("[algo_chacha.update] finit failed\n"));
            return SE3_ERR_HW;
        }
    }

    return SE3_OK;
}

#include "se3_sekey.h"
#include "se3_keys.h"
#include "se3_dispatcher_core.h" // required for login_struct

/*	sekey_get_implementation_info: This function would be the core of the SEkey behaviour,
 * 	it has to be implemented. The provided code is just a stub
 */

se3_flash_it key_iterator = { .addr = NULL }; /**< Global variable required by load_key_ids() */

bool sekey_get_implementation_info(uint8_t* algo_implementation, uint8_t* crypto_algo, uint8_t *key){
	if (sekey_get_auth(key)){
		*algo_implementation = SE3_SECURITY_CORE;
		*crypto_algo = SE3_AES256;
	}
	return true;
}

bool sekey_get_auth(uint8_t *key){
	return true;
}

uint16_t store_user_info(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint8_t userid_len, username_len, offset = 0;
	const uint8_t *userid;
	const uint8_t *username;
    se3_flash_it it = { .addr = NULL };
    uint16_t size = 0;
    *resp_size = 0;
	if(login_struct.access != SE3_ACCESS_ADMIN){
		return SE3_ERR_ACCESS;
	}
	userid_len = req[offset];
	offset++;
	userid = (req)+offset;
	offset+=userid_len;
	username_len = req[offset];
	offset++;
	username = (req)+offset;
	if(login_struct.access != SE3_ACCESS_ADMIN){
		return SE3_ERR_ACCESS;
	}
	if((req_size-2) != (userid_len+username_len+2)){ // +2 for id len and name len, -2 for operation choice
		return SE3_ERR_RESOURCE;
	}
	// delete all nodes in the flash of type userinfo
	se3_flash_it_init(&it);
	while (se3_flash_it_next(&it)){
		if (it.type == SE3_TYPE_USERINFO){
			if (!se3_flash_it_delete(&it)) {
				return SE3_ERR_HW;
			}
		}
	}
	se3_flash_it_init(&it);
	// 1B id length, id, 1B name length, name
	size = userid_len + username_len + 2;
	if (size > SE3_FLASH_NODE_DATA_MAX) {
		return SE3_ERR_MEMORY;
	}

	if (!se3_flash_it_new(&it, SE3_TYPE_USERINFO, size)) {
		return SE3_ERR_MEMORY;
	}
	offset = 0;
	if(!se3_flash_it_write(&it, offset, &userid_len, 1)) {
		return SE3_ERR_HW;
	}
	offset++;
	if (!se3_flash_it_write(&it, offset, userid, userid_len)) {
		return SE3_ERR_HW;
	}
	offset+=userid_len;
	if(!se3_flash_it_write(&it, offset, &username_len, 1)) {
		return SE3_ERR_HW;
	}
	offset++;
	if (!se3_flash_it_write(&it, offset, username, username_len)) {
		return SE3_ERR_HW;
	}
	*resp_size = 8;
	memcpy(resp, "SEKEY_OK", 8);
	return SE3_OK;
}

uint16_t load_user_info(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint8_t userid_len, username_len, offset, counter = 0, total = 0;
	se3_flash_it it = { .addr = NULL };
	uint8_t *tmp = NULL;
	se3_flash_it_init(&it);
	*resp_size = 0;
	while(se3_flash_it_next(&it)){
		if(it.type == SE3_TYPE_USERINFO){
			if(counter != 0){
				if(tmp != NULL){
					free(tmp);
				}
				return SE3_ERR_RESOURCE;
			}
			counter++;
			offset = 0;
			memcpy(&userid_len, it.addr+offset, 1);
			offset++;
			offset+=userid_len;
			memcpy(&username_len, it.addr+offset, 1);
			total = userid_len + username_len + 2;
			if(tmp != NULL){
				free(tmp);
				tmp = NULL;
			}
			tmp = (uint8_t*)malloc(total*sizeof(uint8_t));
			if(tmp == NULL){
				return SE3_ERR_MEMORY;
			}
			memcpy(tmp, it.addr, total);
		}
	}
	if(counter != 1){
		if(tmp != NULL){
			free(tmp);
		}
		return SE3_ERR_RESOURCE;
	} else {
		if(tmp != NULL){
			memcpy(resp, tmp, total);
			*resp_size = total;
			free(tmp);
		}
		return SE3_OK;
	}
}

uint16_t load_encrypted_key_data(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint32_t key_to_load = 0, key_current = 0, wrapping_key = 0;
	uint16_t key_current_length = 0;
	uint8_t *keycontent = NULL;
	int counter = 0;
	se3_flash_it it = { .addr = NULL };
	if(login_struct.access != SE3_ACCESS_ADMIN){
		return SE3_ERR_ACCESS; // only admin can do this
	}
	if((req_size - 2) != 8){
		return SE3_ERR_PARAMS; // check if the request has the right size (do not consider OP code)
	}
	memcpy(&key_to_load, req, 4); // the ID of the key to be retrieved
	memcpy(&wrapping_key, req+4, 4); // the ID of the key to be used to wrap the desired key
	if(wrapping_key == 0){
		return SE3_ERR_PARAMS;
	}
	se3_flash_it_init(&it);
	*resp_size = 0;
	while (se3_flash_it_next(&it)) { // search the desired key
		/* warning: this implementation scans the entire flash memory searching for the key,
		 * therefore it is sub-optimal. to enhance the performance this can be modified returning
		 * as soon as the key is found...but this would not detect any duplicated key ID problem. */
		if (it.type == SE3_TYPE_KEY) {
			SE3_GET32(it.addr, SE3_FLASH_KEY_OFF_ID, key_current);
			if (key_current == key_to_load) {
				if(counter != 0){
					if(keycontent != NULL){
						free(keycontent);
					}
					return SE3_ERR_RESOURCE; // error, more than 1 key found with this ID
				}
				counter++;
				SE3_GET16(it.addr, SE3_FLASH_KEY_OFF_DATA_LEN, key_current_length);
				if(keycontent != NULL){
					free(keycontent);
					keycontent = NULL;
				}
				keycontent = (uint8_t*)malloc(key_current_length);
				if(keycontent == NULL){
					return SE3_ERR_MEMORY;
				}
				/* be careful about offsets: check how the data is written in se3_keys.c */
				memcpy(keycontent, it.addr+SE3_FLASH_KEY_OFF_NAME_AND_DATA, key_current_length);
			}
		}
	}
	if(counter != 1){ // key not found or duplicated
		if(keycontent != NULL){
			free(keycontent);
		}
		return SE3_ERR_RESOURCE;
	}
	/* encrypt the value of keycontent with the wrapping key */
	uint8_t request[2064], response[256]; // 2064 because cryptoinit needs a lot of space
	uint16_t response_size = 0;
	uint16_t algo = SE3_ALGO_AES;
	uint16_t mode = SE3_FEEDBACK_ECB | SE3_DIR_ENCRYPT;
	uint16_t flags = SE3_CRYPTO_FLAG_FINIT | SE3_FEEDBACK_ECB;
	uint16_t d1len = 0, d2len = key_current_length, enc_len = 0;
	uint32_t sessionId = SE3_SESSION_INVALID;
	memset(request, 0, 2064);
	memset(response, 0, 256);
	memcpy(request + SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO, &algo, 2);
	memcpy(request + SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE, &mode, 2);
	memcpy(request + SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID, &wrapping_key, 4);
	// here we internally call the cryptoinit and cryptoupdate as if they were called from the host side
	uint16_t rc = crypto_init(SE3_CMD1_CRYPTO_INIT_REQ_SIZE, request, &response_size, response);
	if((rc != SE3_OK) || (response_size != SE3_CMD1_CRYPTO_INIT_RESP_SIZE)){
		if(keycontent != NULL){
			free(keycontent);
		}
		return SE3_ERR_RESOURCE;
	}
	memcpy(&sessionId, response+SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, response_size);
	memset(request, 0, 2064);
	memset(response, 0, 256);
	memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_SID, &sessionId, 4);
	memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_FLAGS, &flags, 2);
	memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN1_LEN, &d1len, 2);
	memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN2_LEN, &d2len, 2);
	memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA, keycontent, d2len);
	rc = crypto_update(SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA, request, &response_size, response);
	if(rc != SE3_OK){
		if(keycontent != NULL){
			free(keycontent);
		}
		return SE3_ERR_RESOURCE;
	}
	memcpy(&enc_len, response+SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN, 2);
	if(enc_len != 32){
		if(keycontent != NULL){
			free(keycontent);
		}
		return SE3_ERR_RESOURCE;
	}
	uint8_t wrapped_key[32];
	memset(wrapped_key, 0, 32);
	memcpy(wrapped_key, response+SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA, enc_len);
	memcpy(resp, wrapped_key, enc_len);
	*resp_size = enc_len;
	if(keycontent != NULL){
		free(keycontent);
	}
	return SE3_OK;
}

uint16_t load_key_ids(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint32_t key_id = 0;
	uint16_t offset = 0;
	*resp_size = 0;
	do {
		/* 6000 is a limit to avoid writing too many data on the buffer (which is 8192B but we stay lower to avoid problems) */
		if(*resp_size >= 6000){
			return SE3_OK; // this is used only when we have to return more than 6000 bytes
		}
		if (key_iterator.addr != NULL && key_iterator.type == SE3_TYPE_KEY) {
			SE3_GET32(key_iterator.addr, SE3_FLASH_KEY_OFF_ID, key_id);
			memcpy(resp + offset, &key_id, 4);
			*resp_size = (*resp_size) + 4;
			offset += 4;
		}
	} while (se3_flash_it_next(&key_iterator));
	se3_flash_it_init(&key_iterator); // reset the iterator to the beginning of the flash (required for next call of load_key_ids)
	memset(resp + offset, 0, 4); // put all zeroes as the last id (id = 0 is not valid so the host side will understand that we reached the end of the flash)
	*resp_size = (*resp_size) + 4;
	return SE3_OK;
}

uint16_t delete_all_keys(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint32_t key_id = 0;
	bool error = false, skip = false;
	se3_flash_it it = { .addr = NULL };
	uint32_t tokeep = (req_size-2) / 4; // condition: each key ID is stored on 4 bytes
	uint32_t *keep = NULL;
	uint16_t offset = 0;
	*resp_size = 0;
	se3_flash_it_init(&it);
	if(((req_size-2) % 4) != 0){
		return SE3_ERR_PARAMS;
	}
	keep = (uint32_t*)malloc(tokeep * sizeof(uint32_t));
	if(keep == NULL){
		return SE3_ERR_MEMORY;
	}
	for(int i=0; i<tokeep; i++){
		memcpy(&keep[i], req+offset, 4);
		offset+=4;
	}
	while (se3_flash_it_next(&it)){
		if (it.type == SE3_TYPE_KEY){
			SE3_GET32(it.addr, SE3_FLASH_KEY_OFF_ID, key_id);
			/* delete all keys except keys specified by the host */
			for(int i=0; i<tokeep; i++){
				if(keep[i] == key_id){
					skip = true;
					break;
				}
			}
			if(skip){
				skip = false;
				continue;
			}
			if (!se3_flash_it_delete(&it)) {
				error = true;
			}
		}
	}
	if(keep != NULL){
		free(keep);
	}
	if(error){
		return SE3_ERR_RESOURCE;
	} else {
		memcpy(resp, "OK", 2);
		*resp_size = 2;
		return SE3_OK;
	}
}

uint16_t delete_key(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint32_t key_id = 0, kid = 0;
	bool error = false;
	se3_flash_it it = { .addr = NULL };
	*resp_size = 0;
	if((req_size - 2) != 4){
		return SE3_ERR_PARAMS;
	}
	memcpy(&kid, req, 4); // retrieve the key id from the input buffer
	se3_flash_it_init(&it);
	while (se3_flash_it_next(&it)){
		if (it.type == SE3_TYPE_KEY){
			SE3_GET32(it.addr, SE3_FLASH_KEY_OFF_ID, key_id);
			if(key_id == kid){
				if (!se3_flash_it_delete(&it)) {
					error = true;
				}
			}
		}
	}
	if(error){
		return SE3_ERR_RESOURCE;
	} else {
		memcpy(resp, "OK", 2);
		*resp_size = 2;
		return SE3_OK;
	}
	/* notice that if the key specified by the host is not found in the SEcube flash we simply return ok because
	 * in the end the goal is already reached, in fact we don't even have that key. */
}

uint16_t insert_key(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	uint32_t newID = 0, key_dec = 0; // key_dec is the id of the key to be used to decrypt the encrypted key sent as payload (=0 if key is not encrypted)
	uint16_t newLen = 0;
	uint8_t *keydata = NULL;
	const uint8_t *keyptr;
    se3_flash_key key;
    bool equal = false;
	se3_flash_it it = { .addr = NULL };
	*resp_size = 0;
	if((req_size-2) < 6){ // minimum size is 4B for ID and 2B for key length
		return SE3_ERR_PARAMS;
	}
	memcpy(&newID, req, 4); // retrieve key id
	memcpy(&newLen, req+4, 2); // retrieve key length
	keydata = (uint8_t*)malloc(newLen); // allocate space for the key content
	if(keydata == NULL){
		return SE3_ERR_MEMORY;
	}
	if((req_size-2) == 6){ // key must be generated internally
		/* The internal computation of the key is performed with the TRNG of the SEcube. This is sufficient to ensure a high enough entropy to the key value.
		 * For more informations about key generation details look at the NIST SP 800-13 Rev.1 (https://csrc.nist.gov/publications/detail/sp/800-133/rev-1/final),
		 * in particular Section 4 (option 1 from section 4 is used here). */
		if(se3_rand(newLen, keydata) != newLen){
			if(keydata != NULL){ free(keydata);	}
			return SE3_ERR_HW;
		}		
	} else { // the key is decided by the host (key_dec = 0 if key is plaintext, != 0 if key is encrypted)
		if((req_size-2) != (6+4+newLen)){ // 4B for ID, 2B for length, 1B for key data flag, 4 bytes for ID to decrypt encrypted key
			if(keydata != NULL){ free(keydata);	}
			return SE3_ERR_PARAMS;
		}
		memcpy(&key_dec, req+6, 4);
		keyptr = req+10;
		if(key_dec == 0){ // in this case the key was sent as plaintext
			memcpy(keydata, keyptr, newLen);
		} else { /* this means the key content must be decrypted before flashing */
			uint8_t request[2064], response[256]; // same as load_encrypted_key_data() but opposite direction
			uint16_t response_size = 0;
			uint16_t algo = SE3_ALGO_AES;
			uint16_t mode = SE3_FEEDBACK_ECB | SE3_DIR_DECRYPT;
			uint16_t flags = SE3_CRYPTO_FLAG_FINIT | SE3_FEEDBACK_ECB;
			uint16_t d1len = 0, d2len = newLen, dec_len = 0;
			uint32_t sessionId = SE3_SESSION_INVALID;
			memset(request, 0, 2064);
			memset(response, 0, 256);
			memcpy(request + SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO, &algo, 2);
			memcpy(request + SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE, &mode, 2);
			memcpy(request + SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID, &key_dec, 4);
			uint16_t rc = crypto_init(SE3_CMD1_CRYPTO_INIT_REQ_SIZE, request, &response_size, response);
			if((rc != SE3_OK) || (response_size != SE3_CMD1_CRYPTO_INIT_RESP_SIZE)){
				if(keydata != NULL){ free(keydata);	}
				return SE3_ERR_RESOURCE;
			}
			memcpy(&sessionId, response+SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, response_size);
			memset(request, 0, 2064);
			memset(response, 0, 256);
			memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_SID, &sessionId, 4);
			memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_FLAGS, &flags, 2);
			memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN1_LEN, &d1len, 2);
			memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN2_LEN, &d2len, 2);
			memcpy(request+SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA, keyptr, d2len);
			rc = crypto_update(SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA, request, &response_size, response);
			if(rc != SE3_OK){
				if(keydata != NULL){ free(keydata);	}
				return SE3_ERR_RESOURCE;
			}
			memcpy(&dec_len, response+SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN, 2);
			if(dec_len != 32){
				if(keydata != NULL){ free(keydata);	}
				return SE3_ERR_RESOURCE;
			}
			uint8_t unwrapped_key[32];
			memset(unwrapped_key, 0, 32);
			memcpy(unwrapped_key, response+SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA, dec_len);
			memcpy(keydata, unwrapped_key, 32);
		}
	}
	/* for the moment keep using the old key structure in the flash */
	key.id = newID;
	key.data_size = newLen;
	key.name_size = 0; // don't care
	/* use max validity to avoid problems (this parameter is not related to sekey but at the moment is used by the cripto init) */
	key.validity = UINT32_MAX;
	key.data = keydata;
	key.name = NULL; // don't care
	/* strategy for key insertion into flash: retrieve the data sent by the host, check if in memory there is already
	 * a key with the same id and the same content, if the key is already there (same id, same length, same key value...)
	 * do nothing and return ok. if the key is already there (same id) but is not exactly equal or if the key is not there
	 * (key with that id not found in flash) then delete the flash block (if key id is equal but key content is not the same)
	 * and create the new key, finally return ok. */
	se3_flash_it_init(&it);
	if (!se3_key_find(key.id, &it)) { // search in the flash memory if a key with the same ID is already present
		it.addr = NULL;
	}
	if (NULL != it.addr) { // enter if there's another key with same ID
		equal = se3_key_equal(&it, &key);  // do not replace if equal
		if (!equal) { // if not equal delete current key
			if (!se3_flash_it_delete(&it)) {
				if(keydata != NULL){
					free(keydata);
				}
				return SE3_ERR_HW;
			}
		}
	}
	it.addr = NULL;
	if (!equal) { // if not equal create new key
		if (!se3_key_new(&it, &key)) {
			if(keydata != NULL){
				free(keydata);
			}
			return SE3_ERR_MEMORY;
		}
	}
	if(keydata != NULL){
		free(keydata);
	}
	*resp_size = 2;
	memcpy(resp, "OK", 2);
	return SE3_OK;
}

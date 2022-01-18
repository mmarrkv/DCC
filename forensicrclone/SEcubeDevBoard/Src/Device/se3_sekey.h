//SEKEY INTERFACE

#ifndef SE3_SEKEY_H
#define SE3_SEKEY_H

#include "se3_keys.h"
#include <stdint.h>
#include <stdbool.h>

#include "se3_security_core.h"
#include "se3_smartcard.h"
#include "se3_FPGA.h"

#define SE3_TYPE_USERINFO 117 /**< This is the identifier of a flash node that contains the name and the ID of a SEkey user. */

typedef enum {
	SE3_SECURITY_CORE,
	SE3_FPGA,
	SE3_SMARTCARD
}se3_algo_impl_t;

enum{
	SE3_SEKEY_OP_SETINFO = 1, /**< Store SEkey username and user ID in the flash memory. */
	SE3_SEKEY_OP_GETINFO = 2, /**< Retrieve SEkey username and user ID from the flash memory. */
	SE3_SEKEY_OP_GET_KEY_IDS = 4, /**< Retrieve the IDs of all keys stored in the flash memory. */
	SE3_SEKEY_DELETEALL = 5, /**< Delete all keys stored in the flash memory. */
	SE3_SEKEY_DELETEKEY = 6, /**< Delete a specific key from the flash memory. */
	SE3_SEKEY_OP_GETKEYENC = 7, /**< Retrieve the value of a key as ciphertext from the flash memory. */
	SE3_SEKEY_INSERTKEY = 8 /**< Store a new key in the flash memory. */
};

/** \brief Retrieve the IDs of all the keys stored on the SEcube.
 *
 * This function iterates over the entire flash memory reading the ID of each stored key. The ID is then written
 * into the response buffer. In order to avoid overflow when writing the ID into the response buffer, a maximum
 * of 6000 bytes is used when writing the response. If there are IDs still to be sent to the host, a flash iterator
 * declared as global variable will keep pointing to the next key ID to be sent. The host is supposed to check the
 * value of the last ID sent by the SEcube, if it is = 0 then all IDs have been read otherwise the corresponding API
 * to read all key IDs from the flash memory must be issued again. */
uint16_t load_key_ids(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Send to the host the value of a key as ciphertext.
 *
 * This function is required by the SEkey administrator in order to distribute the keys to the users.
 * This function will not work if the active login on the SEcube is not in administrator mode. The value of the key passed
 * in the request buffer will be written as ciphertext in the response buffer, provided that a single key with that ID is
 * stored in the flash memory. In case of multiple keys with the same ID, an error is returned. In order to encrypt the key
 * to be returned, another key present in the flash memory has to be specified by the host in the request buffer. */
uint16_t load_encrypted_key_data(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Send the name and the ID of the SEkey user associated to the SEcube to the host computer. */
uint16_t load_user_info(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Write the name and the ID of the SEkey user associated to the SEcube into the flash memory.
 *
 * This action is performed only by the SEkey administrator therefore it is not allowed when the active login
 * is in user mode. */
uint16_t store_user_info(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Delete all the keys stored in the flash memory of the SEcube.
 *
 * The host can specify a list of IDs, inside the request buffer, not to be deleted in order to
 * preserve them inside the flash memory. This is useful for SEkey. */
uint16_t delete_all_keys(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Simply delete a key from the flash memory. The ID of the key to be deleted is passed in the request buffer. */
uint16_t delete_key(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Store a key inside the flash memory of the SEcube.
 *
 * The request buffer may or may not contain the value of the key to be stored. In case the value is specified in the
 * request buffer, it may be encrypted or not. If it is encrypted, the ID of the key to be used for decryption is
 * also specified. If the value of the key is not present in the request buffer, then the encryption key is computed
 * using the PBKDF2 function with 10000 iterations, a 32 byte random seed (generated with the TRNG embedded in the
 * SEcube) and a 32 byte random salt (again generated with the TRNG embedded in the SEcube).
 * If another key with the same id is already stored in the SEcube, the old key is replaced by the new one. */
uint16_t insert_key(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief SEkey behavior function
 *
 *  Retrieve information, given a key, about the possible implementations
 *  you're allowed to perform, and the algorithm
 */
bool sekey_get_implementation_info(uint8_t* algo_implementation, uint8_t* crypto_algo, uint8_t* key);

/** \brief SEkey checking on keys
 *
 *  checks whether the passed key is registered into SEkey
 */
bool sekey_get_auth(uint8_t *key);

#endif

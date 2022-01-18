//
// Created by mvella on 10/19/21.
//

#ifndef SECUBEHOST_FRCLONE_H
#define SECUBEHOST_FRCLONE_H

#include "sources/L1/L1.h"
#include <string>

using namespace std;

namespace FRcloneCodes {

    typedef enum  {
        FRCLONE_ERR_SUCCESS,
        FRCLONE_ERR_STATE,
        FRCLONE_ERR_FACTORY_INIT_FAIL,
        FRCLONE_ERR_MNG_LOGIN_FAIL,
        FRCLONE_ERR_USR_LOGIN_FAIL,
        FRCLONE_ERR_AUDIT_LOGIN_FAIL,
        FRCLONE_ERR_LOGOUT_FAIL,
        FRCLONE_ERR_FRCLONE_INIT_FAIL,
        FRCLONE_ERR_SESSKEY_FAIL,
        FRCLONE_ERR_BAKENC_FAIL,
        FRCLONE_ERR_DECBAKE_FAIL,
        FRCLONE_ERR_GETPCR_FAIL,
        FRCLONE_ERR_TOKENLIST_FAIL,
    } error_t;

    typedef enum {
        FRCLONE_LOGGEDOUT,
        FRCLONE_FACTORY,
        FRCLONE_MANAGE_HSM,
        FRCLONE_AUDIT_HSM,
        FRCLONE_USE_HSM
    } mode_t;

    typedef enum {
        FRCLONE_OPFLAG_INIT = 0x01,
        FRCLONE_OPFLAG_FIN = 0x02,
        FRCLONE_OPFLAG_AAD = 0x04
    } opflags_t;

}

extern "C" {

/* DCC::FactoryInit()
 *  Performs an clone factory init
 *  SECube factory init (sets Magic number among other things)
 *  Logs in with default admin password
 *  Sets admin/user pins
 *  Logout out from factory session
 *  Required mode: FRCLONE_LOGGEDOUT
 */
FRcloneCodes::error_t FactoryInit(u_int8_t *sn,uint8_t *pin_admin, uint8_t *pin_user);

/* DCC::DCCManagerLogin()
 * FRclone HSM Admin login for Device Management
 * On success sets mode to FRCLONE_MANAGE_HSM
 * Required mode: FRCLONE_LOGGEDOUT
 */
FRcloneCodes::error_t DeviceMngLogin(uint8_t *pin_admin);

/* DCC::HSMInit()
 *  FRclone HSM Admin procedure to set token placeholders - these must synch with frclone config file
 * and initial PCR value
 * as well as dummy token values (set internally)
 * Required mode: FRCLONE_MANAGE_HSM
 */
FRcloneCodes::error_t FRcloneInit(uint8_t *pcr, uint8_t *rfrsh_token_plchldr, uint8_t *access_token_plchldr);


/* DCC::SetSessionKey()
 *  FRclone HSM - Sets session key for d/encrypting HTTPS traffic with ChaPoly
 * Required modes:  FRCLONE_MANAGE_HSM or FRCLONE_USE_HSM
 */
FRcloneCodes::error_t SetSessionKey(uint8_t *sesskey);


/* DCC::EncEmbed()
 * FRclone HSM - Encrypt HTTP requests, baking tokens into placeholders
 * Use the currently set session key
 * Required modes:  FRCLONE_MANAGE_HSM or FRCLONE_USE_HSM
 * !!All output memory must be alloceted/freed by the application!!
 * ChaPolyBAKE returns an output buffer of size: plaintextsize + MAC (16 bytes)
 * ASSUMING same size for token values and token placeholders
 * Best practice: memset output buffer to all 0's prior to usage + do not forget to deallocate buffer once no longer needed
 */
FRcloneCodes::error_t EncBake(uint32_t *sessionId, uint8_t flags, uint8_t *iv, uint8_t *aad, uint16_t aadsize, uint8_t *plaintext, uint16_t plaintextsize, uint8_t *ciphertext, uint16_t *ciphertextsize);


/* DCC::DecStore()
 * FRclone HSM - Decrypt HTTP responses, baking tokens into the device whenever new ones are returned
 * Use the currently set session key
 * Required modes:  FRCLONE_MANAGE_HSM or FRCLONE_USE_HSM*
 * !!All output memory must be alloceted/freed by the application!!
 * ChaPolyBAKE expects an input buffer of size: ciphertext with the last 16 bytes storing the MAC
 * ChaPolyBAKE returns an output buffer of size: ciphertextsize - MAC (16 bytes)
 * ASSUMING same size for token values and token placeholders
 * Best practice: memset output buffer to all 0's prior to usage + do not forget to deallocate buffer once no longer needed
 */
FRcloneCodes::error_t DecBake(uint32_t *sessionId, uint8_t flags, uint8_t *iv, uint8_t *aad, uint16_t aadsize, uint8_t *ciphertext, uint16_t ciphertextsize, uint8_t *plaintext, uint16_t *plaintextsize);

/* DCC::DCCUserLogin()
* FRclone HSM User login
* On sucess sets mode to FRCLONE_USE_HSM
* Required mode: FRCLONE_LOGGEDOUT
*/
FRcloneCodes::error_t DeviceUsrLogin(uint8_t *pin_user);


/* DCC::DCCAuditLogin()
* FRclone HSM Admin login for Log Audit
* On success sets mode to FRCLONE_AUDIT_HSM
* Required mode: FRCLONE_LOGGEDOUT
*/
FRcloneCodes::error_t DeviceAuditLogin(uint8_t *pin_admin);


/* DCC::Logout()
 * FRclone HSM logout
 * Required modes:  FRCLONE_MANAGE_HSM or FRCLONE_USE_HSM or FRCLONE_AUDIT_HSM
 * On success sets mode to FRCLONE_LOGGEDOUT
 */
FRcloneCodes::error_t Logout();

/* DCC::GetTag()
 * FRclone HSM get PCR value for audit purpose
 * Required mode: FRCLONE_AUDIT_HSM
 * All output memory must be alloceted by application
 */
FRcloneCodes::error_t GetPCR(uint8_t* pcrbuffer , uint16_t *pcrsize);

/* DCC::ListTokens()
 * FRclone HSM lists all loaded tokens in JSON format
 * Just a utility - works as long as the HSM is logged-in
 * All output memory must be alloceted by application
 */
FRcloneCodes::error_t TokenList(uint8_t* tokens_buffer , uint16_t *buffer_size);


}


#endif //SECUBEHOST_FRCLONE_H

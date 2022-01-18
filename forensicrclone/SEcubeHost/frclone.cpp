//
// Created by mvella on 10/19/21.
//

#include "frclone.h"
#include <sstream>
using namespace std;

static uint8_t pin0[32] = { // the default pin on the SEcube is all-zeros
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static FRcloneCodes::mode_t mode = FRcloneCodes::FRCLONE_LOGGEDOUT;
static L0 l0 = L0();
static L1 l1 = L1();

FRcloneCodes::error_t FactoryInit(u_int8_t *sn, uint8_t *pin_admin, uint8_t *pin_user) {

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode != FRcloneCodes::FRCLONE_LOGGEDOUT  || numDevices==0 ){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    mode = FRcloneCodes::FRCLONE_FACTORY;

    try{
        l1.L1FactoryInit(sn);
        l1.L1Login(pin0, SE3_ACCESS_ADMIN, true);
        //Note: if default factory login failed it means device already initialized
        l1.L1SetUserPIN(pin_admin);
        l1.L1SetAdminPIN(pin_user);
    } catch(...){
        mode = FRcloneCodes::FRCLONE_LOGGEDOUT;
        return FRcloneCodes::FRCLONE_ERR_FACTORY_INIT_FAIL;
    }

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t DeviceMngLogin(uint8_t *pin_admin) {

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode != FRcloneCodes::FRCLONE_LOGGEDOUT || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try{
        l1.L1Login(pin_admin, SE3_ACCESS_ADMIN, true);// login to the SEcube as user with the pin of the user, force logout if currently the SEcube already has an active session
        l1.L1CryptoSetTime((uint32_t)time(0)); //must be called at least once before any enc/dec
    } catch(...){
        return FRcloneCodes::FRCLONE_ERR_MNG_LOGIN_FAIL;
    }

    mode = FRcloneCodes::FRCLONE_MANAGE_HSM;

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t FRcloneInit(uint8_t *pcr, uint8_t *rfrsh_token_plchldr, uint8_t *access_token_plchldr) {

    se3Key key;

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode != FRcloneCodes::FRCLONE_MANAGE_HSM || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    // Note: a safety check in case any of the constants is adjusted in the future
    if ( (MV_ACCTOKENSIZE > MV_ACCTOKENSIZEMAX) || (MV_RFRSHTOKENSIZE > MV_RFRSHTOKENSIZEMAX)  ) {
        return FRcloneCodes::FRCLONE_ERR_FRCLONE_INIT_FAIL;
    }

    try {
        /***** Upsert Access Token Holder *****/
        key.id = ACC_TKN_PLCHLDR_ID;
        strcpy((char *) key.name, "AccessTokenPlaceHolder");
        key.nameSize = strlen((char *) key.name);
        key.dataSize = MV_ACCTOKENSIZE;
        key.data = access_token_plchldr;
        key.validity = (uint32_t) time(0) + 365 * 24 * 3600;
        l1.L1KeyEdit(&key, 3); //SE3_KEY_OP_UPSERT


        /***** Upsert Refresh Token Holder *****/
        key.id = RFRSH_TKN_PLCHLDR_ID;
        strcpy((char *) key.name, "RefreshTokenPlaceHolder");
        key.nameSize = strlen((char *) key.name);
        key.dataSize = MV_RFRSHTOKENSIZE;
        key.data = rfrsh_token_plchldr;
        key.validity = (uint32_t) time(0) + 365 * 24 * 3600;
        l1.L1KeyEdit(&key, 3); //SE3_KEY_OP_UPSERT

        /***** Upsert Access Token *****/
        key.id = ACC_TKN_ID;
        strcpy((char *) key.name, "AccessToken");
        key.nameSize = strlen((char *) key.name);
        key.dataSize = MV_ACCTOKENSIZE;
        key.data = access_token_plchldr;
        key.validity = (uint32_t) time(0) + 365 * 24 * 3600;
        l1.L1KeyEdit(&key, 3); //SE3_KEY_OP_UPSERT


        /***** Upsert Refresh Token *****/
        key.id = RFRSH_TKN_ID;
        strcpy((char *) key.name, "RefreshToken");
        key.nameSize = strlen((char *) key.name);
        key.dataSize = MV_RFRSHTOKENSIZE;
        key.data = rfrsh_token_plchldr;
        key.validity = (uint32_t) time(0) + 365 * 24 * 3600;
        l1.L1KeyEdit(&key, 3); //SE3_KEY_OP_UPSERT

        /***** Upsert Init PCR *****/
        key.id = PCR_ID;
        strcpy((char *) key.name, "PCR");
        key.nameSize = strlen((char *) key.name);
        key.dataSize = MV_PCRSIZE;
        key.data = pcr;
        key.validity = (uint32_t) time(0) + 365 * 24 * 3600;
        l1.L1KeyEdit(&key, 3); //SE3_KEY_OP_UPSERT


    } catch (...) {
        return FRcloneCodes::FRCLONE_ERR_FRCLONE_INIT_FAIL;
    }

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t SetSessionKey(uint8_t *sesskey) {

    se3Key key;

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode == FRcloneCodes::FRCLONE_LOGGEDOUT || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try {

        /***** Upsert the session key *****/
        strcpy((char *) key.name, "SessionKey");
        key.id = SESSKEY_ID;
        key.nameSize = strlen((char *) key.name);
        key.dataSize = MV_CHACHA20_KEY_SIZE;
        key.data = sesskey;
        key.validity = (uint32_t) time(0) + 365 * 24 * 3600;
        l1.L1KeyEdit(&key, 3); //SE3_KEY_OP_UPSERT
    } catch(...) {
        return FRcloneCodes::FRCLONE_ERR_SESSKEY_FAIL;
    }

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t EncBake(uint32_t *sessionId, uint8_t flags, uint8_t *iv, uint8_t *aad, uint16_t aadsize, uint8_t *plaintext, uint16_t plaintextsize, uint8_t *ciphertext, uint16_t *ciphertextsize) {

    uint8_t numDevices = l0.GetNumberDevices();

    uint32_t keyIdChoosen = SESSKEY_ID;

    if( mode == FRcloneCodes::FRCLONE_LOGGEDOUT || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try {

        //FRCLONE_OPFLAG_INIT - means we need to call L1CryptoInit followed by L1CryptoUpdate+RESET
        if((flags & 0x1) )
        {
            l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305,
                            CryptoInitialisation::Mode::ENCRYPT | CryptoInitialisation::Feedback::DoBake, keyIdChoosen,
                            sessionId);
            l1.L1CryptoUpdate(*sessionId, L1Crypto::UpdateFlags::RESET , MV_CHACHA20_IV_SIZE, iv, 0, NULL, 0, NULL);
        }

        //FRCLONE_OPFLAG_AAD - means we need to call L1CryptoUpdate+AAD - assuming L1CryptoUpdate+RESET has already been called
        if((flags & 0x4) )
        {
            l1.L1CryptoUpdate(*sessionId, L1Crypto::UpdateFlags::SET_AAD, aadsize, aad, 0, NULL, 0, NULL);
        }

        // plaintextsize > 0 - means we need to call L1CryptoUpdate+Enc
        //FRCLONE_OPFLAG_FIN - means we also need to set FINIT
        if(plaintextsize > 0)
        {
            if((flags & 0x2) )
            {
                l1.L1CryptoUpdate(*sessionId,  L1Crypto::UpdateFlags::FINIT, 0, NULL, plaintextsize, plaintext, ciphertextsize, ciphertext);
            } else {
                l1.L1CryptoUpdate(*sessionId, 0, 0, NULL, plaintextsize, plaintext, ciphertextsize, ciphertext);
            }
        }

            // if plaintextsize ==0 and FRCLONE_OPFLAG_FIN then call with set FINIT to get just the Auth Tag
        else if((flags & 0x2) )
        {
            l1.L1CryptoUpdate(*sessionId,  L1Crypto::UpdateFlags::FINIT, 0, NULL, 0, NULL, ciphertextsize, ciphertext);
        }

    } catch (...){
        return FRcloneCodes::FRCLONE_ERR_BAKENC_FAIL;
    }

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t DecBake(uint32_t *sessionId, uint8_t flags, uint8_t *iv, uint8_t *aad, uint16_t aadsize, uint8_t *ciphertext, uint16_t ciphertextsize, uint8_t *plaintext, uint16_t *plaintextsize) {

    uint8_t numDevices = l0.GetNumberDevices();

    uint32_t keyIdChoosen = SESSKEY_ID;

    if( mode == FRcloneCodes::FRCLONE_LOGGEDOUT || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try {

        //FRCLONE_OPFLAG_INIT - means we need to call L1CryptoInit followed by L1CryptoUpdate+RESET
        if((flags & 0x1) )
        {
            l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305,
                            CryptoInitialisation::Mode::DECRYPT | CryptoInitialisation::Feedback::DoBake, keyIdChoosen,
                            sessionId);
            l1.L1CryptoUpdate(*sessionId, L1Crypto::UpdateFlags::RESET , MV_CHACHA20_IV_SIZE, iv, 0, NULL, 0, NULL);
        }

        //FRCLONE_OPFLAG_AAD - means we need to call L1CryptoUpdate+AAD - assuming L1CryptoUpdate+RESET has already been called
        if((flags & 0x4) )
        {
            l1.L1CryptoUpdate(*sessionId, L1Crypto::UpdateFlags::SET_AAD, aadsize, aad, 0, NULL, 0, NULL);
        }

        // plaintextsize > 0 - means we need to call L1CryptoUpdate+Enc
        //FRCLONE_OPFLAG_FIN - means we also need to set FINIT
        if(ciphertextsize > 0)
        {
            if((flags & 0x2) )
            {
                l1.L1CryptoUpdate(*sessionId,  L1Crypto::UpdateFlags::FINIT, 0, NULL, ciphertextsize, ciphertext, plaintextsize, plaintext);
            } else {
                l1.L1CryptoUpdate(*sessionId, 0, 0, NULL, ciphertextsize, ciphertext, plaintextsize, plaintext);
            }
        }

            // if plaintextsize ==0 and FRCLONE_OPFLAG_FIN then call with set FINIT to get just the Auth Tag
        else if((flags & 0x2) )
        {
            l1.L1CryptoUpdate(*sessionId,  L1Crypto::UpdateFlags::FINIT, 0, NULL, 0, NULL, plaintextsize, plaintext);
        }

    } catch (...){
        return FRcloneCodes::FRCLONE_ERR_DECBAKE_FAIL;
    }

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t DeviceUsrLogin(uint8_t *pin_user) {

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode != FRcloneCodes::FRCLONE_LOGGEDOUT || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try{
        l1.L1Login(pin_user, SE3_ACCESS_USER, true);// login to the SEcube as user with the pin of the user, force logout if currently the SEcube already has an active session
        l1.L1CryptoSetTime((uint32_t)time(0)); //must be called at least once before any enc/dec
    } catch(...){
        return FRcloneCodes::FRCLONE_ERR_USR_LOGIN_FAIL;
    }

    mode = FRcloneCodes::FRCLONE_USE_HSM;

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t DeviceAuditLogin(uint8_t *pin_admin) {

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode != FRcloneCodes::FRCLONE_LOGGEDOUT || numDevices==0){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try{
        l1.L1Login(pin_admin, SE3_ACCESS_ADMIN, true);// login to the SEcube as user with the pin of the user, force logout if currently the SEcube already has an active session
        l1.L1CryptoSetTime((uint32_t)time(0)); //must be called at least once before any enc/dec
    } catch(...){
        return FRcloneCodes::FRCLONE_ERR_AUDIT_LOGIN_FAIL;
    }

    mode = FRcloneCodes::FRCLONE_AUDIT_HSM;

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t Logout() {

    uint8_t numDevices = l0.GetNumberDevices();

    if( mode == FRcloneCodes::FRCLONE_LOGGEDOUT  || numDevices==0 ){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try {
        l1.L1Logout();
    } catch(...) {
        return FRcloneCodes::FRCLONE_ERR_LOGOUT_FAIL;
    }

    mode = FRcloneCodes::FRCLONE_LOGGEDOUT;

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t GetPCR(uint8_t* pcrbuffer , uint16_t *pcrsize) {

    uint8_t numDevices = l0.GetNumberDevices();

    uint32_t keyIdChoosen = SESSKEY_ID;
    uint32_t sessionId;

    //dummies****
    uint8_t buffer[1] = {'1'};
    uint16_t buffer_len = 1;
    uint8_t iv[MV_CHACHA20_IV_SIZE];
    memset(iv, 0, MV_CHACHA20_IV_SIZE);
    //***********

    if( mode != FRcloneCodes::FRCLONE_AUDIT_HSM  || numDevices==0 ){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try {
        l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305,
                        CryptoInitialisation::Mode::ENCRYPT | CryptoInitialisation::Feedback::GETPCR, keyIdChoosen,
                        &sessionId);
        l1.L1CryptoUpdate(sessionId, L1Crypto::UpdateFlags::RESET | L1Crypto::UpdateFlags::FINIT, MV_CHACHA20_IV_SIZE,
                          iv, buffer_len, buffer, pcrsize, pcrbuffer);
    } catch (...) {
        return FRcloneCodes::FRCLONE_ERR_GETPCR_FAIL;
    }

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}

FRcloneCodes::error_t TokenList(uint8_t* tokens_buffer , uint16_t *buffer_size) {

    uint8_t numDevices = l0.GetNumberDevices();

    stringstream os;

    uint16_t maxKeys = 128, skip = 0, count;
    se3Key keyArray[maxKeys];


    if( mode == FRcloneCodes::FRCLONE_LOGGEDOUT  || numDevices==0 ){
        return FRcloneCodes::FRCLONE_ERR_STATE;
    }

    try {
        l1.L1KeyList(maxKeys, skip, keyArray, &count);
    } catch(...) {
        return FRcloneCodes::FRCLONE_ERR_TOKENLIST_FAIL;
    }

    os << "{ \"count\":\"" << count << "\", \"keys\":[";
    for(uint16_t i=0; i<count; i++)
    {
        string keyname((char*)keyArray[i].name, keyArray[i].nameSize);
        os << "{\"" << keyArray[i].id << "\":\"" << keyname << "\"}";
        if(i < count-1)
        {
            os << ", ";
        }
    }
    os << "] }";

    os.get((char *) tokens_buffer,2048);

    return FRcloneCodes::FRCLONE_ERR_SUCCESS;
}
//
// Created by mvella on 10/20/21.
//

#include "frclone.h"
#include <iostream>
#include <cstring>

using namespace std;

#define BUFFER_SIZE 1024

void flash_firmware(); //the initial state consists of a clear on-chip flash memory - both code and data banks should be erased
void factory_init(); // to init firmware; requires dev management login
void frclone_init(); // follows up firmware init and deals with frclone specific initialization;  requires dev management login
void enlist_tokens(); // enlisting of tokens; a way to verify the success of the previous step'; requires at least a user device login
void device_authenticate(); // d/encryption of an authentication session that transports new tokens and which trigger on-HSM token update
void device_usage(); // d/ecnryption sessions with token baking accordingly; requires at least a user device login
void device_audit(); // getpcr for audit purposes; required a device audit login


static uint8_t pin_user[32] = { // the pin for ADMIN mode access to be set on the HSM
        't','e','s','t', 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};


static uint8_t pin_admin[32] = { // the pin for USER mode access to be set on the HSM
        't','e','s','t', 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static uint8_t test_sn[32] = { // serial number to be written to the HSM
        1,2,3,4, 5,6,7,8, 9,10,11,12, 13,14,15,16,
        1,2,3,4, 5,6,7,8, 9,10,11,12, 13,14,15,16
};

uint8_t test_pcr_data[32] = {
        0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD, 0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD,
        0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD, 0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD
};

uint8_t test_plchldr_data[MV_ACCTOKENSIZE+1] = "ya29.a0ARrdaM8gxtp34qcvj3C6RI9haZo_Y29Ycl8oQAdzFrOouTXF0v0kMcp8z6JPx2OlVK6ZKiNnh8VQsvNlbhvMHAGwFSS7_x2FMuHVFT3qrjBT1ZNX8EAc2PubObVRefbajpl8mau8crxP2Kr5bOGtOOTp9FWF";
uint8_t test_rfs_plchldr_data[MV_RFRSHTOKENSIZE+1] = "1//04xOZDfnTZta3CgYIARAAGAQSNwF-L9IrmXM95RWHx3Sq3MYZ6brbBGVwJYHaAbCfFE3zQkGKkOGXBp46kCjRaCQ6dDKr4sreewk";


uint8_t test_data[MV_ACCTOKENSIZE+1] = "Ma29.a0ARrdaM8gxtp34qcvj3C6RI9haZo_Y29Ycl8oQAdzFrOouTXF0v0kMcp8z6JPx2OlVK6ZKiNnh8VQsvNlbhvMHAGwFSS7_x2FMuHVFT3qrjBT1ZNX8EAc2PubObVRefbajpl8mau8crxP2Kr5bOGtOOTp9FWV";
uint8_t test_rfs_data[MV_RFRSHTOKENSIZE+1] = "M//04xOZDfnTZta3CgYIARAAGAQSNwF-L9IrmXM95RWHx3Sq3MYZ6brbBGVwJYHaAbCfFE3zQkGKkOGXBp46kCjRaCQ6dDKr4sreewV";


int main() {


    cout << "FRclone test driver" << endl;
    cout << "======= ==== ======" << endl;

    flash_firmware();
    factory_init();

    frclone_init();

    enlist_tokens();

    device_authenticate();

    device_usage();
    device_audit();

}

void flash_firmware() {

    cout << "\n>>: Flash firmware, making sure that both device flash mem bank are fully erased prior to operation" << endl;
    cout << ">>: Use the \'st-flash erase\' command if the chip was previously used to clear the data memory bank" << endl;

}

void factory_init() {
    cout << "\n>>: Factory init in progress" << endl;
    if (FactoryInit(test_sn, pin_admin, pin_user))
    {
        cout << ">>: HSM already initialized, or else general error" << endl;
        return;
    } else {
        cout << ">>: Factory init completed successfully" << endl;
    }

    if(Logout()){
        cout << ">>: Logout error" << endl;
    } else {
        cout << ">>: Logout successful" << endl;
    }

}

void frclone_init() {

    cout << "\n>>: FRCloneInit in progress" << endl;
    if(DeviceMngLogin(pin_admin))
    {
        cout << ">>: FRclone HSM login error" << endl;
        return;
    }
      if(  FRcloneInit(test_pcr_data, test_rfs_plchldr_data, test_plchldr_data) ) {
          cout << ">>: FRclone init error" << endl;
    } else {
          cout << ">>: FRclone init completed successfully" << endl;
          cout << ">>: Note: Refresh token size is set to: " << MV_RFRSHTOKENSIZE << endl;
          cout << ">>: Note: Access token size is set to: " << MV_ACCTOKENSIZE << endl;
          cout << ">>: Note: Constant token size, is being assumed" << endl;
          cout << ">>: Note: Buffer size that does not split tokens is being assumed" << endl;
          cout << ">>: Note: PCR value size is set to: " << MV_PCRSIZE << endl;
      }

    if(Logout()){
        cout << ">>: Logout error" << endl;
    } else {
        cout << ">>: Logout successful" << endl;
    }

}

void enlist_tokens() {

    unique_ptr<uint8_t[]> tokens_buffer = make_unique<uint8_t[]>(2048);
    uint16_t buffersize;
    cout << "\n>>: Enlist tokens in progress" << endl;
    if(DeviceUsrLogin(pin_user))
    {
        cout << ">>: FRclone HSM login error" << endl;
        return;
    } else {
        if(TokenList(tokens_buffer.get(),&buffersize))
        {
            cout << ">>: FRclone HSM token list error" << endl;
        } else {
            cout << ">>: FRclone HSM tokens:" << endl;
            cout << tokens_buffer.get() << endl;
        }
    }

    if(Logout()){
        cout << ">>: Logout error" << endl;
    } else {
        cout << ">>: Logout successful" << endl;
    }


}

void device_authenticate() {

    // - allocate space for buffers
    vector<uint8_t> plaintextvector;
    uint8_t *buffer;
    unique_ptr<uint8_t[]> enc_buffer;
    unique_ptr<uint8_t[]> dec_buffer;
    uint16_t inbuffer_len = 0, outbuffer_len=0, total_outbuffer_len=0;
    string astring = "blablablablablablablabla", encrypted, decrypted, acs_tkn_hdr = "\"access_token\": \"", rfs_tkn_hdr = "\"refresh_token\": \"";

    uint32_t sessionId;
    uint16_t offset = 0;


    uint8_t iv[MV_CHACHA20_IV_SIZE] = {0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint8_t aad[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint8_t sess_key[MV_CHACHA20_KEY_SIZE] = {
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4,
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4
    };

    // - user login
    cout << "\n>>: Device authentication in progress" << endl;
    if (DeviceAuditLogin(pin_admin)) {
        cout << ">>: FRclone HSM login error" << endl;
        return;
    }

// - set session key
    cout << ">>: Setting session key" << endl;
    if (SetSessionKey(sess_key)) {
        cout << ">>: Session key error" << endl;
        goto ERROR;
    }

// - Prepare and display plaintext - token response
    plaintextvector.insert(plaintextvector.end(), astring.begin(), astring.end());
    plaintextvector.insert(plaintextvector.end(), acs_tkn_hdr.begin(), acs_tkn_hdr.end());
    plaintextvector.insert(plaintextvector.end(), test_data, test_data + strlen((char *) test_data));
    plaintextvector.insert(plaintextvector.end(), astring.begin(), astring.end());
    plaintextvector.insert(plaintextvector.end(), rfs_tkn_hdr.begin(), rfs_tkn_hdr.end());
    plaintextvector.insert(plaintextvector.end(), test_rfs_data, test_rfs_data + strlen((char *) test_rfs_data));
    plaintextvector.insert(plaintextvector.end(), astring.begin(), astring.end());
    buffer = &plaintextvector[0];
    inbuffer_len = (uint16_t) plaintextvector.size();
    printf("buffer len plain -> %d\n", inbuffer_len);
    for (unsigned i = 0; i < inbuffer_len; ++i) {
        std::cout << buffer[i];
    }
    std::cout << endl;
    cout << "buffer plain (hex value) -> ";
    for (unsigned i = 0; i < inbuffer_len; ++i) {
        printf("%02x ", buffer[i]);
    }
    std::cout << endl;

// - Prepare encryption buffer + encrypt - token response
// - Display ciphertext + MAC
    enc_buffer = make_unique<uint8_t[]>((inbuffer_len + MV_CHACHA20_DIGEST_SIZE));
    memset(enc_buffer.get(), '\0', (inbuffer_len + MV_CHACHA20_DIGEST_SIZE));
    memset(iv, 0, MV_CHACHA20_IV_SIZE);


    if (inbuffer_len < BUFFER_SIZE) {
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_FIN | FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, buffer+offset,
               inbuffer_len-offset, enc_buffer.get()+offset, &outbuffer_len);

        total_outbuffer_len += outbuffer_len;
    } else {
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, buffer+offset,
                BUFFER_SIZE, enc_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
        offset+=BUFFER_SIZE;
        while(inbuffer_len-offset > BUFFER_SIZE) {
            EncBake(&sessionId, 0, NULL, NULL, 0, buffer+offset,
                    BUFFER_SIZE, enc_buffer.get()+offset, &outbuffer_len);
            total_outbuffer_len += outbuffer_len;
            offset+=BUFFER_SIZE;
        }
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, buffer+offset,
                inbuffer_len-offset, enc_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
    }

    outbuffer_len = total_outbuffer_len;
    total_outbuffer_len=0;
    offset=0;

    printf("%d=?%d\n",outbuffer_len,inbuffer_len+MV_CHACHA20_DIGEST_SIZE);
    if(outbuffer_len != ((inbuffer_len+MV_CHACHA20_DIGEST_SIZE))){
        cout << "Error, the length of the ciphertext does not correspond to the expected value." << endl;
        goto ERROR;
    }


    cout<< "buffer len enc -> " << (outbuffer_len) << endl;
    encrypted.assign((char*)enc_buffer.get(), outbuffer_len);
    cout << "buffer enc -> " << encrypted << endl;
    cout << "buffer enc (hex value) -> ";
    for(int n=0; n<outbuffer_len; n++){
        printf("%02x ", enc_buffer[n]);
    }
    cout << endl;

// - Prepare decryption buffer + decrypt - token response
// - Display plaintext
    buffer=enc_buffer.get();
    outbuffer_len=0;
    dec_buffer = make_unique<uint8_t[]>((inbuffer_len+MV_CHACHA20_DIGEST_SIZE));
    memset(dec_buffer.get(), '\0', (inbuffer_len+MV_CHACHA20_DIGEST_SIZE));
    memset(iv, 0, MV_CHACHA20_IV_SIZE);


    if (inbuffer_len < BUFFER_SIZE) {
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_FIN | FRcloneCodes::FRCLONE_OPFLAG_AAD, iv,aad, 16,  buffer+offset,
                inbuffer_len-offset, dec_buffer.get()+offset, &outbuffer_len);

        total_outbuffer_len += outbuffer_len;
    } else {
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT| FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, buffer+offset,
                BUFFER_SIZE, dec_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
        offset+=BUFFER_SIZE;
        while(inbuffer_len-offset > BUFFER_SIZE) {
            DecBake(&sessionId, 0, NULL, NULL, 0, buffer+offset,
                    BUFFER_SIZE, dec_buffer.get()+offset, &outbuffer_len);
            total_outbuffer_len += outbuffer_len;
            offset+=BUFFER_SIZE;
        }
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, buffer+offset,
                inbuffer_len-offset, dec_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
    }

    outbuffer_len = total_outbuffer_len;
    total_outbuffer_len=0;
    offset=0;

    if(outbuffer_len != ((inbuffer_len+MV_CHACHA20_DIGEST_SIZE))){
        cout << "Error, the length of the plaintext does not correspond to the expected value." << endl;
        goto ERROR;
    }

    cout<< "buffer len dec -> " << (outbuffer_len) << endl;
    decrypted.assign((char*)dec_buffer.get(), outbuffer_len);
    cout << "buffer dec -> " << decrypted << endl;
    cout << "buffer dec (hex value) -> ";
    for(int n=0; n<outbuffer_len; n++){
        printf("%02x ", dec_buffer[n]);
    }
    cout << endl;

    ERROR:
// - user logout
    if(Logout()){
        cout << ">>: Logout error" << endl;
    } else {
        cout << ">>: Logout successful" << endl;
    }


}

void device_usage() {

    // - allocate space for buffers
    vector<uint8_t > plaintextvector;
    uint8_t *buffer;
    unique_ptr<uint8_t[]> enc_buffer;
    unique_ptr<uint8_t[]> dec_buffer;
    uint16_t inbuffer_len = 0, outbuffer_len=0, total_outbuffer_len=0;
    string astring ="blablablablablablablabla", encrypted, decrypted;

    uint32_t sessionId;
    uint16_t offset = 0;

    uint8_t iv[MV_CHACHA20_IV_SIZE] = {0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint8_t aad[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint8_t sess_key[MV_CHACHA20_KEY_SIZE] = {
            1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4,
            1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4
    };

// - user login
    cout << "\n>>: Device usage in progress" << endl;
    if(DeviceAuditLogin(pin_admin))
    {
        cout << ">>: FRclone HSM login error" << endl;
        return;
    }

// - set session key
    cout << ">>: Setting session key" << endl;
    if(SetSessionKey(sess_key))
    {
        cout << ">>: Session key error" << endl;
        goto ERROR;
    }

// - Prepare and display plaintext - request
    plaintextvector.insert(plaintextvector.end(), astring.begin(), astring.end());
    plaintextvector.insert(plaintextvector.end(), test_plchldr_data, test_plchldr_data + strlen((char *)test_plchldr_data));
    plaintextvector.insert(plaintextvector.end(), astring.begin(), astring.end());
    plaintextvector.insert(plaintextvector.end(), test_rfs_plchldr_data, test_rfs_plchldr_data + strlen((char *)test_rfs_plchldr_data));
    plaintextvector.insert(plaintextvector.end(), astring.begin(), astring.end());
    buffer = &plaintextvector[0];
    inbuffer_len = (uint16_t) plaintextvector.size();
    printf("buffer len plain -> %d\n", inbuffer_len);
    for (unsigned i=0; i<inbuffer_len; ++i) {
        std::cout << buffer[i];
    }
    std::cout << endl;
    cout << "buffer plain (hex value) -> ";
    for (unsigned i=0; i<inbuffer_len; ++i) {
        printf("%02x ", buffer[i]);
    }
    std::cout << endl;

// - Prepare encryption buffer + encrypt - request
// - Display ciphetext + MAC
    enc_buffer = make_unique<uint8_t[]>((inbuffer_len+MV_CHACHA20_DIGEST_SIZE));
    memset(enc_buffer.get(), '\0', (inbuffer_len+MV_CHACHA20_DIGEST_SIZE));
    memset(iv, 0, MV_CHACHA20_IV_SIZE);

    //EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_FIN, iv, buffer, inbuffer_len, enc_buffer.get(), &outbuffer_len);

    if (inbuffer_len < BUFFER_SIZE) {
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_FIN| FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, buffer+offset,
                inbuffer_len-offset, enc_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
    } else {
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT| FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, buffer+offset,
                BUFFER_SIZE, enc_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
        offset+=BUFFER_SIZE;
        while(inbuffer_len-offset > BUFFER_SIZE) {
            EncBake(&sessionId, 0, NULL, NULL, 0, buffer+offset,
                    BUFFER_SIZE, enc_buffer.get()+offset, &outbuffer_len);
            total_outbuffer_len += outbuffer_len;
            offset+=BUFFER_SIZE;
        }
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, buffer+offset,
                inbuffer_len-offset, enc_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
    }

    outbuffer_len = total_outbuffer_len;
    total_outbuffer_len=0;
    offset=0;


    if(outbuffer_len != ((inbuffer_len+MV_CHACHA20_DIGEST_SIZE))){
        cout << "Error, the length of the ciphertext does not correspond to the expected value." << endl;
        goto ERROR;
    }

    cout<< "buffer len enc -> " << (outbuffer_len) << endl;
    encrypted.assign((char*)enc_buffer.get(), outbuffer_len);
    cout << "buffer enc -> " << encrypted << endl;
    cout << "buffer enc (hex value) -> ";
    for(int n=0; n<outbuffer_len; n++){
        printf("%02x ", enc_buffer[n]);
    }
    cout << endl;

// - Prepare decryption buffer + decrypt - request
// - Display plaintext
    buffer=enc_buffer.get();
    outbuffer_len=0;
    dec_buffer = make_unique<uint8_t[]>((inbuffer_len+MV_CHACHA20_DIGEST_SIZE));
    memset(dec_buffer.get(), '\0', (inbuffer_len));
    memset(iv, 0, MV_CHACHA20_IV_SIZE);


    //DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_FIN, iv, buffer, inbuffer_len, dec_buffer.get(), &outbuffer_len);

    if (inbuffer_len < BUFFER_SIZE) {
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_FIN | FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, buffer+offset,
                inbuffer_len-offset, dec_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
    } else {
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT| FRcloneCodes::FRCLONE_OPFLAG_AAD, iv,aad, 16,  buffer+offset,
                BUFFER_SIZE, dec_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
        offset+=BUFFER_SIZE;
        while(inbuffer_len-offset > BUFFER_SIZE) {
            DecBake(&sessionId, 0, NULL, NULL, 0, buffer+offset,
                    BUFFER_SIZE, dec_buffer.get()+offset, &outbuffer_len);
            total_outbuffer_len += outbuffer_len;
            offset+=BUFFER_SIZE;
        }
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, buffer+offset,
                inbuffer_len-offset, dec_buffer.get()+offset, &outbuffer_len);
        total_outbuffer_len += outbuffer_len;
    }

    outbuffer_len = total_outbuffer_len;
    total_outbuffer_len=0;
    offset=0;

    if(outbuffer_len != ((inbuffer_len+MV_CHACHA20_DIGEST_SIZE))){
        cout << "Error, the length of the plaintext does not correspond to the expected value." << endl;
        goto ERROR;
    }

    cout<< "buffer len dec -> " << (outbuffer_len) << endl;
    decrypted.assign((char*)dec_buffer.get(), outbuffer_len);
    cout << "buffer dec -> " << decrypted << endl;
    cout << "buffer dec (hex value) -> ";
    for(int n=0; n<outbuffer_len; n++){
        printf("%02x ", dec_buffer[n]);
    }
    cout << endl;

ERROR:
// - user logout
    if(Logout()){
        cout << ">>: Logout error" << endl;
    } else {
        cout << ">>: Logout successful" << endl;
    }


}

void device_audit() {

    unique_ptr<uint8_t[]> pcr_buffer = make_unique<uint8_t[]>(MV_PCRSIZE);
    uint16_t pcrsize;

    cout << "\n>>: Device audit in progress" << endl;
    if(DeviceAuditLogin(pin_admin))
    {
        cout << ">>: FRclone HSM login error" << endl;
        return;
    } else {
        if(GetPCR(pcr_buffer.get(), &pcrsize))
        {
            cout << ">>: GetPCR error" << endl;
        } else {
            cout << ">>: PCR value: ";
            for (int n = 0; n < pcrsize; n++) {
                printf("%02x ", pcr_buffer[n]);
            }
            cout << endl;
        }
    }

    if(Logout()){
        cout << ">>: Logout error" << endl;
    } else {
        cout << ">>: Logout successful" << endl;
    }


}

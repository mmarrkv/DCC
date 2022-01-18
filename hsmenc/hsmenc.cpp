//
// Created by mvella on 10/20/21.
//

#include "frclone.h"
#include <iostream>
#include <cstring>

using namespace std;



void factory_init(); // to init firmware; requires dev management login
void frclone_init(); // follows up firmware init and deals with frclone specific initialization;  requires dev management login
void enlist_tokens(); // enlisting of tokens; a way to verify the success of the previous step'; requires at least a user device login
void device_enc() ; // Encrypt
void device_dec() ; // Decrypt
void user_login(); // User login
void logout(); // logout
void device_audit(); // getpcr for audit purposes; requires a device audit login
void usage(char **); //help

long buffer_size = 1024;

//All pins, keys, crypto parameters are fixed for experiment
static uint8_t pin_user[32] = { // the pin for USER mode access to be set on the HSM
        't','e','s','t', 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static uint8_t pin_admin[32] = { // the pin for ADMIN mode access to be set on the HSM
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

uint8_t iv[MV_CHACHA20_IV_SIZE] = {0,0,0,0, 0,0,0,0, 0,0,0,0};

uint8_t aad[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

uint8_t sess_key[MV_CHACHA20_KEY_SIZE] = {
        1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4,
        1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4
};

int main(int argc, char *argv[]) {

    //execution step flags
    int f_factory_init = 0, f_frclone_init = 0,  f_user_login = 0, f_enlist_tokens = 0, f_device_enc = 0, f_device_dec = 0, f_device_audit = 0, f_logout = 0;
    char opt;

    //usage
    if(argc <2)
    {
        usage(argv);
        exit(EXIT_SUCCESS);
    }

    //getopt while loop - setting flags + globals
    while ((opt = ::getopt(argc, argv, "hitulna:b:o")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv);
                exit(EXIT_SUCCESS);
            case 'i':
                f_factory_init = 1;
                break;
            case 't':
                f_frclone_init = 1;
                break;
            case 'u':
                f_device_audit = 1;
                break;
            case 'l':
                f_user_login = 1;
                break;
            case 'n':
                f_enlist_tokens = 1;
                break;
            case 'a':
                if (strncmp(optarg, "enc", 3)==0) {
                    f_device_enc=1;
                } else if (strncmp(optarg, "dec", 3)==0) {
                    f_device_dec=1;
                } else {
                    usage(argv);
                    exit(EXIT_SUCCESS);
                }
                break;
            case 'b':
                if(sscanf(optarg, "%lu", &buffer_size)<1) {
                    usage(argv);
                    exit(EXIT_SUCCESS);
                }
                break;
            case 'o':
                f_logout = 1;
                break;
            default:
                usage(argv);
                exit(EXIT_SUCCESS);
        }

    }


    // execute sequence of steps according to flags
    if(f_factory_init){
        factory_init();
    }

    if(f_frclone_init){
        frclone_init();
    }

    if(f_device_audit) {
        device_audit();
    }

    if(f_user_login){
        user_login();
    }

    if(f_user_login && f_enlist_tokens) {
        enlist_tokens();
    }

    if(f_user_login && f_device_enc) {
        device_enc();
    } else if(f_user_login && f_device_dec){
        device_dec();
    }

    if(f_logout) {
        logout();
    }

}

void usage(char **argv)
{
    cerr 	<< "Usage: " << argv[0] << " [-h] [-i] [-t] [-u]  [-l] [-n] [-a enc|dec] [-b buffer_size] [-o]"
            << endl
            << "Available options: " << endl
            << "  -h                       Show this help" << endl
            << "  -i                       Default admin-mode login + factory device init" << endl
            << "  -t                       Admin login + Init device firmware for forensic usage" << endl
            << "  -u                       Admin login + Device audit: return PCR value" << endl
            << "  -l                       User login - required for all below operations, or else will be ignored " << endl
            << "  -n                       Enlist device authentication tokens" << endl
            << "  -a <enc|dec>             Enc/dec (aead mode using stdio) + bake on-device authentication tokens" << endl
            << "  -b <buffer_size bytes>   Buffer size to use (default: 1024)" << endl
            << "  -o                       Logout" << endl;
    exit(EXIT_FAILURE);
}

void factory_init() {
    cerr << "\n>>: Factory init in progress" << endl;
    if (FactoryInit(test_sn, pin_admin, pin_user))
    {
        cerr << ">>: HSM already initialized, or else general error" << endl;
        return;
    } else {
        cerr << ">>: Factory init completed successfully" << endl;
    }

    if(Logout()){
        cerr << ">>: Logout error" << endl;
    } else {
        cerr << ">>: Logout successful" << endl;
    }

}

void frclone_init() {

    cerr << "\n>>: FRCloneInit in progress" << endl;
    if(DeviceMngLogin(pin_admin))
    {
        cerr << ">>: FRclone HSM login error" << endl;
        return;
    }

    if(  FRcloneInit(test_pcr_data, test_rfs_plchldr_data, test_plchldr_data) ) {
        cerr << ">>: FRclone init error" << endl;
    } else {
        cerr << ">>: FRclone init completed successfully" << endl;
        cerr << ">>: Note: Refresh token size is set to: " << MV_RFRSHTOKENSIZE << endl;
        cerr << ">>: Note: Access token size is set to: " << MV_ACCTOKENSIZE << endl;
        cerr << ">>: Note: Constant token size, is being assumed" << endl;
        cerr << ">>: Note: Buffer size that does not split tokens is being assumed" << endl;
        cerr << ">>: Note: PCR value size is set to: " << MV_PCRSIZE << endl;
    }

    if(Logout()){
        cerr << ">>: Logout error" << endl;
    } else {
        cerr << ">>: Logout successful" << endl;
    }

}

void user_login() {

    cerr << ">>: Device user login in progress" << endl;
    if(DeviceUsrLogin(pin_user))
    {
        cerr << ">>: FRclone HSM login error" << endl;
        return;
    }

    // - set session key
    if (SetSessionKey(sess_key)) {
        cerr << ">>: Session key error" << endl;
        return;
    }
};

void logout() {

    cerr << ">>: Device logout in progress" << endl;
    if (Logout()) {
        cerr << ">>: Logout error" << endl;
    } else {
        cerr << ">>: Logout successful" << endl;
    }

}

void enlist_tokens() {

    unique_ptr<uint8_t[]> tokens_buffer = make_unique<uint8_t[]>(2048);
    uint16_t buffersize;
    cerr << "\n>>: Enlist tokens in progress" << endl;

    if(TokenList(tokens_buffer.get(),&buffersize))
    {
        cerr << ">>: FRclone HSM token list error" << endl;
    } else {
        cerr << ">>: FRclone HSM tokens:" << endl;
        cerr << tokens_buffer.get() << endl;
    }

}

void device_enc() {

    int32_t c, b=0;
    unique_ptr<uint8_t[]> in_buffer; // plaintext only
    unique_ptr<uint8_t[]> enc_buffer; // ciphertext + Auth Tag
    uint16_t inbuffer_len = 0, outbuffer_len=0;
    uint32_t sessionId;

    cerr << "\n>>: Encryption in progress" << endl;

    in_buffer = make_unique<uint8_t[]>(buffer_size);
    enc_buffer = make_unique<uint8_t[]>(buffer_size+MV_CHACHA20_DIGEST_SIZE);

    //Reset Cipher with IV and AAD
    EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, NULL,
            0, enc_buffer.get(), &outbuffer_len);

    // process full blocks + output OR get last block
    while( (c=getchar()) != EOF ) {
        in_buffer[b++]=c;

        if(b==buffer_size)
        {
            EncBake(&sessionId, 0, NULL, NULL, 0, in_buffer.get(),
                    buffer_size, enc_buffer.get(), &outbuffer_len);
            fwrite(enc_buffer.get(),1,outbuffer_len,stdout);
            b=0;
        }
    }

    //if b> 0: process last block + finish cipher (& getMac) + fwrite
    //-else just finish cipher (& getMac)
    if(b>0){
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, in_buffer.get(),
                b, enc_buffer.get(), &outbuffer_len);
        fwrite(enc_buffer.get(),1,outbuffer_len-MV_CHACHA20_DIGEST_SIZE,stdout);
    } else {
        EncBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, NULL,
                0, enc_buffer.get(), &outbuffer_len);
        //fwrite(enc_buffer.get(),1,outbuffer_len,stdout);
    }

}

void device_dec() {

    int32_t c, b=0;
    unique_ptr<uint8_t[]> in_buffer;
    unique_ptr<uint8_t[]> dec_buffer;
    uint16_t inbuffer_len = 0, outbuffer_len=0;
    uint32_t sessionId;

    cerr << "\n>>: Decryption in progress" << endl;

    in_buffer = make_unique<uint8_t[]>(buffer_size); // ciphertext + Auth Tag
    dec_buffer = make_unique<uint8_t[]>(buffer_size+MV_CHACHA20_DIGEST_SIZE); // plaintext + Auth Tag

    //Reset Cipher with IV and AAD
    DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_INIT | FRcloneCodes::FRCLONE_OPFLAG_AAD, iv, aad, 16, NULL,
            0, dec_buffer.get(), &outbuffer_len);

    // process full blocks + output OR get last block
    while( (c=getchar()) != EOF ) {
        in_buffer[b++]=c;

        if(b==buffer_size)
        {
            DecBake(&sessionId, 0, NULL, NULL, 0, in_buffer.get(),
                    buffer_size, dec_buffer.get(), &outbuffer_len);
            fwrite(dec_buffer.get(),1,outbuffer_len,stdout);
            b=0;
        }
    }

    //if b> 0: process last block + finish cipher (& getMac) + fwrite
    //-else just finish cipher (& getMac)
    if(b>0){
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, in_buffer.get(),
                b, dec_buffer.get(), &outbuffer_len);
        fwrite(dec_buffer.get(),1,outbuffer_len-MV_CHACHA20_DIGEST_SIZE,stdout);
    } else {
        DecBake(&sessionId, FRcloneCodes::FRCLONE_OPFLAG_FIN, NULL, NULL, 0, NULL,
                0, dec_buffer.get(), &outbuffer_len);
        //fwrite(dec_buffer.get(),1,outbuffer_len,stdout);
    }
}


void device_audit() {

    unique_ptr<uint8_t[]> pcr_buffer = make_unique<uint8_t[]>(MV_PCRSIZE);
    uint16_t pcrsize;

    cerr << ">>: Device audit in progress" << endl;

    if(DeviceAuditLogin(pin_admin))
    {
        cerr << ">>: FRclone HSM login error" << endl;
        return;
    }


    if(GetPCR(pcr_buffer.get(), &pcrsize))
    {
        cerr << ">>: GetPCR error" << endl;
    } else {
        cerr << ">>: PCR value: ";
        for (int n = 0; n < pcrsize; n++) {
            printf("%02x ", pcr_buffer[n]);
        }
        cerr << endl;
    }
}

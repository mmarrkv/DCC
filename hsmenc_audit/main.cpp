#include <iostream>
#include <memory>
#include <cstring>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/sha3.h>

using namespace std;

#define MV_PCR_RES_OK                                    ( 0)
#define MV_PCR_RES_INVALID_CONTEXT                       (-1)
#define MV_PCR_RES_CANNOT_ALLOCATE_CONTEXT               (-2)
#define MV_PCR_RES_INVALID_KEY_SIZE                      (-3)
#define MV_PCR_RES_INVALID_ARGUMENT                      (-4)
#define MV_PCR_RES_INVALID_MODE                          (-5)

#define MV_PCRSIZE  32

long buffer_size = 1024;

byte curr_pcr[WC_SHA3_256_DIGEST_SIZE] = {
        0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD, 0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD,
        0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD, 0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD
};

byte new_pcr[WC_SHA3_256_DIGEST_SIZE] = {
        0x0
};


void usage(char **argv);
int MV_PCR_Extend (const long datain_len, char* datain, byte *hash);


int main(int argc, char *argv[]) {

    char opt;
    unique_ptr<char[]> in_buffer;
    int c, b=0;


    while ((opt = ::getopt(argc, argv, "b:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv);
                exit(EXIT_SUCCESS);
            case 'b':
                if(sscanf(optarg, "%lu", &buffer_size)<1) {
                    usage(argv);
                    exit(EXIT_SUCCESS);
                }
                break;
            default:
                usage(argv);
                exit(EXIT_SUCCESS);
        }

    }

    in_buffer = make_unique<char[]>(buffer_size);
    while( (c=getchar()) != EOF ) {
        in_buffer[b++]=c;

        if(b==buffer_size)
        {
            MV_PCR_Extend(b, in_buffer.get(), new_pcr);
            b=0;
            memcpy(curr_pcr,new_pcr,WC_SHA3_256_DIGEST_SIZE);
        }
    }

    //if b> 0: process last block
    if(b>0) {
        MV_PCR_Extend(b, in_buffer.get(), new_pcr);
        memcpy(curr_pcr,new_pcr,WC_SHA3_256_DIGEST_SIZE);
    }

    printf("PCR value: ");

    for(int i=0; i< WC_SHA3_256_DIGEST_SIZE;i++) {
        printf("%02x ", curr_pcr[i]);
    }
    printf("\n");

    return EXIT_SUCCESS;

}

void usage(char **argv)
{
    cerr 	<< "Usage: " << argv[0] << " [-h] [-b buffer_size]"
            << endl
            << "Available options: " << endl
            << "  -h                       Show this help" << endl
            << "  -b <buffer_size bytes>   Buffer size to use (default: 1024)" << endl;
    exit(EXIT_FAILURE);


}


int MV_PCR_Extend (const long datain_len, char* datain, byte *hash)
{
    wc_Sha3  sha;

    byte  hashcopy[WC_SHA3_256_DIGEST_SIZE];
    int ret;
    static int devId = INVALID_DEVID;

    //init hash
    ret = wc_InitSha3_256(&sha, NULL, devId);
    if (ret != 0)
        return MV_PCR_RES_INVALID_MODE;

    // pass in pcr bytes
    ret = wc_Sha3_256_Update(&sha, (byte*)curr_pcr,
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


    return MV_PCR_RES_OK;
}


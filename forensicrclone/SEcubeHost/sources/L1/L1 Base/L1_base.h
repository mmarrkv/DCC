/**
 * @file	L1_base.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the L1Base library
 *
 * The file contains all the prototypes of the L1Base library
 */

#ifndef _L1_BASE_H
#define _L1_BASE_H

#include "../../L0/L0 Base/L0_base.h"
#include "../Crypto Libraries/aes256.h"
#include "../../L0/L0_error_manager.h"
#include "../Crypto Libraries/pbkdf2.h"
#include "../L1_error_manager.h"

#include "../L1_enumerations.h"

//AES
#define B5_AES_256              32  /**< Key Size in Bytes. */
//SHA
#ifndef B5_SHA256_DIGEST_SIZE
#define B5_SHA256_DIGEST_SIZE       32
#endif

#define B5_AES256_CBC_ENC       4       /**< CBC encryption */
#define B5_AES256_CBC_DEC       5       /**< CBC decryption */
#ifndef B5_AES_BLK_SIZE
#define B5_AES_BLK_SIZE         16  /**< Block Size in Bytes. */
#endif

//frclone
#define MV_CHACHA20_KEY_SIZE 32
#define MV_CHACHA20_IV_SIZE 12
#define MV_CHACHA20_DIGEST_SIZE 16
#define MV_SHA3_256_DIGEST_SIZE 32
#define MV_ACCTOKENSIZE 163
#define MV_RFRSHTOKENSIZE 103

#define MV_PCRSIZE 32
#define MV_ACCTOKENSIZEMAX 2048
#define MV_RFRSHTOKENSIZEMAX 512


enum{
    SESSKEY_ID = 4,
    ACC_TKN_PLCHLDR_ID = 5,
    RFRSH_TKN_PLCHLDR_ID = 6,
    ACC_TKN_ID = 7,
    RFRSH_TKN_ID = 8,
    PCR_ID = 9
};
//frclone

enum{
	FIND_KEY_NUM = 50
};

typedef enum se3_access_type_ {
    SE3_ACCESS_NONE = 0,
	SE3_ACCESS_USER = 100,
    SE3_ACCESS_ADMIN = 1000,
    SE3_ACCESS_MAX = 0xFFFF
} se3_access_type;

typedef struct se3PayloadCryptoctx_ {
	B5_tAesCtx aesenc;
    B5_tAesCtx aesdec;
	B5_tHmacSha256Ctx hmac;
	uint8_t hmacKey[B5_AES_256];
    uint8_t auth[B5_SHA256_DIGEST_SIZE];
} se3PayloadCryptoctx;

/** \brief SEcube Communication session structure */
typedef struct se3Session_ {
	//se3Device device;
	uint8_t token[L1Parameters::Size::TOKEN];
	uint8_t key[L1Parameters::Size::KEY];
	uint8_t buf[L0Communication::Parameter::COMM_N * L0Communication::Parameter::COMM_BLOCK];
	bool locked;
	bool logged_in;
	uint32_t timeout;
	se3File hfile;
	se3PayloadCryptoctx cryptoctx;
	bool cryptoctx_initialized;
	se3_access_type access_type;
} se3Session;

/** \brief SEcube Algorithm structure */
typedef struct se3Algo_ {
	uint8_t name[L1Crypto::AlgorithmInfoSize::NAME_SIZE];
	uint16_t type;
	uint16_t blockSize;
	uint16_t keySize;
} se3Algo;

/** \brief SEcube Key structure */
typedef struct se3Key_ {
	uint32_t id;
	uint32_t validity;
	uint16_t dataSize;
	uint16_t nameSize;
	uint8_t* data;
	uint8_t name[L1Key::Size::MAX_NAME];
} se3Key;

class L1Base {
private:
	std::vector<se3Session> s;
	//se3Session s;
	uint8_t ptr;
public:
	L1Base();
	~L1Base();

	void SwitchToSession(uint8_t sPtr);
	//fills the list of sessions (one session for each device connected)
	void InitializeSession(uint8_t nSessions);
	//fill the session buffer with tha data passed as parameter
	void FillSessionBuffer(uint8_t* data, size_t offset, size_t len);
	//fill the session buffer with 0
	void FillSessionBuffer(size_t offset, size_t len);
	uint8_t* GetSessionBuffer();
	bool GetSessionLoggedIn();
	void SetSessionLoggedIn(bool logged);
	se3_access_type GetSessionAccessType();
	void SetSessionAccessType(se3_access_type access);
	bool GetSessionCryptoInitialized();
	B5_tAesCtx* GetSessionCryptoctxAesenc();
	B5_tAesCtx* GetSessionCryptoctxAesdec();
	void SetSessionCryptoctxHmacKey(uint8_t* keys, size_t offset, size_t len);
	uint8_t* GetSessionCryptoctxHmacKey();
	B5_tHmacSha256Ctx* GetSessionCryptoctxHmac();
	void SetCryptoctxInizialized(bool init);
	uint8_t* GetSessionKey();
	uint8_t* GetSessionToken();
	void SetSessionToken(size_t offset, size_t len);
	uint8_t* GetSessionCryptoctxAuth();
	void ReadSessionBuffer(uint8_t* retData, size_t offset, size_t len);
	bool CompareSessionBuf(uint8_t* cmpData, size_t offset, size_t len);
	// @matteo: added to support SEfile
	se3Session *GetCurrentSession();
};

#endif

/**
 * @file	L1.cpp
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Implementation of the L1 methods
 *
 * The file contains the implementation of the methods that belong directly to the L1 LIBRARY (doesn't include the implementation of the APIs)
 */

#include "L1.h"

//to delete this include
#include <stdio.h>

//private

using namespace std;

void L1::SessionInit() {
	this->base.InitializeSession(this->GetNumberDevices());
}

L1::L1() { // default constructor
	this->SessionInit();
	for (size_t i = 0; i < this->GetNumberDevices(); i++){
		this->L0Open(i);
	}
	this->index = 255; // never used, except by SEkey initialization API for the SEcube of the users
}

L1::L1(uint8_t indx) { // used by SEkey, target a specific SEcube
	this->base.InitializeSession(1);
	this->L0Open(indx);
	this->index = indx;
}

L1::~L1() {
	if(this->index != 255){ // this is used by SEkey
		if (this->base.GetSessionLoggedIn()){
			L1Logout();
		}
		this->L0Close(this->index); // added to remove memory leakage of se3file
	} else { // this is used always except for a particular case of SEkey
		for (uint8_t i = 0; i < this->GetNumberDevices(); i++) {
			this->base.SwitchToSession(i);
			if (this->base.GetSessionLoggedIn()){
				L1Logout();
			}
			this->L0Close(i); // added to remove memory leakage of se3file
		}
	}
}

void L1::PrepareSessionBufferForChallenge(uint8_t* cc1, uint8_t* cc2, uint16_t access) {
	//get a byte pointer for the 2 bytes variable (access)
	uint8_t* _access = (uint8_t*)&access;

	this->base.FillSessionBuffer(	cc1,
									L1Response::Offset::DATA + L1ChallengeRequest::Offset::CC1,
									L1Parameters::Size::CHALLENGE);
	this->base.FillSessionBuffer(	cc2,
									L1Response::Offset::DATA + L1ChallengeRequest::Offset::CC2,
									L1Parameters::Size::CHALLENGE);
	this->base.FillSessionBuffer(	_access,
									L1Response::Offset::DATA + L1ChallengeRequest::Offset::ACCESS,
									2);
}

//public

void L1::TXRXData(uint16_t cmd, uint16_t reqLen, uint16_t cmdFlags, uint16_t* respLen) {
	//SET THE HEADERS
	if (this->base.GetSessionLoggedIn())
		//fill the buffer with the token
		this->base.FillSessionBuffer(	this->base.GetSessionToken(),
										L1Request::Offset::TOKEN,
										L1Parameters::Size::TOKEN);
	else
		//fill the buffer with 0s
		this->base.FillSessionBuffer(	L1Request::Offset::TOKEN,
										L1Parameters::Size::TOKEN);

	uint8_t* _cmd = (uint8_t*)&cmd;
	uint8_t* _reqLen = (uint8_t*)&reqLen;

	uint8_t* reqIv = this->base.GetSessionBuffer() + L1Request::Offset::IV;

	this->base.FillSessionBuffer(_cmd, L1Request::Offset::CMD, 2);
	this->base.FillSessionBuffer(_reqLen, L1Request::Offset::LEN, 2);

	uint16_t reqLenPadded = reqLen;
	if (reqLenPadded % L1Parameters::Size::CRYPTO_BLOCK != 0) {
		//fill the buffer with 0s in the request length pat
		this->base.FillSessionBuffer(	reqLenPadded + L1Response::Offset::DATA,
										L1Parameters::Size::CRYPTO_BLOCK - (reqLenPadded % L1Parameters::Size::CRYPTO_BLOCK));
										reqLenPadded += L1Parameters::Size::CRYPTO_BLOCK - (reqLenPadded % L1Parameters::Size::CRYPTO_BLOCK);
	}

	//ENCRYPT
	//check if the session is not initialized
	if (!this->base.GetSessionCryptoInitialized()) {
		//if not initialize it
		Se3PayloadCryptoInit();
		this->base.SetCryptoctxInizialized(true);
	}

	if (cmdFlags & L1Commands::Flags::ENCRYPT)
		L0Support::Se3Rand(L1Parameters::Size::CRYPTO_BLOCK, reqIv);
	else
		this->base.FillSessionBuffer(L1Request::Offset::IV, L1Parameters::Size::CRYPTO_BLOCK);

	uint16_t req0Len = L1Request::Offset::DATA + reqLenPadded;
	uint8_t* reqAuth = this->base.GetSessionBuffer() + L1Request::Offset::AUTH;

	Se3PayloadEncrypt(	cmdFlags,
						this->base.GetSessionBuffer() + L1Request::Offset::IV,
						this->base.GetSessionBuffer() + L1Parameters::Size::AUTH + L1Parameters::Size::IV,
						(req0Len - L1Parameters::Size::AUTH - L1Parameters::Size::IV) / L1Parameters::Size::CRYPTO_BLOCK,
						reqAuth);

	uint16_t resp0Len = L0Communication::Parameter::COMM_N * L0Communication::Parameter::COMM_BLOCK;

	uint16_t respStatus;
	L1TXRXException commExc;
	bool dataSent = false;

	while(!dataSent) {
		try {
			L0::L0TXRX(L0Commands::Command::L1_CMD0, cmdFlags, req0Len, this->base.GetSessionBuffer(), &respStatus, &resp0Len, this->base.GetSessionBuffer());
			dataSent = true;
		}
		catch(const L0NoDeviceOpenedException& e) {
			printf("The device was closed!!!\n");
			L0Open();
		}
		catch (const std::exception& e){
			cout << e.what() << endl;
			throw commExc;
		}
		catch(...) {
			printf("Other exception\n");
			throw commExc;
		}

        if(respStatus == L1Error::Error::SE3_ERR_OPENED)
        {
            L1AlreadyOpenException alreadyOpenExc;
            throw alreadyOpenExc;
        }
        else if(respStatus != L1Error::Error::OK)
        {
            cout << "[L1.cpp - L1::TXRXData] Debug: Response status from L0::L0TXRX -> " << respStatus <<endl;
            L0TXRXException l0TxRxExc;
            throw l0TxRxExc;

        }
	}


	//DECRYPT
	uint8_t* respIv = this->base.GetSessionBuffer() + L1Response::Offset::IV;
	uint8_t* resp_auth = this->base.GetSessionBuffer() + L1Response::Offset::AUTH;
	L1CommunicationError payloadDecryptExc;

	try {
	Se3PayloadDecrypt(	cmdFlags,
						respIv,
						this->base.GetSessionBuffer() + L1Parameters::Size::AUTH + L1Parameters::Size::IV,
						(resp0Len - L1Parameters::Size::AUTH - L1Parameters::Size::IV) / L1Parameters::Size::CRYPTO_BLOCK,
						resp_auth);
	}
	catch (L1Exception& e) {
		//SE3TRACE(("[L0d_cmd1] AUTH failed\n"));
		throw payloadDecryptExc;
	}

	uint16_t u16tmp;

	memcpy((void*)&u16tmp, (const void*)(this->base.GetSessionBuffer() + L1Response::Offset::LEN), 2);
	*respLen = u16tmp;
	memcpy((void*)&u16tmp, (const void*)(this->base.GetSessionBuffer() + L1Response::Offset::STATUS), 2);

	//printf("[L1::TXRXData] Debug: u16tmp -> %d\n", u16tmp);
//printf("status: %d\n",u16tmp);
	if (u16tmp != L0ErrorCodes::Error::OK)
		throw commExc;
}

void L1::Se3PayloadCryptoInit() {
	uint8_t keys[2 * B5_AES_256];
	PBKDF2HmacSha256(this->base.GetSessionKey(), B5_AES_256, NULL, 0, 1, keys, 2 * B5_AES_256);
	B5_Aes256_Init(this->base.GetSessionCryptoctxAesenc(), keys, B5_AES_256, B5_AES256_CBC_ENC);
	B5_Aes256_Init(this->base.GetSessionCryptoctxAesdec(), keys, B5_AES_256, B5_AES256_CBC_DEC);
	this->base.SetSessionCryptoctxHmacKey(keys + B5_AES_256, 0, B5_AES_256);
}

void L1::Se3PayloadEncrypt(uint16_t flags, uint8_t* iv, uint8_t* data, uint16_t nBlocks, uint8_t* auth) {

    if (flags & L1Commands::Flags::ENCRYPT) {
        B5_Aes256_SetIV(this->base.GetSessionCryptoctxAesenc(), iv);
        B5_Aes256_Update(this->base.GetSessionCryptoctxAesenc(), data, data, nBlocks);
    }

    if (flags & L1Commands::Flags::SIGN) {
        B5_HmacSha256_Init(this->base.GetSessionCryptoctxHmac(), this->base.GetSessionCryptoctxHmacKey(), B5_AES_256);
        B5_HmacSha256_Update(this->base.GetSessionCryptoctxHmac(), iv, B5_AES_IV_SIZE);
        B5_HmacSha256_Update(this->base.GetSessionCryptoctxHmac(), data, nBlocks * B5_AES_BLK_SIZE);
        B5_HmacSha256_Finit(this->base.GetSessionCryptoctxHmac(), this->base.GetSessionCryptoctxAuth());
        memcpy(auth, this->base.GetSessionCryptoctxAuth(), 16);
    }
    else {
        memset(auth, 0, 16);
    }
}

void L1::Se3PayloadDecrypt(uint16_t flags, const uint8_t* iv, uint8_t* data, uint16_t nBlocks, const uint8_t* auth) {
	L1PayloadDecryptionException PayloadDecExc;

    if (flags & L1Commands::Flags::SIGN) {
        B5_HmacSha256_Init(this->base.GetSessionCryptoctxHmac(), this->base.GetSessionCryptoctxHmacKey(), B5_AES_256);
        B5_HmacSha256_Update(this->base.GetSessionCryptoctxHmac(), iv, B5_AES_IV_SIZE);
        B5_HmacSha256_Update(this->base.GetSessionCryptoctxHmac(), data, nBlocks * B5_AES_BLK_SIZE);
        B5_HmacSha256_Finit(this->base.GetSessionCryptoctxHmac(), this->base.GetSessionCryptoctxAuth());
        if (memcmp(auth, this->base.GetSessionCryptoctxAuth(), 16)) {
            throw PayloadDecExc;
        }
    }

    if (flags & L1Commands::Flags::ENCRYPT) {
        B5_Aes256_SetIV(this->base.GetSessionCryptoctxAesdec(), iv);
        B5_Aes256_Update(this->base.GetSessionCryptoctxAesdec(), data, data, nBlocks);
    }
}

void L1::L1Config(uint16_t type, uint16_t op, uint8_t* value) {
	this->base.FillSessionBuffer(	(uint8_t*)&type,
									L1Response::Offset::DATA + L1Configuration::RequestOffset::CONFIG_ID,
									2);
	this->base.FillSessionBuffer(	(uint8_t*)&op,
									L1Response::Offset::DATA + L1Configuration::RequestOffset::CONFIG_OP,
									2);

	if(op == L1Configuration::Operation::GET)
		this->base.FillSessionBuffer(	L1Response::Offset::DATA + L1Configuration::RequestOffset::CONFIG_VALUE,
										L1Configuration::RecordSize::RECORD_SIZE);

	if(op == L1Configuration::Operation::SET)
		this->base.FillSessionBuffer(	value,
										L1Response::Offset::DATA + L1Configuration::RequestOffset::CONFIG_VALUE,
										L1Parameters::Size::PIN);

	uint16_t dataLen = 2 + 2 + L1Configuration::RecordSize::RECORD_SIZE;
	uint16_t respLen = 0;
	L1ConfigException configExc;

	try {
		TXRXData(L1Commands::Codes::CONFIG, dataLen, 0, &respLen);
	}
	catch(L1Exception& e) {
		throw configExc;
	}

	//read the response
	if(op == L1Configuration::Operation::GET)
		this->base.ReadSessionBuffer(	value,
										L1Response::Offset::DATA + L1Configuration::ResponseOffset::CONFIG_VALUE,
										L1Configuration::RecordSize::RECORD_SIZE);
}

void L1::L1FactoryInit(uint8_t* serialno) {
 this->L0FactoryInit(serialno);
}

void L1::SelectSession(uint8_t sPtr) {
	L1SelectDeviceException selectDevExc;
	if (!this->SwitchToDevice(sPtr)){
		throw selectDevExc;
	}
	this->base.SwitchToSession(sPtr);
}

se3_access_type L1::L1GetAccessType(){
	return this->base.GetSessionAccessType();
}

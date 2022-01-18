/**
 * @file	L1.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototype of the L1 library
 *
 * The file contains the prototype of the whole L1 LIBRARY, including all the APIs
 */

#ifndef L1_H /* guard for header inclusion */
#define L1_H

#include "../L0/L0.h"
#include "L1 Base/L1_base.h"
#include "Login-Logout API/login_logout_api.h"
#include "Security API/security_api.h"
#include "Utility API/utility_api.h"

class L1 : private L0, public LoginLogoutApi, public SecurityApi, public UtilityApi {
private:
	L1Base base;
	uint8_t index; // this is used only by SEkey to support multiple SEcube connected to the same host computer (default value 255)
	void SessionInit();
	//overriding
	void PrepareSessionBufferForChallenge(uint8_t* cc1, uint8_t* cc2, uint16_t access);
	void TXRXData(uint16_t cmd, uint16_t reqLen, uint16_t cmdFlags, uint16_t* respLen);
	void Se3PayloadCryptoInit();
	void Se3PayloadEncrypt(uint16_t flags, uint8_t* iv, uint8_t* data, uint16_t nBlocks, uint8_t* auth);
	void Se3PayloadDecrypt(uint16_t flags, const uint8_t* iv, uint8_t* data, uint16_t nBlocks, const uint8_t* auth);
	void L1Config(uint16_t type, uint16_t op, uint8_t* value);
	//security api private methods
	void KeyList(uint16_t maxKeys, uint16_t skip, se3Key* keyArray, uint16_t* count);
public:
	L1();
	L1(uint8_t index);
	~L1();
	//LOGIN-LOGOUT API
	void L1Login(const uint8_t* pin, uint16_t access, bool force);
	void L1Logout();
	void L1LogoutForced();
	bool L1GetSessionLoggedIn(){ return this->base.GetSessionLoggedIn(); }
	se3_access_type L1GetAccessType();
	//SECURITY API
	void L1CryptoSetTime(uint32_t devTime);
	void L1CryptoInit(uint16_t algorithm, uint16_t mode, uint32_t keyId, uint32_t* sessId);
	void L1CryptoUpdate(uint32_t sessId, uint16_t flags, uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2, uint16_t* dataOutLen, uint8_t* dataOut);
	void L1Encrypt(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm, uint16_t mode, uint32_t keyId);
	void L1Decrypt(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm, uint16_t mode, uint32_t keyId);
	void L1Digest(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm);
	void L1GetAlgorithms(uint16_t maxAlgorithms, uint16_t skip, se3Algo* algorithmsArray, uint16_t* count);
	void L1SetAdminPIN(uint8_t* pin);
	void L1SetUserPIN(uint8_t* pin);
	void L1KeyEdit(se3Key* k, uint16_t op);
	void L1KeyList(uint16_t maxKeys, uint16_t skip, se3Key* keyArray, uint16_t* count);
	bool L1FindKey(uint32_t keyId);
	//other functionalities
	void SelectSession(uint8_t sPtr);
	void L1FactoryInit(uint8_t* serialno);
	uint8_t *GetDeviceSerialNumber(){return this->GetDeviceSn();}
	// these functions were added to implement SEkey, they must not be used elsewhere
	bool L1SEkeyInfo(std::string& id, std::string& name, uint8_t mode);
	bool L1GetKeyEnc(uint32_t key_id, uint32_t k2, uint8_t *key_data, uint16_t key_len);
	void L1SEkeyMaintenance(uint8_t *buffer, uint16_t *buflen);
	bool L1DeleteKey(uint32_t key_id);
	bool L1DeleteAllKeys(std::vector<uint32_t>& keep);
	bool L1InsertKey(uint32_t key_id, uint16_t key_len, uint32_t dec_id, uint8_t *key_data);
};

#endif /* L1_H */

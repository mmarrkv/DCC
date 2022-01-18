/**
 * @file	security_api.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the SECURITY API
 *
 * The file contains all the prototypes of the SECURITY API
 */

#include "../L1 Base/L1_base.h"

class SecurityApi {
private:
	virtual void KeyList(uint16_t maxKeys, uint16_t skip, se3Key* keyArray, uint16_t* count) = 0;
public:
	virtual ~SecurityApi() {};
	virtual void L1KeyList(uint16_t maxKeys, uint16_t skip, se3Key* keyArray, uint16_t* count) = 0;
	virtual void L1KeyEdit(se3Key* k, uint16_t op) = 0;
	virtual bool L1FindKey(uint32_t keyId) = 0;
	virtual void L1CryptoInit(uint16_t algorithm, uint16_t mode, uint32_t keyId, uint32_t* sessId) = 0;
	virtual void L1CryptoUpdate(uint32_t sessId, uint16_t flags, uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2, uint16_t* dataOutLen, uint8_t* dataOut) = 0;
	virtual void L1CryptoSetTime(uint32_t devTime) = 0;
	virtual void L1Encrypt(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm, uint16_t mode, uint32_t keyId) = 0;
	virtual void L1Decrypt(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm, uint16_t mode, uint32_t keyId) = 0;
	virtual void L1Digest(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm) = 0;
	virtual void L1GetAlgorithms(uint16_t maxAlgorithms, uint16_t skip, se3Algo* algorithmsArray, uint16_t* count) = 0;
};

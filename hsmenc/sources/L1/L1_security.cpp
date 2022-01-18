/**
 * @file	L1_login_logout.cpp
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Implementation of the SECURITY API
 *
 * The file contains the implementation of the SECURITY API
 */

#include "L1.h"
#include "L1_error_manager.h"

using namespace std;

void L1::L1CryptoSetTime(uint32_t devTime) {
	uint8_t* time;
	uint16_t respLen = 0;
	L1CryptoSetTimeException cryptoTimeExc;

	time = (uint8_t*)&devTime;


	this->base.FillSessionBuffer(	time,
									L1Response::Offset::DATA + L1Crypto::SetTimeRequestOffset::DEV_TIME,
									4);

	try {
		TXRXData(	L1Commands::Codes::SET_TIME,
					L1Crypto::SetTimeRequestSize::SIZE,
					0,
					&respLen);
	}
	catch(L1Exception& e) {
		throw cryptoTimeExc;
	}
}

void L1::L1CryptoInit(uint16_t algorithm, uint16_t mode, uint32_t keyId, uint32_t* sessId) {
	uint8_t* _algo = (uint8_t*)&algorithm;
	uint8_t* _mode = (uint8_t*)&mode;
	uint8_t* _keyId = (uint8_t*)&keyId;
	uint16_t respLen = 0;

	this->base.FillSessionBuffer(	_algo,
									L1Response::Offset::DATA + L1Crypto::InitRequestOffset::ALGO,
									2);
	this->base.FillSessionBuffer(	_mode,
									L1Response::Offset::DATA + L1Crypto::InitRequestOffset::MODE,
									2);
	this->base.FillSessionBuffer(	_keyId,
									L1Response::Offset::DATA + L1Crypto::InitRequestOffset::KEY_ID,
									4);

	L1CryptoInitException cryptoInitExc;

	//send the data
	try {
		TXRXData(	L1Commands::Codes::CRYPTO_INIT,
					L1Crypto::InitRequestSize::SIZE,
					0,
					&respLen);
	}
	catch(L1Exception& e) {
		throw cryptoInitExc;
	}

	uint32_t u32Tmp = 0;

	this->base.ReadSessionBuffer((uint8_t*)&u32Tmp, L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::SID, 4);

	*sessId = u32Tmp;
}

void L1::L1CryptoUpdate(uint32_t sessId, uint16_t flags, uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2, uint16_t* dataOutLen, uint8_t* dataOut) {
	uint8_t* _sessId = (uint8_t*)&sessId;
	uint8_t* _flags = (uint8_t*)&flags;
	uint8_t* _data1Len = (uint8_t*)&data1Len;
	uint8_t* _data2Len = (uint8_t*)&data2Len;

	/* versione originale, notare come si usano 4 byte anche per tipi che in realtà sono uint16_t, probabilmente errore del programmatore */
	/*this->base.FillSessionBuffer(	_sessId,
									L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::SID,
									4);
	this->base.FillSessionBuffer(	_flags,
									L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::FLAGS,
									4);
	this->base.FillSessionBuffer(	_data1Len,
									L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::DATAIN1_LEN,
									4);
	this->base.FillSessionBuffer(	_data2Len,
									L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::DATAIN2_LEN,
									4);*/

	/* @matteo: versione modificata usando 2 byte invece di 4 */
	this->base.FillSessionBuffer(	_sessId,
										L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::SID,
										4);
		this->base.FillSessionBuffer(	_flags,
										L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::FLAGS,
										2);
		this->base.FillSessionBuffer(	_data1Len,
										L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::DATAIN1_LEN,
										2);
		this->base.FillSessionBuffer(	_data2Len,
										L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::DATAIN2_LEN,
										2);

	//compute the offset for Data2
	uint16_t data1LenPadded =	data1Len % 16 != 0 ?				//is data1Len not a multiple of 16?
								data1Len + (16 - (data1Len % 16)) :	//if it's not the wrap it
								data1Len;							//if it is the just assign it

	//check if the buffer length is exceeded
	L1CryptoUpdateException cryptoUpdateExc;
	uint16_t dataLen = L1Crypto::UpdateRequestOffset::DATA + data1LenPadded + data2Len;

	if (dataLen > L1Request::Size::MAX_DATA)
		throw cryptoUpdateExc;

	//fill the buffer with data1
	if (data1Len > 0)
		this->base.FillSessionBuffer(	data1,
										L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::DATA,
										data1Len);
	//fill the buffer with data2
	if (data2Len > 0)
		this->base.FillSessionBuffer(	data2,
										L1Response::Offset::DATA + L1Crypto::UpdateRequestOffset::DATA + data1LenPadded,
										data2Len);

	//send the data
	uint16_t respLen;
	try {
		TXRXData(	L1Commands::Codes::CRYPTO_UPDATE,
					dataLen,
					0,
					&respLen);
	}
	catch(L1Exception& e) {
		throw cryptoUpdateExc;
	}

	uint16_t u16tmp;
	this->base.ReadSessionBuffer(	(uint8_t*)&u16tmp,
									L1Response::Offset::DATA + L1Crypto::UpdateResponseOffset::DATAOUT_LEN,
									2);	//extract the data length
	if(dataOutLen != NULL)
		*dataOutLen = u16tmp;
	if(dataOut != NULL)
		memcpy(	dataOut,																						//extract the data
				this->base.GetSessionBuffer() + L1Response::Offset::DATA + L1Crypto::UpdateResponseOffset::DATA,
				u16tmp);
}

void L1::L1Encrypt(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm, uint16_t mode, uint32_t keyId) {
	L1EncryptException encryptExc;

	if(dataInLen < 0 || dataOut == NULL)
		throw encryptExc;

	uint32_t encSessId = 0;

	try {
		L1CryptoInit(algorithm, mode, keyId, &encSessId);
	}
	catch (L1Exception& e) {
		throw encryptExc;
	}

	if(dataOutLen != NULL)
		*dataOutLen = 0;

	size_t currChunk = dataInLen < L1Crypto::UpdateSize::DATAIN ? dataInLen : L1Crypto::UpdateSize::DATAIN;

	if((algorithm & L1Algorithms::Algorithms::AES_HMAC) && currChunk == L1Crypto::UpdateSize::DATAIN)
		currChunk -= B5_SHA256_DIGEST_SIZE;

	uint8_t* _dataIn = dataIn;
	uint8_t* _dataOut = dataOut;
	uint16_t currLen = 0;

	do {
		try {
			if(dataInLen - currChunk)
				L1CryptoUpdate(encSessId, mode, 0, NULL, (uint16_t)currChunk, _dataIn, &currLen, _dataOut);
			else
				L1CryptoUpdate(	encSessId,
								L1Crypto::UpdateFlags::FINIT | mode,
								0,
								NULL,
								(uint16_t)currChunk,
								_dataIn,
								&currLen,
								_dataOut);
		}
		catch (L1Exception& e) {
			throw encryptExc;
		}

		dataInLen -= currChunk;
		//updating the pointers for the next chunk
		_dataIn += currChunk;
		_dataOut += currChunk;
		currChunk = dataInLen < L1Crypto::UpdateSize::DATAIN ? dataInLen : L1Crypto::UpdateSize::DATAIN;

		if((algorithm & L1Algorithms::Algorithms::AES_HMAC) && currChunk == L1Crypto::UpdateSize::DATAIN)
			currChunk -= B5_SHA256_DIGEST_SIZE;

		if(dataOutLen != NULL)
			*dataOutLen += currLen;
	} while(dataInLen > 0);
}

void L1::L1Decrypt(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm, uint16_t mode, uint32_t keyId) {
	L1DecryptException decryptExc;
	try {
		L1Encrypt(dataInLen, dataIn, dataOutLen, dataOut, algorithm, mode, keyId);
	}
	catch(L1Exception& e) {
		throw decryptExc;
	}
}

void L1::L1Digest(size_t dataInLen, uint8_t* dataIn, size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm) {
	L1DigestException digestExc;

	if(dataInLen < 0 || dataOut == NULL)
		throw digestExc;

	uint32_t encSessId = 0;

	try {
		L1CryptoInit(algorithm, 0, 0, &encSessId);
	}
	catch (L1Exception& e) {
		throw digestExc;
	}

	if(dataOutLen != NULL)
		*dataOutLen = 0;

	size_t currChunk = dataInLen < L1Crypto::UpdateSize::DATAIN ? dataInLen : L1Crypto::UpdateSize::DATAIN;
	//uint8_t* _dataIn = dataIn;
	uint8_t* _dataOut = dataOut;
	uint16_t currLen = 0;

	do{
		try {
			if(dataInLen - currChunk)
				L1CryptoUpdate(	encSessId,
								0,
								(uint16_t)currChunk,
								dataIn,
								0,
								NULL,
								&currLen,
								_dataOut);
			else
				L1CryptoUpdate(	encSessId,
								L1Crypto::UpdateFlags::FINIT,
								(uint16_t)currChunk,
								dataIn,
								0,
								NULL,
								&currLen,
								_dataOut);
		}
		catch(L1Exception& e) {
			throw digestExc;
		}
	}while(dataInLen > 0);
}

void L1::L1GetAlgorithms(uint16_t maxAlgorithms, uint16_t skip, se3Algo* algorithmsArray, uint16_t* count) {
	L1GetAlgorithmsException algoExc;

	//check parameters
	if(maxAlgorithms <= 0 || skip < 0)
		throw algoExc;

	uint16_t respLen = 0;

	//send requests
	try {
		TXRXData(	L1Commands::Codes::CRYPTO_LIST,
					L1Crypto::ListRequestSize::REQ_SIZE,
					0,
					&respLen);
	}
	catch(L1Exception& e) {
		throw algoExc;
	}

	uint16_t nAlgo;

	//read response
	try {
		this->base.ReadSessionBuffer(	(uint8_t*)&nAlgo,
										L1Response::Offset::DATA + L1Crypto::ListResponseOffset::COUNT,
										2);
	}
	catch(L1Exception& e) {
		throw algoExc;
	}

	size_t offsetAlgo = L1Crypto::ListResponseOffset::ALGORITHM_INFO + skip * L1Crypto::AlgorithmInfoSize::SIZE;

	size_t i;
	size_t j;

	for(i = 0, j = skip; i < maxAlgorithms && j < nAlgo; i++, j++) {
		try {
			this->base.ReadSessionBuffer(	algorithmsArray[i].name,
											L1Response::Offset::DATA + offsetAlgo + L1Crypto::AlgorithmInfoOffset::NAME,
											L1Crypto::AlgorithmInfoSize::NAME_SIZE);
			this->base.ReadSessionBuffer(	(uint8_t*)&(algorithmsArray[i].type),
											L1Response::Offset::DATA + offsetAlgo + L1Crypto::AlgorithmInfoOffset::TYPE,
											2);
			this->base.ReadSessionBuffer(	(uint8_t*)&algorithmsArray[i].blockSize,
											L1Response::Offset::DATA + offsetAlgo + L1Crypto::AlgorithmInfoOffset::BLOCK_SIZE,
											2);
			this->base.ReadSessionBuffer(	(uint8_t*)&algorithmsArray[i].keySize,
											L1Response::Offset::DATA + offsetAlgo + L1Crypto::AlgorithmInfoOffset::KEY_SIZE,
											2);
			offsetAlgo += L1Crypto::AlgorithmInfoSize::SIZE;
		}
		catch(L1Exception& e) {
			throw algoExc;
		}
	}

	*count = i;
}

void L1::L1SetAdminPIN(uint8_t* pin) {
	L1Exception exc;
	if((this->L1GetAccessType() != SE3_ACCESS_ADMIN) && (this->L1GetAccessType() != SE3_ACCESS_MAX)){
		throw exc;
	}
	return L1Config(	L1Configuration::RecordType::ADMINPIN,
						L1Configuration::Operation::SET,
						pin);
}

void L1::L1SetUserPIN(uint8_t* pin) {
	L1Exception exc;
	if((this->L1GetAccessType() != SE3_ACCESS_ADMIN) && (this->L1GetAccessType() != SE3_ACCESS_MAX)){
		throw exc;
	}
	return L1Config(	L1Configuration::RecordType::USERPIN,
						L1Configuration::Operation::SET,
						pin);
}

void L1::L1KeyEdit(se3Key* k, uint16_t op) {
	L1KeyEditException keyEditExc;

	if(k == NULL)
		throw keyEditExc;

	this->base.FillSessionBuffer(	(uint8_t*)&op,
									L1Response::Offset::DATA + L1Request::KeyOffset::OP,
									2);
	this->base.FillSessionBuffer(	(uint8_t*)&(k->id),
									L1Response::Offset::DATA + L1Request::KeyOffset::ID,
									4);
	this->base.FillSessionBuffer(	(uint8_t*)&(k->validity),
									L1Response::Offset::DATA + L1Request::KeyOffset::VALIDITY,
									4);
	this->base.FillSessionBuffer(	(uint8_t*)&(k->dataSize),
									L1Response::Offset::DATA + L1Request::KeyOffset::DATA_LEN,
									2);
	this->base.FillSessionBuffer(	(uint8_t*)&(k->nameSize),
									L1Response::Offset::DATA + L1Request::KeyOffset::NAME_LEN,
									2);
	this->base.FillSessionBuffer(	k->data,
									L1Response::Offset::DATA + L1Request::KeyOffset::DATA_AND_NAME,
									k->dataSize);
	this->base.FillSessionBuffer(	k->name,
									L1Response::Offset::DATA + L1Request::KeyOffset::DATA_AND_NAME + k->dataSize,
									k->nameSize);

	//sum all the bytes added in the buffer
	uint16_t dataLen = 2 + 4 + 4 + 2 + 2 + k->dataSize + k->nameSize;
	uint16_t respLen = 0;

	try {
		TXRXData(L1Commands::Codes::KEY_EDIT, dataLen, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &respLen);
	}
	catch(L1Exception& e) {
		throw keyEditExc;
	}
}

void L1::L1KeyList(uint16_t maxKeys, uint16_t skip, se3Key* keyArray, uint16_t* count) {
	size_t i = 0;
	uint16_t xCount = 0;

	while(i != maxKeys) {
		KeyList(maxKeys - i, skip + i, &(keyArray[i]), &xCount);
		i += xCount;
		if(xCount==0)
            break;
	}
	*count = i;
}

void L1::KeyList(uint16_t maxKeys, uint16_t skip, se3Key* keyArray, uint16_t* count) {
	L1KeyListException keyListExc;

	if(maxKeys <= 0 || skip < 0)
		throw keyListExc;

	this->base.FillSessionBuffer(	(uint8_t*)&skip,
									L1Response::Offset::DATA + L1Key::RequestListOffset::SKIP,
									2);
	this->base.FillSessionBuffer(	(uint8_t*)&maxKeys,
									L1Response::Offset::DATA + L1Key::RequestListOffset::NMAX,
									2);

	uint16_t respLen = 0;

	//send the data
	try {
		TXRXData(	L1Commands::Codes::KEY_LIST,
					L1Key::RequestListSize::SIZE,
					0,
					&respLen);
	}
	catch(L1Exception& e) {
		throw keyListExc;
	}

	uint16_t nKeys;

	//read the response
	this->base.ReadSessionBuffer(	(uint8_t*)&nKeys,
									L1Response::Offset::DATA + L1Key::ResponeListOffset::COUNT,
									2);

	uint16_t offsetKey = 2;

	for(size_t i = 0; i < nKeys; i++) {
		this->base.ReadSessionBuffer(	(uint8_t*)&keyArray[i].id,
										offsetKey + L1Response::Offset::DATA + L1Key::InfoOffset::ID,
										4);
		this->base.ReadSessionBuffer(	(uint8_t*)&keyArray[i].validity,
										offsetKey + L1Response::Offset::DATA + L1Key::InfoOffset::VALIDITY,
										4);
		this->base.ReadSessionBuffer(	(uint8_t*)&keyArray[i].dataSize,
										offsetKey + L1Response::Offset::DATA + L1Key::InfoOffset::DATA_LEN,
										2);
		this->base.ReadSessionBuffer(	(uint8_t*)&keyArray[i].nameSize,
										offsetKey + L1Response::Offset::DATA + L1Key::InfoOffset::NAME_LEN,
										2);
		this->base.ReadSessionBuffer(	keyArray[i].name,
										offsetKey + L1Response::Offset::DATA + L1Key::InfoOffset::NAME,
										keyArray[i].nameSize);
		//add all the bytes read from the buffer
		offsetKey += L1Key::InfoOffset::NAME + keyArray[i].nameSize;
	}

	*count = nKeys;
}

bool L1::L1FindKey(uint32_t keyId) {
	L1FindKeyException findKeyExc;
	se3Key keyArray[FIND_KEY_NUM];
	uint8_t i = 0;
	uint16_t count = 0;

	try {
		do{
			L1KeyList(i + FIND_KEY_NUM, i, keyArray, &count);
			for(size_t j = 0; j < count; j++){
				if(keyArray[j].id == keyId){
					return true;
				}
			}
			i += count;
		} while(count > 0);
	}
	catch(L1Exception& e) {
		throw findKeyExc;
	}
	return false;
}

bool L1::L1GetKeyEnc(uint32_t key_id, uint32_t k2, uint8_t *key_data, uint16_t key_len){
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t op, offset;
	op = L1Commands::Options::SE3_SEKEY_OP_GETKEYENC;
	offset = L1Request::Offset::DATA;
	this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
	offset += 2;
	this->base.FillSessionBuffer((unsigned char*)&key_id, offset, 4);
	offset += 4;
	this->base.FillSessionBuffer((unsigned char*)&k2, offset, 4);
	offset += 4;
	data_len = offset - L1Request::Offset::DATA;
	try{
		TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
	} catch(L1Exception& e){
		return false;
	}
	if((resp_len == 0) || (resp_len != key_len)){
		return false;
	}
	memcpy((void*)key_data, (const void*)(this->base.GetSessionBuffer()+L1Request::Offset::DATA), resp_len);
	return true;
}

bool L1::L1SEkeyInfo(string& id, string& name, uint8_t mode)
{
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	unique_ptr<char[]> resp_buffer;
	uint16_t op, offset;
	if(mode != L1SEkey::Direction::STORE && mode != L1SEkey::Direction::LOAD){
		return false;
	}
	if(mode == L1SEkey::Direction::STORE){
		op = L1Commands::Options::SE3_SEKEY_OP_SETINFO;
		offset = L1Request::Offset::DATA;
		this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
		offset += 2;
		/* contenuto della richiesta: 1B per lunghezza id, id, 1B per lunghezza nome, nome */
		uint8_t idlen = id.length();
		this->base.FillSessionBuffer((unsigned char*)&idlen, offset, 1);
		offset++;
		this->base.FillSessionBuffer((unsigned char*)id.c_str(), offset, idlen);
		offset += idlen;
		uint8_t namelen = name.length();
		this->base.FillSessionBuffer((unsigned char*)&namelen, offset, 1);
		offset++;
		this->base.FillSessionBuffer((unsigned char*)name.c_str(), offset, namelen);
		offset += namelen;
		data_len = offset - L1Request::Offset::DATA;
		try{
			TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
		} catch(L1Exception& e){
			return false;
		}
		if(resp_len != 8){
			return false;
		}
		resp_buffer = make_unique<char[]>(resp_len);
		if(resp_buffer == nullptr){
			return false;
		}
		memcpy(resp_buffer.get(), this->base.GetSessionBuffer()+L1Request::Offset::DATA, resp_len);
		char tmp[] = "SEKEY_OK";
		if(memcmp(resp_buffer.get(), tmp, 8) != 0){
			resp_buffer = nullptr;
			return false;
		}
	}
	if(mode == L1SEkey::Direction::LOAD){
		op = L1Commands::Options::SE3_SEKEY_OP_GETINFO;
		offset = L1Request::Offset::DATA;
		this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
		offset += 2;
		data_len = offset - L1Request::Offset::DATA;
		try{
			TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
		} catch(L1Exception& e){
			return false;
		}
		if(resp_len == 0){
			return false;
		}
		resp_buffer.reset();
		resp_buffer = make_unique<char[]>(resp_len);
		if(resp_buffer == nullptr){
			return false;
		}
		/* contenuto della risposta: 1B per lunghezza id, id, 1B per lunghezza nome, nome */
		memcpy(resp_buffer.get(), this->base.GetSessionBuffer()+L1Request::Offset::DATA, resp_len);
		uint8_t off = 0;
		uint8_t idlen = resp_buffer[off];
		off++;
		string tmpid(&resp_buffer[off], idlen);
		off += idlen;
		uint8_t namelen = resp_buffer[off];
		off++;
		string tmpname(&resp_buffer[off], namelen);
		id = tmpid;
		name = tmpname;
	}
	return true;
}

void L1::L1SEkeyMaintenance(uint8_t *buffer, uint16_t *buflen){
	if(buffer == nullptr && buflen != nullptr){
		*buflen = 0;
		return;
	}
	if(buflen == nullptr){
		return;
	}
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t op = L1Commands::Options::SE3_SEKEY_OP_GET_KEY_IDS;
	uint16_t offset = L1Request::Offset::DATA;
	this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
	offset += 2;
	data_len = offset - L1Request::Offset::DATA;
	try{
		TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
	} catch(L1Exception& e){
		*buflen = 0;
		return;
	}
	memcpy(buffer, (this->base.GetSessionBuffer()+L1Request::Offset::DATA), resp_len);
	*buflen = resp_len;
}

bool L1::L1DeleteAllKeys(std::vector<uint32_t>& keep){
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t op = L1Commands::Options::SE3_SEKEY_DELETEALL;
	uint16_t offset = L1Request::Offset::DATA;
	this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
	offset += 2;
	for(uint32_t key : keep){ // in case some keys have to be preserved, send their IDs to the SEcube
		this->base.FillSessionBuffer((unsigned char*)&key, offset, 4);
		offset += 4;
	}
	data_len = offset - L1Request::Offset::DATA;
	try{
		TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
	} catch(L1Exception& e){
		return false;
	}
	if(strncmp((const char*)(this->base.GetSessionBuffer()+L1Response::Offset::DATA), "OK", 2) != 0){
		return false;
	} else {
		return true;
	}
}

bool L1::L1DeleteKey(uint32_t key_id){
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t op = L1Commands::Options::SE3_SEKEY_DELETEKEY;
	uint16_t offset = L1Request::Offset::DATA;
	this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
	offset += 2;
	this->base.FillSessionBuffer((unsigned char*)&key_id, offset, 4);
	offset += 4;
	data_len = offset - L1Request::Offset::DATA;
	try{
		TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
	} catch(L1Exception& e){
		return false;
	}
	if(strncmp((const char*)(this->base.GetSessionBuffer()+L1Response::Offset::DATA), "OK", 2) != 0){
		return false;
	} else {
		return true;
	}
}

bool L1::L1InsertKey(uint32_t key_id, uint16_t key_len, uint32_t dec_id, uint8_t *key_data){
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t op = L1Commands::Options::SE3_SEKEY_INSERTKEY;
	uint16_t offset = L1Request::Offset::DATA;
	this->base.FillSessionBuffer((unsigned char*)&op, offset, 2);
	offset += 2;
	this->base.FillSessionBuffer((unsigned char*)&key_id, offset, 4);
	offset += 4;
	this->base.FillSessionBuffer((unsigned char*)&key_len, offset, 2);
	offset += 2;
	if(key_data != nullptr){ // this is in case the host wants to explicitly send the key content to the SEcube
		this->base.FillSessionBuffer((unsigned char*)&dec_id, offset, 4);
		offset+=4;
		this->base.FillSessionBuffer((unsigned char*)key_data, offset, key_len);
		offset += key_len;
	}
	data_len = offset - L1Request::Offset::DATA;
	try{
		TXRXData(L1Commands::Codes::SEKEY, data_len, L1Commands::Flags::ENCRYPT | L1Commands::Flags::SIGN, &resp_len);
	} catch(L1Exception& e){
		return false;
	}
	if(resp_len != 2){
		return false;
	}
	char okbuf[] = "OK";
	if(memcmp((const void*)(this->base.GetSessionBuffer()+L1Response::Offset::DATA), (const void*)okbuf, 2) != 0){
		return false;
	} else {
		return true;
	}
}

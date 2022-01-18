/**
 * @file	L0.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototype of the L0 library
 *
 * The file contains the prototype of the whole L0 LIBRARY, including all the APIs
 */

#include "../LH/Commodities API/commodities_api.h"
#include "Communication API/communication_api.h"
#include "Provision API/provision_api.h"
#include "L0 Base/L0_base.h"

const uint32_t SE3_TIMEOUT = 10000;

class L0 : public CommoditiesApi, public CommunicationApi, public ProvisionApi {
private:
	L0Base base;
	//COMMODITIES
	//overriding the virtual methods
	bool Se3DriveNext();
	bool Se3Info(uint64_t deadline, se3DiscoverInfo* info);
	/////////////////////
	void L0DiscoverInit();
	bool L0DiscoverNext();

	//COMMUNICATION
	bool Se3Open(uint64_t deadline, se3File* phFile, se3DiscoverInfo* disco);
	uint16_t L0TX(uint16_t cmd, uint16_t cmdFlags, uint16_t len, const uint8_t* data);
	uint16_t L0RX(uint16_t* respStatus, uint16_t* respLen, uint8_t* respData);
	//CLASS ATTRIBUTES
	int nDevices;
public:
	L0();
	~L0();
	//COMMODITIES
	bool L0DiscoverSerialNo(uint8_t* serialNo);
	//COMMUNICATION
	void L0Open(uint8_t devPtr);
	void L0Open();
	void L0Close(uint8_t devPtr);
	void L0Close();
	void L0TXRX(uint16_t reqCmd, uint16_t reqCmdFlags, uint16_t reqLen, const uint8_t* reqData, uint16_t* respStatus, uint16_t* respLen, uint8_t* respData);	//used by L1
	uint16_t L0Echo(const uint8_t* dataIn, uint16_t dataInLen, uint8_t* dataOut);
	//PROVISION
	uint16_t L0FactoryInit(const uint8_t* serialno);
	//PERSONAL METHODS
	void L0Restart();
	uint8_t GetNumberDevices();
	bool SwitchToDevice(int devPos);
	uint8_t* GetDeviceHelloMsg();
	se3Char* GetDevicePath(){return this->base.GetDeviceInfoPath();}
	uint8_t* GetDeviceSn(){return this->base.GetDeviceInfoSerialNo();}
	//LOGFILE MANAGING
	bool Se3CreateLogFile(char* path, uint32_t file_dim);
	char* Se3CreateLogFilePath(char *name);
};

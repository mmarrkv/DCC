/**
 * @file	commodities_api.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the COMMODITY API
 *
 * The file contains all the prototypes of the COMMODITY API
 */

#include "../../L0/L0 Base/L0_base.h"

//PURE VIRTUAL CLASS, THE METHODS WILL BE IMPLEMENTED IN L1
//the L0.h contains the prototype, while the L0_commodities.cpp contains the implementation
class CommoditiesApi {
private:
	///////////////////////////////////////////
	//SUPPORT METHODS FOR THE COMMODITIES API//
	///////////////////////////////////////////
	virtual bool Se3DriveNext() = 0;
	virtual bool Se3Info(uint64_t deadline, se3DiscoverInfo* info) = 0;
	/////////////////
	virtual void L0DiscoverInit() = 0;
	virtual bool L0DiscoverNext() = 0;
public:
	virtual ~CommoditiesApi() {};
	virtual bool L0DiscoverSerialNo(uint8_t* serialNo) = 0;
};

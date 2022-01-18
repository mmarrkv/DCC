/**
 * @file	utility_api.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the UTILITY API
 *
 * The file contains all the prototypes of the UTILITY API
 */

#include "../L1 Base/L1_base.h"

class UtilityApi {
public:
	virtual ~UtilityApi() {};
	virtual void L1SetAdminPIN(uint8_t* pin) = 0;
	virtual void L1SetUserPIN(uint8_t* pin) = 0;
};

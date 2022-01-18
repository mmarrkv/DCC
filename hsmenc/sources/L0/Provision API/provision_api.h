/**
 * @file	provision_api.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the PROVISION API
 *
 * The file contains all the prototypes of the PROVISION API
 */

class ProvisionApi {
public:
	virtual ~ProvisionApi() {};
	virtual uint16_t L0FactoryInit(const uint8_t* serialno) = 0;
};

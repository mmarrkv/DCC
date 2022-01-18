/**
 * @file	communication_api.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the COMMUNICATION API
 *
 * The file contains all the prototypes of the COMMUNICATION API
 */

#include "../L0 Base/L0_base.h"

class CommunicationApi {
private:
	virtual bool Se3Open(uint64_t deadline, se3File* phFile, se3DiscoverInfo* disco) = 0;
	virtual uint16_t L0TX(uint16_t cmd, uint16_t cmdFlags, uint16_t len, const uint8_t* data) = 0;
	virtual uint16_t L0RX(uint16_t* respStatus, uint16_t* respLen, uint8_t* respData) = 0;
public:
	/*
	 * @brief	Empty destructor
	 */
	virtual ~CommunicationApi() {};
	/**
	 * @brief The Se3Open method
	 *
	 * @param[in]	deadline	Timeout to open the seCube
	 * @param[out]	phFile		The seCube file handler
	 * @param[out]	disco		The seCube discover information
	 *
	 * @return					Boolean value returned, true if the seCube has been open correctly, false otherwise
	 */
	virtual void L0Open(uint8_t devPtr) = 0;
	virtual void L0Open() = 0;

	/*
	 * @brief Method used to close the seCube file handler and to free the device request and response
	 *
	 * @return	Void
	 */
	virtual void L0Close() = 0;

	/*
	 * @brief Method used to communicate with seCube, data is sent and the response is read
	 *
	 * @param[in]	reqCmd		Command that will be sent to the seCube
	 * @param[in]	reqCmdFlags	Flags used for transmission towards the seCube
	 * @param[in]	reqLen		Size of the data that wants to be transmitted
	 * @param[in]	reqData		Data buffer that will be sent to the seCube
	 * @param[out]	respStatus	Status of the seCube response
	 * @param[out]	respLen		Size of the response buffer
	 * @param[out]	respData	The response data buffer
	 *
	 * @return					SE3_OK if communication was successful, the related error code otherwise
	 */
	virtual void L0TXRX(uint16_t reqCmd, uint16_t reqCmdFlags, uint16_t reqLen, const uint8_t* reqData, uint16_t* respStatus, uint16_t* respLen, uint8_t* respData) = 0;
	virtual uint16_t L0Echo(const uint8_t* dataIn, uint16_t dataInLen, uint8_t* dataOut) = 0;
};

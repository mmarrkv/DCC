/**
 * @file	L0_provision.cpp
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Implementation of the PROVISION API
 *
 * The file contains the implementation of the PROVISION API
 */

#include "L0.h"
#include "L0_error_manager.h"

uint16_t L0::L0FactoryInit(const uint8_t* serialno) {
	uint16_t respStatus = 0;
	uint16_t respLen = 0;
	L0FactoryInitException factInitExc;

	try {
		L0TXRX(L0Commands::Command::FACTORY_INIT, 0, L0Communication::Size::SERIAL, serialno, &respStatus, &respLen, NULL);
	}
	catch (L0Exception& e) {
		throw factInitExc;
	}

	return respStatus;
}

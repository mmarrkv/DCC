/**
 * @file	L0.cpp
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Implementation of the L0 methods
 *
 * The file contains the implementation of the methods that belong directly to the L0 LIBRARY (doesn't include the implementation of the APIs)
 */

#include "L0.h"
//#define SE3_LOG_FILE


L0::L0() {
	//initialize the secube discover
	L0DiscoverInit();
	//scan all the seCubes connected
	while(L0DiscoverNext()){
		//adding the device parses all the iterator data inside the device
		this->base.AddDevice();
	}
	this->nDevices = this->base.GetNDevices();
	if(this->nDevices > 0){ // set all devices by default to closed
		int originalptr = this->base.GetDevicePtr();
		for(int i = 0; i < this->nDevices; i++){
			this->base.SetDevicePtr(i);
			this->base.SetDeviceOpened(false);
		}
		this->base.SetDevicePtr(originalptr); // go back to first device
	}
// cambiare qui per creare il file di log
#ifdef SE3_LOG_FILE
	//Se3CreateLogFilePath("log_file.txt")
	this->nDevices = this->base.GetNDevices();
	//if ( ! Se3CreateLogFile("/media/nico/6163-3831/log_file.txt",2) )  // cambiare qui
		//printf("log file not created\n");
#endif
}

L0::~L0() {
	//clear the array containing all the devices
	this->base.ResetDeviceArray();
}

void L0::L0Restart() {
	//close all the devices
	for (uint8_t i = 0; i < this->nDevices; i++)
		L0Close(i);
	//clear all the secube devices found
	this->base.ResetDeviceArray();

	//re-initialise the devices as done in the ctor
	L0DiscoverInit();

	while(L0DiscoverNext()){
		this->base.AddDevice();
	}

	this->nDevices = this->base.GetNDevices();
}

uint8_t L0::GetNumberDevices() {
	return this->nDevices;
}

bool L0::SwitchToDevice(int devPos) {
	return this->base.SetDevicePtr(devPos);
}

uint8_t* L0::GetDeviceHelloMsg() {
	return this->base.GetDeviceHelloMsg();
}

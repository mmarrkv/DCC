/**
 * @file	L0_error_manager.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Exception classes
 *
 * The file contains all the exception classes that can occur in the L0 library
 */

#include <iostream>
#include <exception>

class L0Exception : public std::exception {
public:
	virtual const char* what() const throw() {
		return "General exception in the L0 API";
	}
};

class L0NoDeviceException : public L0Exception {
public:
	virtual const char* what() const throw() {
		return "No device at the specified pointer!";
	}
};

class L0CommunicationErrorException : public L0Exception {
	virtual const char* what() const throw() {
		return "Communication error!";
	}
};

class L0TXRXException : public L0Exception {
public:
	virtual const char* what() const throw() {
		return "Error while transmitting data!";
	}
};


/*
class L0DeviceAlreadyOpenException : public L0Exception {
	virtual const char* what() const throw() {
		return "Another device is already opened!";
	}
};*/

class L0NoDeviceOpenedException : public L0Exception {
	virtual const char* what() const throw() {
		return "No device opened!";
	}
};

class L0ParametersErrorException : public L0Exception {
	virtual const char* what() const throw() {
		return "Parameter Error!";
	}
};

class L0TXException : public L0Exception {
	virtual const char* what() const throw() {
		return "TX Error!";
	}
};

class L0RXException : public L0Exception {
	virtual const char* what() const throw() {
		return "RX Error!";
	}
};

class L0FactoryInitException : public L0Exception {
	virtual const char* what() const throw() {
		return "Exception while performing the factory initialization!";
	}
};

class L0EchoException : public L0Exception {
	virtual const char* what() const throw() {
		return "Echo exception!";
	}
};

/**
 * @file	L1_error_manager.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Exception classes
 *
 * The file contains all the exception classes that can occur in the L1 library
 */

#ifndef _L1_ERROR_MANAGER_H
#define _L1_ERROR_MANAGER_H

#include <iostream>
#include <exception>

class L1Exception : public std::exception {
public:
	virtual const char* what() const throw() {
		return "General exception in the L1 API";
	}
};

class L1AlreadyOpenException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "SECube already opened";
	}
};

class L1OutOfBoundsException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Pointing outside the vector!";
	}
};

class L1TXRXException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while transmitting data!";
	}
};

class L1PayloadDecryptionException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error In the Payload Decryption!";
	}
};

class L1CommunicationError : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error In the communication!";
	}
};

class L1LoginException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error In the Login!";
	}
};

class L1CryptoSetTimeException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error setting the crypto time!";
	}
};

class L1CryptoInitException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error initializing the crypto session!";
	}
};

class L1CryptoUpdateException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error updating the crypto session!";
	}
};

class L1LogoutException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error logging out!";
	}
};

class L1EncryptException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while encrypting!";
	}
};

class L1DecryptException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while decrypting!";
	}
};

class L1DigestException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while digesting!";
	}
};

class L1GetAlgorithmsException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while getting algorithms!";
	}
};

class L1ConfigException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while configuring L1!";
	}
};

class L1KeyEditException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while editing the key!";
	}
};

class L1KeyListException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while listing the keys!";
	}
};

class L1FindKeyException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while finding the key!";
	}
};

class L1SelectDeviceException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while changing the device!";
	}
};

class L1GroupEditException : public L1Exception {
public:
	virtual const char* what() const throw() {
		return "Error while editing the group!";
	}
};

#endif

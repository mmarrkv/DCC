/**
 * @file	L0_enumerations.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	All the enumeration structures used in the L0 library
 *
 * The file contains all the enumerations that are needed in the L0 library
 */

#ifndef _L0_ENUMERATIONS_H
#define _L0_ENUMERATIONS_H

#ifdef _WIN32
//Windows
#include "Windows.h"
#endif

namespace L0Communication {
	struct Size {
		enum {
			//size of the magic block
			//SE3_MAGIC_SIZE = 32,
			MAGIC = 32,
			//the hello message in bytes (uint8_t)
			//SE3_HELLO_SIZE = 32,
			HELLO = 32,
			//the serial number size in bytes (uint8_t)
			//SE3_SERIAL_SIZE = 32
			SERIAL = 32
		};
	};

	struct Parameter {
		enum {
			//SE3_COMM_BLOCK = 512,
			COMM_BLOCK = 512,
			//SE3_COMM_N = 16
			COMM_N = 16,
			//MAX_PATH define is already declared in the windows library
			SE3_MAX_PATH = 256
		};
	};

	/* TODO: change this with exception handling*/
	struct Error {
		enum {
			//SE3C_OK = 0,
			OK = 0,
			//SE3C_ERR_NOT_FOUND = 1,
			ERR_NOT_FOUND = 1,
			//SE3C_ERR_TIMEOUT = 2,
			ERR_TIMEOUT = 2,
			//SE3C_ERR_NO_DEVICE = 3
			ERR_NO_DEVICE = 3
		};
	};
}

namespace L0DiscoverParameters {
	struct Offset {
		enum {
			SE3_DISCO_OFFSET_MAGIC = 0,
			//SE3_DISCO_OFFSET_SERIAL = 32,
			SERIAL = 32,
			//SE3_DISCO_OFFSET_HELLO = 2 * 32,
			HELLO = 2 * 32,
			//SE3_DISCO_OFFSET_STATUS = 3 * 32
			STATUS = 3 * 32
		};
	};
}

namespace L0Request {
	struct Size {
		enum {
			//SE3_REQ_SIZE_HEADER = 16,
			HEADER = 16,
			//SE3_REQDATA_SIZE_HEADER = 4,
			DATA_HEADER = 4,
			SE3_REQ_SIZE_DATA = L0Communication::Parameter::COMM_BLOCK - HEADER,
			SE3_REQDATA_SIZE_DATA = L0Communication::Parameter::COMM_BLOCK - DATA_HEADER,
			//used in the L1 enumerations
			//SE3_REQ_MAX_DATA =	L0Communication::Parameter::COMM_BLOCK - HEADER +
								//(L0Communication::Parameter::COMM_N - 2) * (L0Communication::Parameter::COMM_BLOCK - DATA_HEADER) - 8
			MAX_DATA =	L0Communication::Parameter::COMM_BLOCK - HEADER +
						(L0Communication::Parameter::COMM_N - 2) * (L0Communication::Parameter::COMM_BLOCK - DATA_HEADER) - 8

		};
	};

	struct Offset {
		enum {
			//SE3_REQ_OFFSET_CMD = 0,
			CMD = 0,		//offset of the command
			//SE3_REQ_OFFSET_CMDFLAGS = 2,
			CMD_FLAGS = 2,	//offset of the command flags
			//SE3_REQ_OFFSET_LEN = 4,
			LEN = 4,		//offset to write the length of the data and the header
			//SE3_REQ_OFFSET_CMDTOKEN = 6,
			CMD_TOKEN = 6,	//offset of the command token
			//SE3_REQ_OFFSET_PADDING = 10,
			PADDING = 10,	//offset for the padding
			//SE3_REQ_OFFSET_CRC = 14,
			CRC = 14,		//offset of the CRC
			//SE3_REQ_OFFSET_DATA = 16,
			DATA = 16,
			//SE3_REQDATA_OFFSET_CMDTOKEN = 0,
			DATA_CMD_TOKEN = 0,
			SE3_REQDATA_OFFSET_DATA = 4
		};
	};
}

namespace L0Response {
	struct Offset {
		enum {
			SE3_RESP_OFFSET_READY = 0,
			//SE3_RESP_OFFSET_STATUS = 2,
			STATUS = 2,
			//SE3_RESP_OFFSET_LEN = 4,
			LEN = 4,
			//SE3_RESP_OFFSET_CMDTOKEN = 6,
			CMD_TOKEN = 6,
			SE3_RESP_OFFSET_CRC = 14,
			//SE3_RESPDATA_OFFSET_CMDTOKEN = 0,
			DATA_CMD_TOKEN = 0,
			SE3_RESPDATA_OFFSET_DATA = 4
		};
	};

	struct Size {
		enum {
			//SE3_RESP_SIZE_HEADER = 16,
			HEADER = 16,
			//SE3_RESPDATA_SIZE_HEADER = 4,
			DATA_HEADER = 4,
			SE3_RESP_SIZE_DATA = L0Communication::Parameter::COMM_BLOCK - L0Request::Size::HEADER,
			SE3_RESPDATA_SIZE_DATA = L0Communication::Parameter::COMM_BLOCK - L0Request::Size::HEADER,
			//SE3_RESP_MAX_DATA =	L0Communication::Parameter::COMM_BLOCK - L0Request::Size::HEADER +
								//(L0Communication::Parameter::COMM_N - 2) * (L0Communication::Parameter::COMM_BLOCK - L0Request::Size::DATA_HEADER) - 8
			MAX_DATA =	L0Communication::Parameter::COMM_BLOCK - L0Request::Size::HEADER +
						(L0Communication::Parameter::COMM_N - 2) * (L0Communication::Parameter::COMM_BLOCK - L0Request::Size::DATA_HEADER) - 8
		};
	};
}

namespace L0Commands {
	struct Command {
		enum {
			//SE3_CMD0_FACTORY_INIT = 1,
			FACTORY_INIT = 1,
			//SE3_CMD0_ECHO = 2,
			ECHO = 2,
			//SE3_CMD0_L1 = 3,
			L1_CMD0 = 3,
			SE3_CMD0_BOOT_MODE_RESET = 4
		};
	};
}

namespace L0ErrorCodes {
	struct Error {
		enum {
			//SE3_OK = 0,  ///< success
			OK = 0,					//success
			SE3_ERR_HW = 0xF001,  ///< hardware failure
			//SE3_ERR_COMM = 0xF002,  ///< communication error
			COMMUNICATION = 0xF002,		//communication errors
			SE3_ERR_BUSY = 0xF003,  ///< device locked by another process
			SE3_ERR_STATE = 0xF004,  ///< invalid state for this operation
			SE3_ERR_CMD = 0xF005,  ///< command does not exist
			SE3_ERR_PARAMS = 0xF006,  ///< parameters are not valid
		};
	};
}

//for generating random values in WINDOWS environment
#ifdef _WIN32
namespace L0Win32ApiCodes {
	struct Codes {
		enum {
			//ADVAPI32_PROV_RSA_FULL = 1,
			FULL = 1,
			//ADVAPI32_CRYPT_NEWKEYSET = 0x00000008,
			NEW_KEYSET = 0x00000008,
			//ADVAPI32_NTE_BAD_KEYSET = _HRESULT_TYPEDEF_(0x80090016L)
			BAD_KEYSET = _HRESULT_TYPEDEF_(0x80090016L)
		};
	};
}
#endif

#endif

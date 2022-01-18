/**
 * @file	L1_enumerations.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	All the enumeration structures used in the L1 library
 *
 * The file contains all the enumerations that are needed in the L1 library
 */

#ifndef L1_ENUMERATIONS_H
#define L1_ENUMERATIONS_H

#include "../L0/L0_enumerations.h"

//L1 Error
namespace L1Error {
	struct Error {
		enum {
		    OK = 0, ///< No Error
		    SE3_ERR_ACCESS = 100,  ///< insufficient privileges
		    SE3_ERR_PIN = 101,  ///< pin rejected
		    SE3_ERR_RESOURCE = 200,  ///< resource not found
		    SE3_ERR_EXPIRED = 201,  ///< resource expired
		    SE3_ERR_MEMORY = 400,  ///< no more space to allocate resource
			SE3_ERR_AUTH =	401,	   ///< SHA256HMAC Authentication failed

		    SE3_ERR_OPENED = 300   /// < There is a session already opened and host is trying to open a new one
		};
	};
}


namespace L1Request {
	struct Offset {
		enum {
		    //SE3_REQ1_OFFSET_AUTH = 0,
			AUTH = 0,
		    //SE3_REQ1_OFFSET_IV = 16,
			IV = 16,
		    //SE3_REQ1_OFFSET_TOKEN = 32,
			TOKEN = 32,
		    //SE3_REQ1_OFFSET_LEN = 48,
			LEN = 48,
		    //SE3_REQ1_OFFSET_CMD = 50,
			CMD = 50,
		    //SE3_REQ1_OFFSET_DATA = 64,
			DATA = 64,
		};
	};

	struct Size {
		enum {
			//SE3_REQ1_MAX_DATA = (SE3_REQ_MAX_DATA - SE3_REQ1_OFFSET_DATA)
			MAX_DATA = L0Request::Size::MAX_DATA - L1Request::Offset::DATA
		};
	};

	struct KeyOffset {
		enum {
			//SE3_CMD1_KEY_EDIT_REQ_OFF_OP = 0,
			OP = 0,
			//SE3_CMD1_KEY_EDIT_REQ_OFF_ID = 2,
			ID = 2,
			//SE3_CMD1_KEY_EDIT_REQ_OFF_VALIDITY = 6,
			VALIDITY = 6,
			//SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_LEN = 10,
			DATA_LEN = 10,
			//SE3_CMD1_KEY_EDIT_REQ_OFF_NAME_LEN = 12,
			NAME_LEN = 12,
			//SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_AND_NAME = 14
			DATA_AND_NAME = 14
		};
	};
}

namespace L1Response {
	struct Offset {
		enum {
			//SE3_RESP1_OFFSET_AUTH = 0,
			AUTH = 0,
			//SE3_RESP1_OFFSET_IV = 16,
			IV = 16,
			//SE3_RESP1_OFFSET_TOKEN = 32,
			TOKEN = 32,
			//SE3_RESP1_OFFSET_LEN = 48,
			LEN = 48,
			//SE3_RESP1_OFFSET_STATUS = 50,
			STATUS = 50,
			//SE3_RESP1_OFFSET_DATA = 64
			DATA = 64
		};
	};

	struct Size {
		enum {
			//SE3_RESP1_MAX_DATA = (SE3_REQ_MAX_DATA - SE3_RESP1_OFFSET_DATA)
			MAX_DATA = L0Response::Size::MAX_DATA - L1Response::Offset::DATA
		};
	};
}

namespace L1ChallengeRequest {
	struct Offset {
		enum {
			//SE3_CMD1_CHALLENGE_REQ_OFF_CC1 = 0,
			CC1 = 0,
			//SE3_CMD1_CHALLENGE_REQ_OFF_CC2 = 32,
			CC2 = 32,
			//SE3_CMD1_CHALLENGE_REQ_OFF_ACCESS = 64
			ACCESS = 64
		};
	};

	struct Size {
		enum {
			//SE3_CMD1_CHALLENGE_REQ_SIZE = 66
			SIZE = 66
		};
	};
}

namespace L1ChallengeResponse {
	struct Offset {
		enum {
			//SE3_CMD1_CHALLENGE_RESP_OFF_SC = 0,
			SC = 0,
			//SE3_CMD1_CHALLENGE_RESP_OFF_SRESP = 32
			SRESP = 32
		};
	};

	struct Size {
		enum {
			//SE3_CMD1_CHALLENGE_RESP_SIZE = 64
			SIZE = 64
		};
	};
}

namespace L1Parameters {
	struct Size {
		enum {
			//SE3_L1_PIN_SIZE = 32,
			PIN = 32,
			//SE3_L1_KEY_SIZE = 32,
			KEY = 32,
			//SE3_L1_AUTH_SIZE = 16,
			AUTH = 16,
			//SE3_L1_CRYPTOBLOCK_SIZE = 16,
			CRYPTO_BLOCK = 16,
			//SE3_L1_CHALLENGE_SIZE = 32,
			CHALLENGE = 32,
			//SE3_L1_IV_SIZE = 16,
			IV = 16,
			//SE3_L1_TOKEN_SIZE = 16
			TOKEN = 16
		};
	};

	struct Parameter {
		enum {
			//SE3_L1_CHALLENGE_ITERATIONS = 32
			ITERATIONS = 32
		};
	};
}

namespace L1Crypto {
	// @matteo: cryptotypes added because required by SEfile
	struct CryptoTypes {
		enum {
			SE3_CRYPTO_TYPE_BLOCKCIPHER = 0,
			SE3_CRYPTO_TYPE_STREAMCIPHER = 1,
			SE3_CRYPTO_TYPE_DIGEST = 2,
			SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH = 3,
            SE3_CRYPTO_TYPE_STREAMCIPHER_AUTH = 4,
			SE3_CRYPTO_TYPE_OTHER = 0xFFFF
		};
	};

	struct ListResponseOffset {
		enum {
			//SE3_CMD1_CRYPTO_LIST_RESP_OFF_COUNT = 0,
			COUNT = 0,
			//SE3_CMD1_CRYPTO_LIST_RESP_OFF_ALGOINFO = 2
			ALGORITHM_INFO = 2
		};
	};

	struct ListRequestSize {
		enum {
			//SE3_CMD1_CRYPTO_LIST_REQ_SIZE = 0,
			REQ_SIZE = 0,
		};
	};

	struct AlgorithmInfoOffset {
		enum {
			//SE3_CMD1_CRYPTO_ALGOINFO_OFF_NAME = 0,
			NAME = 0,
			//SE3_CMD1_CRYPTO_ALGOINFO_OFF_TYPE = 16,
			TYPE = 16,
			//SE3_CMD1_CRYPTO_ALGOINFO_OFF_BLOCK_SIZE = 18,
			BLOCK_SIZE = 18,
			//SE3_CMD1_CRYPTO_ALGOINFO_OFF_KEY_SIZE = 20
			KEY_SIZE = 20
		};
	};

	struct AlgorithmInfoSize {
		enum {
			//SE3_CMD1_CRYPTO_ALGOINFO_SIZE = 22,
			SIZE = 22,
			//SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE = 16
			NAME_SIZE = 16
		};
	};

	struct SetTimeRequestOffset {
		enum {
			//SE3_CMD1_CRYPTO_SET_TIME_REQ_OFF_DEVTIME = 0
			DEV_TIME = 0
		};
	};

	struct SetTimeRequestSize {
		enum {
			//SE3_CMD1_CRYPTO_SET_TIME_REQ_SIZE = 4
			SIZE = 4
		};
	};

	struct InitRequestOffset {
		enum {
			//SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO = 0,
			ALGO = 0,
			//SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE = 2,
			MODE = 2,
			//SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID = 4
			KEY_ID = 4
		};
	};

	struct InitRequestSize {
		enum {
			//SE3_CMD1_CRYPTO_INIT_REQ_SIZE = 8
			SIZE = 8
		};
	};

	struct InitResponseOffset {
		enum {
			//SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID = 0
			SID = 0
		};
	};

	struct InitResponseSize {
		enum {
			//SE3_CMD1_CRYPTO_INIT_RESP_SIZE = 4
			SIZE = 4
		};
	};

	struct UpdateRequestOffset {
		enum {
			//SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_SID = 0,
			SID = 0,
			//SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_FLAGS = 4,
			FLAGS = 4,
			//SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN1_LEN = 6,
			DATAIN1_LEN = 6,
			//SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN2_LEN = 8,
			DATAIN2_LEN = 8,
			//SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA = 16
			DATA = 16
		};
	};

	struct UpdateResponseOffset {
		enum {
			//SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN = 0,
			DATAOUT_LEN = 0,
			//SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA = 16
			DATA = 16
		};
	};

	struct UpdateSize {
		enum {
			//SE3_CRYPTO_MAX_DATAIN = (SE3_REQ1_MAX_DATA - SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA),
			DATAIN = L1Request::Size::MAX_DATA - L1Crypto::UpdateRequestOffset::DATA,
			//SE3_CRYPTO_MAX_DATAOUT = (SE3_RESP1_MAX_DATA - SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA)
			DATAOUT = L1Response::Size::MAX_DATA - L1Crypto::UpdateResponseOffset::DATA
		};
	};

	struct UpdateFlags {
		enum {
			//SE3_CRYPTO_FLAG_FINIT = (1 << 15),
			FINIT = 1 << 15,
			//SE3_CRYPTO_FLAG_RESET = (1 << 14),
			RESET = 1 << 14,
			//SE3_CRYPTO_FLAG_SETIV = SE3_CRYPTO_FLAG_RESET,
			SET_IV = RESET,
			//SE3_CRYPTO_FLAG_SETNONCE = (1 << 13),
			SETNONCE = 1 << 13,
			//SE3_CRYPTO_FLAG_AUTH = (1 << 12)
			AUTH = 1 << 12,
            //SE3_CRYPTO_FLAG_SETAAD = (1 << 11)
            SET_AAD = 1 << 11  //!! CAN ONLY BE USED SUBSEQUENT TO A PREVIOUS CALL WITH SET_IV/RESET!!!!
		};
	};
}

namespace L1Key {
	struct Size {
		enum {
			//SE3_KEY_DATA_MAX = 2048,
			MAX_DATA = 2048,
			//SE3_KEY_NAME_MAX = 32
			MAX_NAME = 32
		};
	};

	struct RequestListSize {
		enum {
			//SE3_CMD1_KEY_LIST_REQ_SIZE = 36
			SIZE = 36
		};
	};

	struct RequestListOffset {
		enum {
			//SE3_CMD1_KEY_LIST_REQ_OFF_SKIP = 0,
			SKIP = 0,
			//SE3_CMD1_KEY_LIST_REQ_OFF_NMAX = 2,
			NMAX = 2,
		};
	};

	struct ResponeListOffset {
		enum {
			//SE3_CMD1_KEY_LIST_RESP_OFF_COUNT = 0,
			COUNT = 0,
			//SE3_CMD1_KEY_LIST_RESP_OFF_KEYINFO = 2
			KEYINFO = 2
		};
	};

	struct InfoOffset {
		enum {
			//SE3_CMD1_KEY_LIST_KEYINFO_OFF_ID = 0,
			ID = 0,
			//SE3_CMD1_KEY_LIST_KEYINFO_OFF_VALIDITY = 4,
			VALIDITY = 4,
			//SE3_CMD1_KEY_LIST_KEYINFO_OFF_DATA_LEN = 8,
			DATA_LEN = 8,
			//SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME_LEN = 10,
			NAME_LEN = 10,
			//SE3_CMD1_KEY_LIST_KEYINFO_OFF_FINGERPRINT = 12
			FINGERPRINT = 12,
			// SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME = 44
			NAME = 44

		};
	};
}

namespace L1Commands {
	struct Flags {
		enum {
			//SE3_CMDFLAG_ENCRYPT = (1 << 15),  ///< encrypt L1 packet
			ENCRYPT = 1 << 15,			//encrypt L1 packet
			//SE3_CMDFLAG_SIGN = (1 << 14) ///< sign L1 payload
			SIGN = 1 << 14				//sign L1 payload
		};
	};

	struct Codes {
		enum {
			//SE3_CMD1_CHALLENGE = 1,
			CHALLENGE = 1,
			//SE3_CMD1_LOGIN = 2,
			LOGIN = 2,
			//SE3_CMD1_LOGOUT = 3,
			LOGOUT = 3,
			//SE3_CMD1_CONFIG = 4,
			CONFIG = 4,
			//SE3_CMD1_KEY_EDIT = 5,
			KEY_EDIT = 5,
			//SE3_CMD1_KEY_LIST = 6,
			KEY_LIST = 6,
			//SE3_CMD1_CRYPTO_INIT = 7,
			CRYPTO_INIT = 7,
			//SE3_CMD1_CRYPTO_UPDATE = 8,
			CRYPTO_UPDATE = 8,
			//SE3_CMD1_CRYPTO_LIST = 9,
			CRYPTO_LIST = 9,
			//SE3_CMD1_CRYPTO_SET_TIME = 10
			SET_TIME = 10,
			//SE3_CMD1_LOGOUT_FORCED = 11
			FORCED_LOGOUT=11,
			//SE3_CMD1_SEKEY (includes all options below)
			SEKEY = 12
		};
	};

	struct Options {
		enum{
			SE3_SEKEY_OP_SETINFO = 1,
			SE3_SEKEY_OP_GETINFO = 2,
			SE3_SEKEY_OP_GETKEY = 3,
			SE3_SEKEY_OP_GET_KEY_IDS = 4,
			SE3_SEKEY_DELETEALL = 5,
			SE3_SEKEY_DELETEKEY = 6,
			SE3_SEKEY_OP_GETKEYENC = 7,
			SE3_SEKEY_INSERTKEY = 8
			//SE3_SEKEY_FINDKEY = 9
		};
	};
}

namespace L1Login {
	struct RequestOffset {
		enum {
			//SE3_CMD1_LOGIN_REQ_OFF_CRESP = 0
			CRESP = 0
		};
	};

	struct RequestSize {
		enum {
			//SE3_CMD1_LOGIN_REQ_SIZE = 32
			SIZE = 32
		};
	};

	struct ResponseOffset {
		enum {
			//SE3_CMD1_LOGIN_RESP_OFF_TOKEN = 0
			TOKEN = 0
		};
	};

	struct ResponseSize {
		enum {
			//SE3_CMD1_LOGIN_RESP_SIZE = 16
			SIZE = 16
		};
	};
}

namespace L1Algorithms {
	/* WARNING: any change in the algorithms below must be propagated also
	 * in SEkey code which is based on this namespace. */
	struct Algorithms {
		enum {
		    AES = 0,  ///< AES
			SHA256 = 1,  ///< SHA256
			HMACSHA256 = 2,  ///< HMAC-SHA256
			AES_HMACSHA256 = 3,  ///< AES + HMAC-SHA256
			AES_HMAC = 4,		///< AES 256 + HMAC Auth (todo: remove)
			CHACHA20_POLY1305 =5 //frclone
		};
	};

	// @matteo: copied from original C source code because needed by SEfile
	struct Parameters {
		enum {
			SE3_ALGO_MAX = 8
		};
	};
}

namespace L1Configuration {
	struct RequestOffset {
		enum {
			//SE3_CMD1_CONFIG_REQ_OFF_ID = 0,
			CONFIG_ID = 0,
			//SE3_CMD1_CONFIG_REQ_OFF_OP = 2,
			CONFIG_OP = 2,
			//SE3_CMD1_CONFIG_REQ_OFF_VALUE = 4,
			CONFIG_VALUE = 4,
		};
	};

	struct ResponseOffset {
		enum {
			//SE3_CMD1_CONFIG_RESP_OFF_VALUE = 0
			CONFIG_VALUE = 0
		};
	};

	struct Operation {
		enum {
			//SE3_CONFIG_OP_GET = 1,
			GET = 1,
			//SE3_CONFIG_OP_SET = 2
			SET = 2
		};
	};

	struct RecordSize {
		enum {
			//SE3_RECORD_SIZE = 32,
			RECORD_SIZE = 32,
			//SE3_RECORD_MAX = 2
			RECORD_MAX = 2
		};
	};

	struct RecordType {
		enum {
			//SE3_RECORD_TYPE_ADMINPIN = 0,
			ADMINPIN = 0,
			//SE3_RECORD_TYPE_USERPIN = 1
			USERPIN = 1
		};
	};
}

namespace CryptoInitialisation {
	/**  \brief L1CryptoInit default modes
	  *
	  *  One Feedback and one Mode may be combined to specify the desired mode
	  *  Example:
	  *     Encrypt in CBC mode
	  *     (CryptoInitialisation::Feedback::CBC | CryptoInitialisation::Mode::ENCRYPT)
	  */

	struct Parameters {
		enum {
			//SE3_DIR_SHIFT = 8
			SHIFT = 8
		};
	};

	struct Mode {
		enum {
			//SE3_DIR_ENCRYPT = (1 << SE3_DIR_SHIFT),
			ENCRYPT = 1 << CryptoInitialisation::Parameters::SHIFT,
			//SE3_DIR_DECRYPT = (2 << SE3_DIR_SHIFT)
			DECRYPT = 2 << CryptoInitialisation::Parameters::SHIFT
		};
	};

	struct Feedback {
		enum {
			//SE3_FEEDBACK_ECB = 1,
			ECB = 1,
			//SE3_FEEDBACK_CBC = 2,
			CBC = 2,
			//SE3_FEEDBACK_OFB = 3,
			OFB = 3,
			//SE3_FEEDBACK_CTR = 4,
			CTR = 4,
			//SE3_FEEDBACK_CFB = 5
			CFB = 5,
			//frclone
            //SE3_FEEDBACK_DOBAKE = 6 in se3c1def.h
			DoBake = 6,
            //SE3_FEEDBACK_DONOTBAKE = 0 in se3c1def.h
            DoNotBake = 0,
            //SE3_FEEDBACK_GETPCR =7 in se3c1def.h
            GETPCR = 7
        };
	};

}




namespace L1SEkey {
	struct Direction { // Operations to read or write SEkey user info (username and user ID) from the SEcube to the host and vice-versa
		enum {
			LOAD, // Read from the SEcube
			STORE // Write to the SEcube
		};
	};
}

#endif

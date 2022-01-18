/**
 * @file	login_logout_api.h
 * @Author	Alexander James Pane (alexanderjp91@gmail.com)
 * @date	July, 2017
 * @brief	Prototypes of the LOGIN LOGOUT API
 *
 * The file contains all the prototypes of the LOGIN LOGOUT API
 */

#include "../L1 Base/L1_base.h"

class LoginLogoutApi {
//private:
	//virtual void Se3SessionInit() = 0;
public:
	virtual ~LoginLogoutApi() {};
	virtual void L1Login(const uint8_t* pin, uint16_t access, bool force) = 0;
	virtual void L1Logout() = 0;
};

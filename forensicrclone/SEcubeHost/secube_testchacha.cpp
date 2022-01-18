 #include <iostream>
 #include <stdlib.h>
 #include <stdio.h>

 #include "sources/L1/L1.h"

 using namespace std;

 static uint8_t pin_user[32] = {
     't','e','s','t', 0,0,0,0, 0,0,0,0, 0,0,0,0,
     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
 };

 //uint16_t encSize(uint16_t plain_size)
 //{
     //return (((plain_size/L1Parameters::Size::CRYPTO_BLOCK)+1)*L1Parameters::Size::CRYPTO_BLOCK);
 //}

 int main()
 {
	 string strTest = "CHACHAMV_ACC_TOKENSPLAINTEXT";
     //string strTest = "CHACHAMV_RFS_TOKENPLAINTEXT";
     //string strTest = "blabla\"access_token\": \"XYZXYZXYZXYZS\"blablabla";
     //string strTest = "blabla\"refresh_token\": \"XYZXYZXYZXYZS\"blablabla";
	 uint16_t strLen = strTest.length();

	 uint8_t iv[MV_CHACHA20_IV_SIZE];

     uint8_t test_data[32] = {
             1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4,
             1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4
     };

     uint8_t test_plchldr_data[13] = {
             'M','V','_','A', 'C','C','_','T', 'O','K','E', 'N', 'S'
     };


     uint8_t test_rfs_plchldr_data[13] = {
             'M','V','_','R', 'F','S','_','T', 'O','K','E', 'N', 'S'
     };


     uint8_t test_token_data[13] = {
             '1','2','3','4','5','6','7','8','9','a','b','c', 'd'
     };

     /*
     uint8_t test_pcr_data[32] = {
             0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD, 0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD,
             0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD, 0x1,0x2,0x3,0x4, 0xA,0xB,0xC,0xD
     };
      */

     se3Key key;

	 L0 l0 = L0(); // low level SEcube object
     uint8_t numDevices = l0.GetNumberDevices(); // how many SEcube devices are currently connected to the host machine
     if(numDevices==0){
         cout << "No Devices connected!" << endl;
         return -1;
     }

     L1 l1 = L1(); // high level SEcube object
     try{
    	 l1.L1Login(pin_user, SE3_ACCESS_USER, true);// login to the SEcube as user with the pin of the user, force logout if currently the SEcube already has an active session
     } catch(...){
    	 cout << "Login failed!" << endl;
    	 return -1;
     }
     cout << "Login ok!" << endl;
     cout << endl;

     // Retrieve the list of the keys (their ID, not their values) currently stored on the device
     uint16_t maxKeys = 128, maxAlgo = 128, skip = 0, count;
     se3Key keyArray[maxKeys];
     l1.L1KeyList(maxKeys, skip, keyArray, &count);
     cout << "Keys List (id - name):"<< endl;
     for(uint16_t i=0; i<count; i++)
     {
         string keyname((char*)keyArray[i].name, keyArray[i].nameSize);
    	 cout << keyArray[i].id << " - " << keyname << endl;
     }
     cout << endl;

     // Retrieve the list of crypto algorithms supported by the SEcube
     se3Algo algorithmsArray[maxAlgo];
     l1.L1GetAlgorithms(maxAlgo, skip, algorithmsArray, &count);
     cout << "Algorithms List (name - type):"<< endl;
     for(uint16_t i=0; i<count; i++)
     {
    	 string algoname((char*)algorithmsArray[i].name, L1Crypto::AlgorithmInfoSize::NAME_SIZE);
    	 string algotype;
    	 switch(algorithmsArray[i].type){
    	 	 case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_BLOCKCIPHER:
    	 		algotype = "block cipher";
    	 		 break;
    	 	 case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH:
    	 		algotype = "block cipher with authentication and integrity";
    	 		 break;
    	 	 case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_DIGEST:
    	 		algotype = "digest algorithm";
    	 		 break;
    	 	 case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_STREAMCIPHER:
    	 		algotype = "stream cipher";
    	 		 break;
             case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_STREAMCIPHER_AUTH:
                 algotype = "stream cipher with authentication and integrity";
                 break;
             case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_OTHER:
    	 		algotype = "other type";
    	 		 break;
    	 	 default:
    	 		 algotype = "invalid type";
    	 }
    	 cout << algoname << " - " << algotype << endl;
     }
     cout << endl;

          /***** Upsert the session key *****/
     strcpy((char* )key.name, "SessionKey");
     key.id = 4;
     key.nameSize = strlen((char *)key.name);
     key.dataSize = MV_CHACHA20_KEY_SIZE;
     key.data = test_data;
     key.validity = (uint32_t)time(0) + 365 * 24 * 3600;
     l1.L1KeyEdit(&key,3); //SE3_KEY_OP_UPSERT
     cout << "Key with ID = 4 updated successfully" << endl;

    /***** Upsert Access Token Holder *****/
     key.id = ACC_TKN_PLCHLDR_ID;
     strcpy((char* )key.name, "AccessTokenPlaceHolder");
     key.nameSize = strlen((char *)key.name);
     key.dataSize = MV_ACCTOKENSIZE;
     key.data = test_plchldr_data;
     key.validity = (uint32_t)time(0) + 365 * 24 * 3600;
     l1.L1KeyEdit(&key,3); //SE3_KEY_OP_UPSERT
     cout << "Key with ID = 5 updated successfully" << endl;


     /***** Upsert Refresh Token Holder *****/
     key.id = RFRSH_TKN_PLCHLDR_ID;
     strcpy((char* )key.name, "RefreshTokenPlaceHolder");
     key.nameSize = strlen((char *)key.name);
     key.dataSize = MV_RFRSHTOKENSIZE;
     key.data = test_rfs_plchldr_data;
     key.validity = (uint32_t)time(0) + 365 * 24 * 3600;
     l1.L1KeyEdit(&key,3); //SE3_KEY_OP_UPSERT
     cout << "Key with ID = 6 updated successfully" << endl;

     /***** Upsert Access Token *****/
     key.id = ACC_TKN_ID;
     strcpy((char* )key.name, "AccessToken");
     key.nameSize = strlen((char *)key.name);
     key.dataSize = MV_ACCTOKENSIZE;
     key.data = test_token_data;
     key.validity = (uint32_t)time(0) + 365 * 24 * 3600;
     l1.L1KeyEdit(&key,3); //SE3_KEY_OP_UPSERT
     cout << "Key with ID = 7 updated successfully" << endl;


     /***** Upsert Refresh Token *****/
     key.id = RFRSH_TKN_ID;
     strcpy((char* )key.name, "RefreshToken");
     key.nameSize = strlen((char *)key.name);
     key.dataSize = MV_RFRSHTOKENSIZE;
     key.data = test_token_data;
     key.validity = (uint32_t)time(0) + 365 * 24 * 3600;
     l1.L1KeyEdit(&key,3); //SE3_KEY_OP_UPSERT
     cout << "Key with ID = 8 updated successfully" << endl;

    /***** Upsert Init PCR *****/
    /*
     key.id = PCR_ID;
     strcpy((char* )key.name, "PCR");
     key.nameSize = strlen((char *)key.name);
     key.dataSize = MV_PCRSIZE;
     key.data = test_pcr_data;
     key.validity = (uint32_t)time(0) + 365 * 24 * 3600;
     l1.L1KeyEdit(&key,3); //SE3_KEY_OP_UPSERT
     cout << "Key with ID = 9 updated successfully" << endl;
     */

     //common stuff
     l1.L1CryptoSetTime((uint32_t)time(0)); // this must be called at least one time before doing the first encryption/decryption operation after the login to the SEcube
     uint32_t keyIdChoosen = 4;
     uint32_t sessionId;
     uint8_t *buffer;
     unique_ptr<uint8_t[]> enc_buffer;
     unique_ptr<uint8_t[]> dec_buffer;
     uint16_t buffer_len;
     uint16_t enc_buffer_len = 0;
     uint16_t dec_buffer_len = 0;
     vector<uint8_t> myVector(strTest.begin(), strTest.end());


     //GETPCR TEST - 1
     memset(iv, 0, MV_CHACHA20_IV_SIZE);
     enc_buffer = make_unique<uint8_t[]>(MV_PCRSIZE);
     memset(enc_buffer.get(), '\0', MV_PCRSIZE);
     enc_buffer_len = MV_PCRSIZE;
     buffer = &myVector[0];
     buffer_len = 1; // sending a single dummy byte not to return an error


     l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305, CryptoInitialisation::Mode::ENCRYPT | CryptoInitialisation::Feedback::GETPCR , keyIdChoosen, &sessionId);
     l1.L1CryptoUpdate(sessionId, L1Crypto::UpdateFlags::RESET | L1Crypto::UpdateFlags::FINIT, MV_CHACHA20_IV_SIZE, iv, buffer_len, buffer, &enc_buffer_len, enc_buffer.get());
     cout << "PCR (hex value) -> ";
     for(int n=0; n<enc_buffer_len; n++){
         printf("%02x ", enc_buffer[n]);
     }
     cout << endl;
     enc_buffer.reset();

     // Now we try to encrypt a payload

 	 // now we setup the parameters we want to use for encryption: CHACHA20-POLY1305 algorithm. We specify also the key that we want to use.
     l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305, CryptoInitialisation::Mode::ENCRYPT | CryptoInitialisation::Feedback::DoBake , keyIdChoosen, &sessionId);

     buffer = &myVector[0];
     buffer_len = strLen;
     printf("buffer len plain -> %d\n", buffer_len);
 	 cout << "buffer plain -> " << strTest << endl;
 	 cout << "buffer plain (hex value) -> ";
 	 for(int n=0; n<strTest.length(); n++){
 		 printf("%02x ", strTest.at(n));
 	 }
 	 cout << endl;
 	 enc_buffer = make_unique<uint8_t[]>((buffer_len+MV_CHACHA20_DIGEST_SIZE)*sizeof(uint8_t));
 	 memset(enc_buffer.get(), '\0', (buffer_len+MV_CHACHA20_DIGEST_SIZE)*sizeof(uint8_t));

 	 // with the L1CryptoUpdate we iterate over the plaintext until it is completely encrypted (FINIT flag is used to finalize the encryption)
 	 // + Set IV in data1
 	 memset(iv, 0, MV_CHACHA20_IV_SIZE);
 	 l1.L1CryptoUpdate(sessionId, L1Crypto::UpdateFlags::RESET | L1Crypto::UpdateFlags::FINIT, MV_CHACHA20_IV_SIZE, iv, buffer_len, buffer, &enc_buffer_len, enc_buffer.get());


 	 if(enc_buffer_len != ((buffer_len+MV_CHACHA20_DIGEST_SIZE)*sizeof(uint8_t))){
 		 cout << "Error, the length of the ciphertext does not correspond to the expected value." << endl;
 		 return -1;
 	 }

 	 cout<< "buffer len enc -> " << (enc_buffer_len) << endl;
 	 string encrypted((char*)enc_buffer.get(), enc_buffer_len);
 	 cout << "buffer enc -> " << encrypted << endl;
 	 cout << "buffer enc (hex value) -> ";
 	 for(int n=0; n<enc_buffer_len; n++){
 		 printf("%02x ", enc_buffer[n]);
 	 }
 	 cout << endl;

 	 //Decryption
 	 dec_buffer = make_unique<uint8_t[]>(enc_buffer_len*sizeof(uint8_t));
 	 memset(dec_buffer.get(), '\0', enc_buffer_len*sizeof(uint8_t));
 	 l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305, CryptoInitialisation::Mode::DECRYPT | CryptoInitialisation::Feedback::DoBake, keyIdChoosen, &sessionId);
 	 l1.L1CryptoUpdate(sessionId,  L1Crypto::UpdateFlags::RESET | L1Crypto::UpdateFlags::FINIT, MV_CHACHA20_IV_SIZE, iv, enc_buffer_len, enc_buffer.get(), &dec_buffer_len, dec_buffer.get());


 	 if(dec_buffer_len != ((enc_buffer_len-MV_CHACHA20_DIGEST_SIZE)*sizeof(uint8_t))){
 		 cout << "Error, the length of the plaintext does not correspond to the expected value." << endl;
 		 return -1;
 	 }

 	 cout << "buffer len dec -> " << dec_buffer_len << endl;
 	 string decrypted((char*)dec_buffer.get(), dec_buffer_len);
 	 cout << "buffer dec -> " << decrypted << endl;
 	 cout << "buffer dec (hex value) -> ";
 	 for(int n=0; n<dec_buffer_len; n++){
 		 printf("%02x ", dec_buffer[n]);
 	 }
 	 cout << endl;

 	 // Compare plain data with decrypted data - no longer the case due to baking
 	 /*
     if (memcmp(buffer, dec_buffer.get(), buffer_len) == 0) { // we use here enc_buffer_len because we only want to compare the firt N bytes where N is the size of the original plaintext
         cout << "Data match! Notice that trailing zeros or access token chars are not considered since the decrypted value is checked against the original plaintext only for a number"
        		 " of bytes which is equal to the size of the original plaintext." << endl;
     }
     else {
         cout << "Error, data DO NOT match" << endl;
     }
     */

 	 //GETPCR TEST - 2
     memset(iv, 0, MV_CHACHA20_IV_SIZE);
     enc_buffer.reset();
     enc_buffer = make_unique<uint8_t[]>(MV_PCRSIZE);
     memset(enc_buffer.get(), '\0', MV_PCRSIZE);
     enc_buffer_len = MV_PCRSIZE;
     buffer_len = 1; // sending a single dummy byte not to return an error

     l1.L1CryptoInit(L1Algorithms::Algorithms::CHACHA20_POLY1305, CryptoInitialisation::Mode::ENCRYPT | CryptoInitialisation::Feedback::GETPCR , keyIdChoosen, &sessionId);
     l1.L1CryptoUpdate(sessionId, L1Crypto::UpdateFlags::RESET | L1Crypto::UpdateFlags::FINIT, MV_CHACHA20_IV_SIZE, iv, buffer_len, buffer, &enc_buffer_len, enc_buffer.get());
     cout << "PCR (hex value) -> ";
     for(int n=0; n<enc_buffer_len; n++){
         printf("%02x ", enc_buffer[n]);
     }
     cout << endl;

     l1.L1Logout();
     cout << "Logout ok!" << endl;
     return 0;
 }

/**
 *  \file se3_common.c
 *  \author Nicola Ferri, Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Common functions and data structures. Debug tools are also here
 */

#include "se3_common.h"
#include "se3_sdio.h"
#include <string.h>

SE3_SERIAL serial;
uint16_t hwerror;

const uint8_t se3_magic[SE3_MAGIC_SIZE] = {
    0x3c, 0xab, 0x78, 0xb6, 0x2, 0x64, 0x47, 0xe9, 0x30, 0x26, 0xd4, 0x1f, 0xad, 0x68, 0x22, 0x27,
    0x41, 0xa4, 0x32, 0xba, 0xbe, 0x54, 0x83, 0xee, 0xab, 0x6b, 0x62, 0xce, 0xf0, 0x5c, 0x7, 0x91
};

//########################DEBUG##############################
#ifdef SE3_DEBUG_SD

const uint8_t debug_string[DEBUG_STRING_SIZE] = "debug_file";
bool se3_write_trace(uint8_t* buf) {
	if (se3_debug.debug_file_created == false)
		return false; 	//prevent writing in case of file not created, avoiding possible SD corruption
	uint32_t str_len = strlen(buf);


	while(se3_debug.blk_cnt <= se3_debug.debug_file_size) { //while we do not reach the end of the file
		if (se3_debug.data_written_len + str_len > STORAGE_BLK_SIZ) {
			//number of bytes to be written are greater than the memory block
			//write in the buffer the part of the string passed as argument to fill it
			memcpy(se3_debug.buf + se3_debug.data_written_len, buf + (strlen(buf) - str_len), STORAGE_BLK_SIZ - se3_debug.data_written_len);
			if (!secube_sdio_write(STORAGE_BLK_SIZ, se3_debug.buf, se3_debug.debug_address + se3_debug.blk_cnt, 1))
				return false;
			//written an entire sector, move to the next one
			se3_debug.blk_cnt ++;
			str_len -= STORAGE_BLK_SIZ - se3_debug.data_written_len; //remove the number of bytes already written
			se3_debug.data_written_len = 0; //reset the number of bytes in the buffer since we start again from 0
			uint8_t *tmp;
			tmp = (uint8_t*) calloc (STORAGE_BLK_SIZ,sizeof(uint8_t));
			memcpy(se3_debug.buf, tmp, STORAGE_BLK_SIZ); //reset the buffer
			free(tmp);
		} else {
			//the amount of data to be written is less than the memory block
			memcpy(se3_debug.buf + se3_debug.data_written_len, buf + (strlen(buf) - str_len), str_len);
			if (!secube_sdio_write(STORAGE_BLK_SIZ, se3_debug.buf, se3_debug.debug_address + se3_debug.blk_cnt, 1))
				return false;
			se3_debug.data_written_len += str_len;
			return true;
		}
	}
	return true;
}

#endif

uint16_t se3_req_len_data(uint16_t len_data_and_headers)
{
    uint16_t nblocks;
    if (len_data_and_headers < SE3_REQ_SIZE_HEADER) {
        return 0;
    }
    nblocks = len_data_and_headers/SE3_COMM_BLOCK;
    if (len_data_and_headers % SE3_COMM_BLOCK != 0) {
        nblocks++;
    }
    if (nblocks == 0)return 0;
    return len_data_and_headers - SE3_REQ_SIZE_HEADER - (nblocks - 1)*SE3_REQDATA_SIZE_HEADER;
}

uint16_t se3_req_len_data_and_headers(uint16_t len_data)
{
    uint16_t ndatablocks;
    if (len_data <= SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER) {
        return len_data + SE3_REQ_SIZE_HEADER;
    }
    len_data -= (SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER);
    ndatablocks = len_data / (SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER);
    if (len_data % (SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER) != 0) {
        ndatablocks++;
    }
    return SE3_COMM_BLOCK + len_data + ndatablocks*SE3_REQDATA_SIZE_HEADER;
}

uint16_t se3_resp_len_data(uint16_t len_data_and_headers)
{
    uint16_t nblocks;
    if (len_data_and_headers < SE3_RESP_SIZE_HEADER) {
        return 0;
    }
    nblocks = len_data_and_headers / SE3_COMM_BLOCK;
    if (len_data_and_headers % SE3_COMM_BLOCK != 0) {
        nblocks++;
    }
    if (nblocks == 0)return 0;
    return len_data_and_headers - SE3_RESP_SIZE_HEADER - (nblocks - 1)*SE3_RESPDATA_SIZE_HEADER;
}

uint16_t se3_resp_len_data_and_headers(uint16_t len_data)
{
    uint16_t ndatablocks;
    if (len_data <= SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER) {
        return len_data + SE3_RESP_SIZE_HEADER;
    }
    len_data -= (SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER);
    ndatablocks = len_data / (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER);
    if (len_data % (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER) != 0) {
        ndatablocks++;
    }
    return SE3_COMM_BLOCK + len_data + ndatablocks*SE3_RESPDATA_SIZE_HEADER;
}

uint16_t se3_nblocks(uint16_t len)
{
    uint16_t nblocks = len / SE3_COMM_BLOCK;
    if (len%SE3_COMM_BLOCK != 0) {
        nblocks++;
    }
    return nblocks;
}


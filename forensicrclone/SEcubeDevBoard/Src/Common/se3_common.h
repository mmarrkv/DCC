/**
 *  \file se3_common.h
 *  \author Nicola Ferri, Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Common functions and data structures. Debug tools are also here
 */


#pragma once


#include "se3c1def.h"
#include "se3_sdio.h"

extern const uint8_t se3_magic[SE3_MAGIC_SIZE];

#ifndef se3_serial_def
#define se3_serial_def
typedef struct SE3_SERIAL_ {
    uint8_t data[SE3_SERIAL_SIZE];
    bool written;  					///< Indicates whether the serial number has been set (by FACTORY_INIT)
} SE3_SERIAL;
#endif

/** \brief decoded request header */
typedef struct se3_comm_req_header_ {
    uint16_t cmd;
    uint16_t cmd_flags;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} se3_comm_req_header;

extern SE3_SERIAL serial;
extern uint16_t hwerror;

//########################DEBUG##############################
//#define SE3_DEBUG_SD

#ifdef SE3_DEBUG_SD

#define DEBUG_STRING_SIZE 10
const uint8_t debug_string[DEBUG_STRING_SIZE];
typedef struct se3_debug_val_ {
	uint32_t blk_cnt;
	uint16_t data_written_len;
	uint32_t debug_address;
	uint32_t debug_file_size;
	uint8_t buf[STORAGE_BLK_SIZ];
	bool debug_file_created;
} se3_debug_val;

se3_debug_val se3_debug;

/** \brief write a trace on the log file
 *
 */
bool se3_write_trace(uint8_t* buf);

/*  DEBUG TOOL USAGE EXAMPLE:
 *
 * 1) If commented, de-comment '#define SE3_DEBUG_SD' in this file.
 * 2) Build your project and program the chip.
 * 3) From the host create the log_file and write the debug string in it with the file dimension
 * 4) Use the function se3_write_trace() to write in the log file, the function will write starting from the beginning of the file appending each time it is called the new information
 * 5) pay attention that the se3_write_trace() could not be used in the device code that runs prior to the creation of the file from the host causing, otherwise, errors.
 */

#endif
//##############################################################

/**
 *  \brief Compute length of data in a request in terms of SE3_COMM_BLOCK blocks
 *  
 *  \param [in] len_data_and_headers Data length
 *  \return Number of SE3_COMM_BLOCK blocks
 *  
 */
uint16_t se3_req_len_data(uint16_t len_data_and_headers);

/**
 *  \brief Compute length of data in a request accounting for headers
 *  
 *  \param [in] len_data Data length
 *  \return Number of Bytes
 *  
 */
uint16_t se3_req_len_data_and_headers(uint16_t len_data);

/**
 *  \brief Compute length of data in a request in terms of SE3_COMM_BLOCK blocks
 *  
 *  \param [in] len_data_and_headers Data length
 *  \return Number of SE3_COMM_BLOCK blocks
 *  
 */
uint16_t se3_resp_len_data(uint16_t len_data_and_headers);

/**
 *  \brief Compute length of data in a response accounting for headers
 *  
 *  \param [in] len_data Data Length
 *  \return Number of Bytes
 *  
 */
uint16_t se3_resp_len_data_and_headers(uint16_t len_data);

/**
 *  \brief Compute number of SE3_COMM_BLOCK blocks, given length in Bytes
 *  
 *  \param [in] cap Length
 *  \return Number of Blocks
 *  
 */
uint16_t se3_nblocks(uint16_t len);





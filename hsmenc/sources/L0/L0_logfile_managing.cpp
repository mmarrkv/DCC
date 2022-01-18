///*
// * L0_logfile_managing.c
// *
// *  Created on: Sep 20, 2018
// *      Author: nico
// */
//
//#include "L0.h"
//
//
//char* L0::Se3CreateLogFilePath(char *name) {
//	char file_path[L0Communication::Parameter::SE3_MAX_PATH];
//	sprintf(file_path,"%s/%s\0", this->base.GetDeviceInfoPath(), name);
//	printf("file path: %s\n", file_path);
//	return file_path;
//}
//
//#ifdef _WIN32
//bool L0::Se3CreateLogFile(char* path, uint32_t file_dim) {
//	HANDLE h = INVALID_HANDLE_VALUE;
//	DWORD bytes_written;
//	char *s;
//	h = CreateFileW(h,
//					GENERIC_WRITE,
//					FILE_SHARE_WRITE,
//					NULL,
//					CREATE_ALWAYS,
//					FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED,
//					NULL);
//	if (h == INVALID_HANDLE_VALUE) {
//		//failed opening log file
//		return false;
//	}
//	h.ol.Offset = 0; //write from the start of the file
//	h.ol.OffsetHigh = 0;
//	s = (char*) calloc (file_dim*512, sizeof(char));
//	sprintf(s,"debug_file%d",file_dim);
//	if (! WriteFile(h,s,(DWORD)(file_dim * L0Communication::Parameter::COMM_BLOCK), &bytes_written, &hfile.ol) ) {
//		//failed writing log file
//		CloseHandle(h);
//		free(s);
//		return false;
//	}
//	CloseHandle(h);
//	free(s);
//	return true;
//}
//#else
//
//bool L0::Se3CreateLogFile(char* path, uint32_t file_dim) {
//	int fd;
//	char *string;
//	fd = open(path, O_RDWR | O_SYNC | O_DIRECT | O_CREAT , S_IWUSR | S_IRUSR);
//	if (fd < 0) {
//		// cannot open log file
//		return false;
//	}
//	string = (char*) malloc (file_dim*L0Communication::Parameter::COMM_BLOCK*sizeof(char));
//	sprintf(string,"debug_file%d",file_dim);
//	if ( write(fd, string, file_dim*L0Communication::Parameter::COMM_BLOCK) != file_dim * L0Communication::Parameter::COMM_BLOCK ) {
//		//failed writing log file
//		close(fd);
//		free(string);
//		return false;
//	}
//	free(string);
//	close(fd);
//	return true;
//}
//#endif

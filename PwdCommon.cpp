#ifdef _LEAKDETECT
	#ifdef _DEBUG
	   #ifndef DBG_NEW
		  #define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
		  #define new DBG_NEW
	   #endif
	#endif  // _DEBUG
	#define _CRTDBG_MAP_ALLOC
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>
#endif

#include <windows.h>
#include <npapi.h>
#include <ntsecapi.h>
#include <tchar.h>
#include <wchar.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#ifndef _LEAKDETECT
	#include <stdlib.h>
#endif
#include <vector>

#ifndef _INCL_PWD_COMMON_H
#define _INCL_PWD_COMMON_H
#include "PwdCommon.h"
#endif

//Default debug level
DEBUG_LEVEL debug_level = Debug;

//Default user - unknown
PWCHAR USER = NULL;

int simple_reg_read_int(HKEY phkey, PWCHAR subkey, PWCHAR keyname, DWORD default_estimated_size, int &value){

	int result = 0;

	PWCHAR tmp = NULL;
	result = simple_reg_read(phkey,
		subkey,
		keyname,
		NULL,
		default_estimated_size,
		tmp);

	if(result){
		value = _wtoi(tmp);
	}

	delete[] tmp;

	return result;
}

int simple_reg_read_wstring(HKEY phkey, PWCHAR subkey, PWCHAR keyname, DWORD default_estimated_size, PWCHAR &value) {

	value = NULL;

	return simple_reg_read(phkey,
		subkey,
		keyname,
		NULL,
		default_estimated_size,
		value);
}

int simple_reg_read(HKEY phkey, PWCHAR subkey, PWCHAR keyname, DWORD type, DWORD estimated_buf_size, PWCHAR &buffer) {

	HKEY hkey;
	LONG err;
	DWORD buf_size = estimated_buf_size;

	buffer = NULL;

	err = RegOpenKeyEx(phkey, subkey, 0, KEY_READ, &hkey);
	if(err == ERROR_SUCCESS)
	{
		buffer = new WCHAR[buf_size + 1];

		err = RegQueryValueEx(hkey, keyname, NULL, &type, (LPBYTE)buffer, &buf_size);
		if(err == ERROR_MORE_DATA){
			log_evt(Debug, AT_FILE_LINE, _TEXT("Allocating more memory for reading key."));
			//Try and allocate appropirate buffer
			//Previous call to RegQueryValueEx stored the required buffer size in buf_size
			delete [] buffer;
			buffer = new WCHAR[buf_size + 1];
			err = RegQueryValueEx(hkey, keyname, NULL, &type, (LPBYTE)buffer, &buf_size);
		}
	}

	RegCloseKey(hkey);

	if(err == ERROR_SUCCESS) {
		//RegQueryValueEx may return value that is not \0 terminated
		(buffer)[buf_size/sizeof(WCHAR)] = 0;
		return 1;
	}
	else {
		delete[] buffer;
		return 0;
	}
}


int log_evt_func_call(DEBUG_LEVEL debug_lvl, PWCHAR at_file_line, PWCHAR func){

	return log_evt(debug_lvl, at_file_line, _TEXT("Call to %s()"), func);
}

int log_evt_func_exit(DEBUG_LEVEL debug_lvl, PWCHAR at_file_line, PWCHAR func, ULONG exit_code){

	return log_evt(debug_lvl, at_file_line, _TEXT("%s() exiting with return code %x"), func, exit_code);
}

int log_evt(DEBUG_LEVEL debug_lvl, PWCHAR at_file_line, PWCHAR format, ...) {

	int result = 0;

	va_list args;

	size_t char_count = 0;
	size_t printf_char_count = 0;

	PWCHAR log_format = NULL;
	PWCHAR timestamp = NULL;
	PWCHAR log_prefix = NULL;
	PWCHAR template_format = NULL;

	FILE *log_file = NULL;

	//Abort if message should not be logged
	if(debug_lvl > debug_level)
		return 0;


	//Log template format
	if(USER == NULL){
		template_format = _TEXT("%s %s %s %s\n");
	}
	else {
		template_format = _TEXT("%s %s {%s} %s %s\n");
	}

	//Convert debug level to string
	PWCHAR debug_lvl_str = NULL;
	switch(debug_lvl){
	case Error:
		debug_lvl_str = _TEXT("Error");
		break;
	case Warn:
		debug_lvl_str = _TEXT("Warn");
		break;
	case Info:
		debug_lvl_str = _TEXT("Info");
		break;
	case Debug:
		debug_lvl_str = _TEXT("Debug");
		break;
	default:
		debug_lvl_str = _TEXT("Unknown");
	}


	//Get timestamp
	timestamp = log_timestamp();
	if(timestamp == NULL)
		return 0;


	//Calculate size of format string for vsprintf
	char_count = 0;
	char_count = wcslen(template_format);
	char_count += wcslen(timestamp);
	char_count += wcslen(debug_lvl_str);
	char_count += wcslen(at_file_line);
	if(USER != NULL)
		char_count += wcslen(USER);
	char_count += wcslen(format);

	//Format string for vsprintf
	log_format = new WCHAR[char_count + 1];

	if(log_format != NULL){

		if(USER == NULL)
			printf_char_count = swprintf_s(log_format, char_count, template_format, timestamp, debug_lvl_str, at_file_line, format);
		else
			printf_char_count = swprintf_s(log_format, char_count, template_format, timestamp, debug_lvl_str, USER, at_file_line, format);

		if(printf_char_count > 0){

			va_start(args, format);

			log_file = _wfopen(LOG_FILE, L"a");
			if(log_file != NULL){

				if(vfwprintf(log_file, log_format, args) > 0)
					result = 1;

				fclose(log_file);
			}

			va_end(args);
		}

		delete[] log_format;
	}

	delete[] timestamp;

	return result;
}

PWCHAR log_timestamp() {

	PWCHAR w_timestamp = NULL;
	CHAR a_timestamp[64];
	time_t raw_time;
	struct tm* current_time = NULL;
	int result = 1;

	//Timestamp is always less than 64 chars based on format used below
	w_timestamp = new WCHAR[64];

	if(w_timestamp == NULL){
		return NULL;
	}
	else {
		if(time(&raw_time) != -1){

			current_time = localtime(&raw_time);

			if(strftime(a_timestamp, 64, "%a %b %d %X %Y", current_time) != 0){

				if(ASCII_to_UNICODE(a_timestamp, w_timestamp, 64)){
					result = 0;
				}
			}
		}

		if(result == 1) {
			delete[] w_timestamp;
			w_timestamp = NULL;
		}
	}

	return w_timestamp;
}


int tokenize_string(PWCHAR string, WCHAR delimiter, std::vector<PWCHAR> &arr){
	PWCHAR token = NULL;
	PWCHAR token_cpy = NULL;

	if(string == NULL)
		return 0;

	if(string[0] == 0)
		return 0;

	int string_len = wcslen(string);
	int num_tokens = 1;
	for(int x = 0; x < string_len; x++){
		if (string[x] == delimiter)
			num_tokens++;
	}

	arr.reserve(num_tokens);

	PWCHAR delimiter_ = new WCHAR[2] { delimiter, 0 };

	token = wcstok(string, delimiter_);
	while(token != NULL) {
		PWCHAR token_cpy = new WCHAR[wcslen(token) + 1];
		wcscpy(token_cpy, token);

		arr.push_back(token_cpy);
		token = wcstok(NULL, delimiter_);
	}

	delete[] delimiter_;

	return num_tokens;
}

int untokenize_string_array(const std::vector<PWCHAR> &arr, WCHAR delimiter, PWCHAR* string){
	if(arr.size() == 0) {
		*string = new WCHAR[1] { 0 };
		return 1;
	}

	size_t num_chars = 0;

	for(std::vector<PWCHAR>::size_type i = 0; i != arr.size(); i++) {
		num_chars+= wcslen(arr[i]);
		if(i != 0) {
			++num_chars;
		}
	}
	++num_chars;

	*string = new WCHAR[num_chars];
	(*string)[0] = 0;

	PWCHAR delimiter_ = new WCHAR[2] { delimiter, 0 };

	for(std::vector<PWCHAR>::size_type i = 0; i != arr.size(); i++) {
		if(i != 0) {
			wcscat_s(*string, num_chars, delimiter_);
		}
		wcscat_s(*string, num_chars, arr[i]);
	}

	delete[] delimiter_;

	return num_chars;
}

int ASCII_to_UNICODE(PCHAR ascii_str, PWCHAR unicode_str, int size){

	//MultiByteToWideChar == 0 indicates failure
	if(MultiByteToWideChar(CP_ACP, 0, ascii_str, -1, unicode_str, size) == 0)
		return 0;
	else
		return 1;
}

int UNICODE_to_ASCII(PWCHAR unicode_str, PCHAR ascii_str, int size){

	//WideCharToMultiByte == 0 indicates failure
	if(WideCharToMultiByte(CP_ACP, 0, unicode_str, -1, ascii_str, size, NULL, NULL) == 0)
		return 0;
	else
		return 1;
}

PWCHAR PUNICODE_STRING_to_PWCHAR(PUNICODE_STRING PUN_String)
{
	size_t len = PUN_String->Length / sizeof(WCHAR);
	PWCHAR temp = new WCHAR[len + 1];
	memcpy(temp, PUN_String->Buffer, PUN_String->Length);
	temp[len] = 0;

	return temp;
}

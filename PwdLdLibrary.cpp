#ifdef _LEAKDETECT
	#ifdef _DEBUG
	   #ifndef DBG_NEW
		  #define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
		  #define new DBG_NEW
	   #endif
	#endif  // _DEBUG
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
#include <Strsafe.h>
#include <stdio.h>
#include <time.h>
#ifndef _LEAKDETECT
	#include <stdlib.h>
#endif
#include <vector>

#include "PwdCommon.h"
#include "PwdLdLibrary.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

typedef int (__cdecl *PPWD_FILT)(PUNICODE_STRING UserName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOL SetOperation);

HMODULE hModuleDll;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	hModuleDll = hModule;
    return TRUE;
}

BOOL NTAPI InitializeChangeNotify(void)
{
	return TRUE;
}

NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING Password)
{
    return STATUS_SUCCESS;
}

BOOL NTAPI PasswordFilter(PUNICODE_STRING UserName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOL SetOperation)
{
	log_evt_func_call(Debug,AT_FILE_LINE,_TEXT(__FUNCTION__));

	PWLLConfig pwll_config;			//Config structure for PwdLdLibrary
	PWCHAR pwll_config_str = NULL;	//String representation of PWLLConfig structure. Used for logging
	PWCHAR c_username = NULL;		//Username as a PWCHAR
	HINSTANCE hLib = NULL;			//Handle to library (.DLL)
	PPWD_FILT pwd_filt = NULL;		//Pointer to pwd_filt function in remote library
	BOOL pwd_status = FALSE;		//Return value from pwd_filt from remote library

	int result = 0;					//Temp var used for getting return value from func calls

	PWCHAR printf_format_str = NULL;	//String sent to any printf funcs (printf,swprintf,etc)
	size_t printf_char_count = 0;		//Used for storing the character count for buffer used w/ printf funcs		

	
	//Default debug level before config is parsed
	debug_level = Debug;

	//Convert username to PCHAR for logging purposes
	c_username = PUNICODE_STRING_to_PWCHAR(UserName);

	//Global User variable - used for associating log messages w/ particular user
	USER = c_username;

	//Log Passwd Change Recieved
	log_evt(Info,AT_FILE_LINE,_TEXT("Password change received."));

	if(!pwll_config.load_config_from_registry()){
		log_evt(Error,AT_FILE_LINE,_TEXT("Failed to parse configuration from registry. Aborting..."));
	}
	else{
		//Set debug level
		debug_level = pwll_config.debug_lvl;

		//Log configuration
		pwll_config_str = pwll_config.to_string();
		if(pwll_config_str != NULL) {
			log_evt(Debug, AT_FILE_LINE, pwll_config_str);
			delete[] pwll_config_str;
		}
			
		//Check if user is excluded from being processed further
		if(pwll_config.exclude_users.size() != 0){
			for(std::vector<PWCHAR>::size_type i = 0; i != pwll_config.exclude_users.size(); i++) {
				if(_wcsicmp(pwll_config.exclude_users[i], c_username) == 0){
					log_evt(Debug, AT_FILE_LINE, _TEXT("User matches exclusion list. Password change permitted but further processing will not be performed."));
					pwd_status = TRUE;
					break;
				}
			}
		}

		if(pwd_status != TRUE && pwll_config.libraries.size() != 0){
			for(std::vector<PWCHAR>::size_type i = 0; i != pwll_config.libraries.size(); i++) {
				
				size_t dll_len = wcslen(pwll_config.libraries[i]) + 1;
				WCHAR* abs_lib_path = new WCHAR[dll_len];
				wcscpy_s(abs_lib_path, dll_len, pwll_config.libraries[i]);

				hLib = LoadLibrary(abs_lib_path);

				if(hLib == NULL) {
					log_evt(Error, AT_FILE_LINE, _TEXT("Failed to load library %s. Aborting..."), abs_lib_path);
					pwd_status = FALSE;
				}
				else {
					//Log loading of library
					log_evt(Info, AT_FILE_LINE, _TEXT("Successfully loaded library %s."), abs_lib_path);

					pwd_filt = (PPWD_FILT)GetProcAddress(hLib, "pwd_filt");
					if(pwd_filt == NULL) {
						log_evt(Error, AT_FILE_LINE, _TEXT("Failed to load pointer to function pwd_filt for library %s. Aborting..."), abs_lib_path);
						pwd_status = FALSE;
					}
					else {
						pwd_status = pwd_filt(UserName, FullName, Password, SetOperation);

						//Log result of pwd_filt for this particular library
						log_evt(Info, AT_FILE_LINE, _TEXT("Function pwd_filt returned %d for library %s."), pwd_status, pwll_config.libraries[i]);
					}

					FreeLibrary(hLib);
					hLib = NULL;
				}

				delete[] abs_lib_path;

				if(!pwd_status)
					break;
			}
		}
	}

	//Cleanup
	USER = NULL;
	delete[] c_username;

	log_evt_func_exit(Info,AT_FILE_LINE,_TEXT(__FUNCTION__),pwd_status);

	return pwd_status;
}


int PWLLConfig::load_config_from_registry()
{
	log_evt_func_call(Debug,AT_FILE_LINE,_TEXT(__FUNCTION__));

	int result = 1;

	int tmp = 0;
	PWCHAR tmp_str = NULL;

	PWCHAR read_error_msg = _TEXT("simple_reg_read failed to open or read HKLM\\%s %s");

	//Debug level
	result = simple_reg_read_int(
		HKEY_LOCAL_MACHINE,
		REG_KEY_CONF,
		REG_NAME_DBG_LVL,
		sizeof(WCHAR) * 2,
		tmp);

	if(!result){
		log_evt(Error,AT_FILE_LINE,read_error_msg,REG_KEY_CONF,REG_NAME_DBG_LVL);
	}
	else
		debug_lvl = (DEBUG_LEVEL) tmp;


	//Exclude users
	if(result){

		result = simple_reg_read_wstring(
			HKEY_LOCAL_MACHINE,
			REG_KEY_CONF,
			REG_EXCLUDE_USERS,
			sizeof(WCHAR)*1024,
			tmp_str);

		if(!result){
			log_evt(Error, AT_FILE_LINE, read_error_msg, REG_KEY_CONF, REG_EXCLUDE_USERS);
		}
		else{

			if(tokenize_string(tmp_str, ' ', exclude_users) < 1){
				log_evt(
					Warn,
					AT_FILE_LINE,
					_TEXT("Failed to parse HKLM\\%s %s into list of user exclusions. Proceeding w/ empty user exclusion list."),
					REG_KEY_CONF,
					REG_EXCLUDE_USERS);
			}
		}

		delete[] tmp_str;
	}

	//Libs
	if(result){
		result = simple_reg_read_wstring(
			HKEY_LOCAL_MACHINE,
			REG_KEY_CONF,
			REG_NAME_LIBS,
			sizeof(WCHAR)*1024,
			tmp_str);

		if(!result){
			log_evt(Error,AT_FILE_LINE,read_error_msg,REG_KEY_CONF,REG_NAME_LIBS);
		}
		else {

			if(tokenize_string(tmp_str, ' ', libraries) < 1){
				log_evt(
					Warn,
					AT_FILE_LINE,
					_TEXT("Failed to parse HKLM\\%s %s into list of libraries. Proceeding w/ empty library list."),
					REG_KEY_CONF,
					REG_NAME_LIBS);
			}

			delete[] tmp_str;
		}
	}

	log_evt_func_exit(Debug,AT_FILE_LINE,_TEXT(__FUNCTION__),result);
	return result;
}

PWCHAR PWLLConfig::to_string()
{
	log_evt_func_call(Debug,AT_FILE_LINE,_TEXT(__FUNCTION__));

	size_t config_str_len = 0;
	PWCHAR config_str = NULL;
	PWCHAR libs = NULL;
	PWCHAR excludes = NULL;

	WCHAR config_templ[] =
		L"Settings {"
		L" Debug Level: %d;"
		L" Exclude Users: %s;"
		L" Libraries: %s; };";

	config_str_len += wcslen(config_templ);
	config_str_len += 2; //Debug level should never be more than 2 digits

	//Libs
	untokenize_string_array(libraries, ' ', &libs);
	config_str_len += wcslen(libs);
	config_str_len++;

	//User exclusions
	untokenize_string_array(exclude_users, ' ', &excludes);
	config_str_len += wcslen(excludes);
	config_str_len++;

	config_str = new WCHAR[config_str_len];
	
	int result = swprintf_s(config_str, config_str_len, config_templ, debug_lvl, excludes, libs);
	if(result < 0)
		return NULL;

	delete[] libs;
	delete[] excludes;

	log_evt_func_exit(Debug,AT_FILE_LINE,_TEXT(__FUNCTION__),result);
	return config_str;
}

PWLLConfig::~PWLLConfig() {
	for(std::vector<PWCHAR>::size_type i = 0; i != exclude_users.size(); i++) {
		delete[] exclude_users[i];
	}
	for(std::vector<PWCHAR>::size_type i = 0; i != libraries.size(); i++) {
		delete[] libraries[i];
	}
}

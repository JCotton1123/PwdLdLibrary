//---------------------------------------------------------------------------//
// @Macros/Config

//Debugging
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT_FILE_LINE _TEXT("(") _TEXT(__FILE__) _TEXT(":") _TEXT(TOSTRING(__LINE__)) _TEXT(")")

//Log File
#define LOG_FILE L"c:\\windows\\system32\\LogFiles\\pwd_filt_libs.log"

//Debug Levels
typedef enum
{
	Error = 0,
	Warn,
	Info,
	Debug,
	Spec
} DEBUG_LEVEL;

//Global Vars to assist with logging
extern DEBUG_LEVEL debug_level;
extern PWCHAR USER;


//---------------------------------------------------------------------------//
// @Prototypes
int simple_reg_read_int(HKEY phkey, PWCHAR subkey, PWCHAR keyname, DWORD default_estimated_size, int &value);
int simple_reg_read_wstring(HKEY phkey, PWCHAR subkey, PWCHAR keyname, DWORD default_estimated_size, PWCHAR &value);
int simple_reg_read(HKEY phkey, PWCHAR subkey, PWCHAR keyname, DWORD type, DWORD estimated_buf_size, PWCHAR &buffer);

int log_evt_func_call(DEBUG_LEVEL debug_lvl, PWCHAR at_file_line, PWCHAR func);
int log_evt_func_exit(DEBUG_LEVEL debug_lvl, PWCHAR at_file_line, PWCHAR func, ULONG exit_code);
int log_evt(DEBUG_LEVEL debug_lvl, PWCHAR at_file_line, PWCHAR format, ...);
PWCHAR log_timestamp();

int tokenize_string(PWCHAR string, WCHAR delimiter, std::vector<PWCHAR> &arr);
int untokenize_string_array(const std::vector<PWCHAR> &arr, WCHAR delimiter, PWCHAR* string);

int ASCII_to_UNICODE(PCHAR ascii_str, PWCHAR unicode_str, int size);
int UNICODE_to_ASCII(PWCHAR unicode_str, PCHAR ascii_str, int size);

PWCHAR PUNICODE_STRING_to_PWCHAR(PUNICODE_STRING PUN_String);

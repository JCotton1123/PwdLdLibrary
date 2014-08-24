//---------------------------------------------------------------------------//
// @Macros/Config

//Registry Configuration
//Keys
#define REG_KEY_CONF L"Software\\PwdFiltLibs\\PwdLdLibs"

//Names
#define REG_NAME_DBG_LVL L"DebugLvl"
#define REG_NAME_LIBS L"Libraries"
#define REG_EXCLUDE_USERS L"ExcludeUsers"


//---------------------------------------------------------------------------//
// @Structures


class PWLLConfig {
public:
	//Debug level
	DEBUG_LEVEL debug_lvl = Debug;
	
	//Array of users for exclusion
	std::vector<PWCHAR> exclude_users;

	//Array of libraries
	std::vector<PWCHAR> libraries;

	int load_config_from_registry();
	PWCHAR to_string();

	~PWLLConfig();
};

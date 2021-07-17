#pragma once
#include <string>
using namespace std;

//各种参数的默认值

class Config {
public:
	int listen_port = 5180;
	int conn_port = 5180;
	int max_conn = 10;
	const char* target = "127.0.0.1";
	static bool enable_log;
	static string logfile;
	string default_mode = "none";
	bool enable_localarg = false;
	string argfile = "C:\\Windows\\Temp\\sf.txt";
	int bufsize = 51800;
	static string key;
	static string encry_mode;
	
};


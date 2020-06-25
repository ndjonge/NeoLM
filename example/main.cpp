#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <numeric>
#include <unordered_map>
#include <vector>

#include "http_basic.h"

//#include "http_asio.h"
//#include "neolm.h"


#include "cld_director.h"

int main()
{
	network::init();
	network::ssl::init();

#ifdef _WIN32
	const char* rest_argv[]
		= { "appname", "-configfile", "C:/tmp/pm_root/config.json", "-http_port", "4000", "-curldebug" };
#else
	const char* rest_argv[]
		= { "appname", "-configfile", "/home/ndjonge/config.json", "-http_port", "4000", "-curldebug" };
#endif
	start_rest_server(4, rest_argv);

	while (1)
	{
	}
}

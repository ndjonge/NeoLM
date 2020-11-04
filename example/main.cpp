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


int main(int argc, const char* argv[])
{
	network::init();
	network::ssl::init();

//#ifdef _WIN32
//	const char* rest_argv[]
//		= { "appname", "-config", "C:/tmp/pm_root/config.json", /*"-test",*/ "-http_listen_port", "4000", "-logfile", "cout", "-loglevel", "debug" };
//#else
//	const char* rest_argv[]
//		= { "appname",	"-config", "/home/ndjonge/config.json", /*"-test",*/ "-http_listen_port", "4000", "-logfile", "cout", "-loglevel", "api" };
//#endif

	start_cld_manager_server(argc, argv);

	while (1)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

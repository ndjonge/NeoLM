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
#include "cld_director.h"

#include "nlohmann/json.hpp"
using json = nlohmann::json;

int main(int argc, const char* argv[])
{
	network::init();
	network::ssl::init();

	start_cld_manager_server(argc, argv);
	
	run_cld_manager_server();
	stop_cld_manager_server();
};
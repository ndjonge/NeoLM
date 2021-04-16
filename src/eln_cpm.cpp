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
#include "eln_cpm.h"

#include "nlohmann/json.hpp"
using json = nlohmann::json;

int main(int argc, const char* argv[])
{
	network::init();
	network::ssl::init();

	start_eln_cpm_server(argc, argv);
	
	run_eln_cpm_server();
	stop_eln_cpm_server();
};
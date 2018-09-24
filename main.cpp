#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>

#include <signal.h>


#include "http_basic.h"
#include "http_asio.h"

//#include "neolm.h"
//#include <nlohmann/json.hpp>
//using json = nlohmann::json;

namespace http
{

namespace cluster
{

}

}


using namespace std::literals;

int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

	neolm::license_manager<http::basic::threaded::server> license_server{ "/projects/neolm_licenses/" };

    //neolm::license_manager<http::basic::async::server> license_server{ "/projects/neolm_licenses/" };

	license_server.start_server();

	//license_server.add_test_routes();

	network::init();
	while (1)
	{
		//load_test();
        std::this_thread::sleep_for(10s);
	}
}

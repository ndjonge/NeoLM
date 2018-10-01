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

#include "neolm.h"
//#include <nlohmann/json.hpp>
//using json = nlohmann::json;

namespace http
{

namespace cluster
{
	
namespace haproxy
{
	bool add_upstream_server(const std::string& server)
	{
		bool ret = false;
		std::string url = "::1";
		network::tcp::v6 s(url, port);
		network::error_code ec;
		s.connect(ec);

		// auto start_requests = std::chrono::system_clock::now();

		for (int i = 0; i < test_requests; i++)
		{

			http::request_message req("GET", "/null");

			network::write(s.socket(), http::to_string(req));


		network::tcp::v6 endpoint_to_haproxy{3000};
		network::tcp::socket s;
		network::error_code ec;

		endpoint_to_haproxy.connect(ec);

		if (!ec)
		{
			network::write(s, "blabla");
		}

		return ret;
	}

	bool remove_upstream_server(const std::string& server)
	{
	}
}

namespace nginx
{
}

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

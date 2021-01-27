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

				//



int main(int argc, const char* argv[])
{
	{
		//// vector of allowed network objects
		//// return true if client ip converted to network with same width as allowed is same canononical network.
		//std::string allowed_spec
		//	= std::string{ "::ffff:127.0.0.0/120" }; //::ffff:192.168.1.0/120;::ffff:10.0.0.0/104"};

		////auto address = asio::ip::make_address_v6("::ffff:192.168.2.1");
		//auto address = asio::ip::make_address_v6("::ffff:127.0.0.1");

		//for (const auto& allowed_range_spec : util::split(allowed_spec, ";"))
		//{
		//	auto spec = util::split(allowed_range_spec, "/");
		//	auto allowed_address = asio::ip::address_v6::from_string(spec[0]);

		//	auto x = asio::ip::network_v6(allowed_address, std::atoi(spec[1].data()));

		//	auto z = asio::ip::network_v6(address, 128);

		//	std::cout << "ip:" << address.to_string() << " network1:" << x.canonical().to_string()
		//			  << " network2:" << z.canonical().to_string() 
		//			  << " result1:" << (x.canonical() == z.canonical()) 
		//		      << " result2:" << z.is_subnet_of(x.canonical()) << "\n";
		//}

	}




	network::init();
	network::ssl::init();

	//http::client::request<http::method::get>(
	//	"http://nlbalcc/",
	//	{},
	//	"",
	//	[](http::response_message& response, asio::error_code& ec) 
	//	{
	//		if (!ec)
	//			std::cout << "body:" << response.body() << "\n";
	//	}
	//);

	start_cld_manager_server(argc, argv);
	run_cld_manager_server();
	stop_cld_manager_server();
}

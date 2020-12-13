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


	http::client::async_request<http::method::get>(
		"http://info.cern.ch/", { { "Host", "nlbalcc" } }, "", [](http::response_message& response, asio::error_code& ec) 
		{
			if (!ec)
				std::cout << "body:" << response.body() << "\n";
		});

	start_cld_manager_server(argc, argv);

	while (1)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

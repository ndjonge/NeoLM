#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <numeric>

#include <signal.h>


#include "http_basic.h"
#include "http_asio.h"

#include "neolm.h"
//#include <nlohmann/json.hpp>
//using json = nlohmann::json;

using namespace std::literals;


int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

//	network::tcp::resolver resolver;
//	auto results = resolver.resolve("localhost", "4000");

//	network::tcp::socket s;
//	network::connect(s, results);

//	http::request_message request{"GET", "/dynamic?upstream=backend"};
//	request.set("Host", "localhost");

//	std::array<char, 8192> data;
//	auto request_result  = network::write(s, http::to_string(request));
//	auto response_result = network::read(s, network::buffer(data.data(), data.size()));

	http::session_handler session{http::configuration{}};

//	http::response_parser p;
//	http::response_message message;

//	auto parse_result = p.parse(message, data.begin(), data.end());

	auto result1 = session.get("http://localhost:4000/dynamic?upstream=backend", {});
	auto result2 = session.get("http://localhost:4000/status", {});

	
	neolm::license_manager<http::basic::threaded::server> license_server{http::configuration
		{
			{ "server", "neolm/8.0.01" },
			{ "listen_port_begin", "3000" },
			{ "listen_port_end", "3063" },
			{ "keepalive_count", "1048576" },
			{ "keepalive_timeout", "30" },
			{ "thread_count", "8" },
			{ "doc_root", "/Projects/doc_root" },
			{ "ssl_certificate", "/Projects/ssl/ssl.crt" },
			{ "ssl_certificate_key", "/Projects/ssl/ssl.key" } 
		},	"/projects/neolm_licenses/" };

    //neolm::license_manager<http::basic::async::server> license_server{ "/projects/neolm_licenses/" };

	license_server.start_server();
	license_server.run();

	std::cout << "exit!\n";

}

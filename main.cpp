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

	neolm::license_manager<http::basic::threaded::server> license_server{http::configuration
						{
						  { "server", "neolm/8.0.01" },
						  { "listen_port_begin", "3000" },
						  { "listen_port_end", "3015" },
						  { "keepalive_count", "4096" },
						  { "keepalive_timeout", "30" },
						  { "thread_count", "8" },
						  { "scale_out_command", "" + std::accumulate(argv, argv + argc, std::string("")) + " &"},
						  { "scale_in_command", ""},
						  { "proxy_address", "127.0.0.1:9999" },
						  { "doc_root", "/Projects/doc_root" },
						  { "ssl_certificate", "/Projects/ssl/ssl.crt" },
						  { "ssl_certificate_key", "/Projects/ssl/ssl.key" } 
						},	"/projects/neolm_licenses/" };

    //neolm::license_manager<http::basic::async::server> license_server{ "/projects/neolm_licenses/" };

	license_server.start_server();
	license_server.run();

	std::cout << "exit!\n";

}

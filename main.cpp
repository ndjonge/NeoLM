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
#include "http_upstream_node.h"

#include "http_asio.h"
#include "neolm.h"

using namespace std::literals;

int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

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
		{ "ssl_certificate_key", "/Projects/ssl/ssl.key" }, 
		// http_upstream_node.h
		{ "upstream-node-nginx-endpoint", "http://nlbalndjonge01.mshome.net:4000/dynamic" },
		{ "upstream-node-nginx-endpoint-downstream", "backend" },
		{ "upstream-node-nginx-endpoint-myip", "172.17.245.161" },
		{ "upstream-node-nginx-endpoint-api", "ngx_dynamic_upstream" },
		{ "upstream-node-scaling", "self-scale" },
		{ "upstream-node-scaling-fork-cmd", "start /b " + std::accumulate(argv, argv + argc, std::string("")) },
		{ "upstream-node-connection-limit-high", "2" },
		{ "upstream-node-connection-limit-lwo", "0"}
		// http_upstream_node.h
	},	"/projects/neolm_licenses/" };

    //neolm::license_manager<http::basic::async::server> license_server{ "/projects/neolm_licenses/" };

	license_server.start_server();

	license_server.run();

	std::cout << "exit!\n";

}

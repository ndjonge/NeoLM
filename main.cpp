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
#include "http_proxy_controler.h"

#include "http_asio.h"
#include "neolm.h"

using namespace std::literals;


int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

	http::session_handler session{http::configuration{}};

	//	auto result1 = session.get("http://localhost:4000/dynamic?upstream=backend", {});

	neolm::license_manager<http::basic::threaded::server> license_server{http::configuration
		{
			{ "server", "neolm/8.0.01" },
			{ "listen_port_begin", "3000" },
			{ "listen_port_end", "3063" },
			{ "cluster-downstream-nginx-endpoint", "http://localhost:4000/dynamic"},
			{ "cluster-downstream-nginx-endpoint-api", "ngx_dynamic_upstream"},
			{ "cluster-scaling-mode", "self-scale"},
			{ "cluster-scale-connection-limit-high", "2"},
			{ "cluster-scale-connection-limit-lwo", "0"},
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

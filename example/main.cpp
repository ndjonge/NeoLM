#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <numeric>
#include <unordered_map>

#include "http_basic.h"

//#include "http_asio.h"
#include "neolm.h"

#include "process_utils.h"

#include <vector>

using json = nlohmann::json;

int main()
{
	network::init();
	network::ssl::init();

	neolm::license_manager<http::basic::threaded::server> license_server{
		http::configuration{ { "http_server_identification", "neolm/8.0.01" },
							 { "http_listen_address", "::0" },
							 { "http_listen_port_begin", "3000" },
							 { "https_listen_port_begin", "0" },
							 { "https_listen_port_end", "0" },
							 { "http_enabled", "true" },
							 { "https_enabled", "false" },
							 { "keepalive_count", "1048576" },
							 { "keepalive_timeout", "4" },
							 { "doc_root", "/Projects/doc_root" },
							 { "ssl_certificate", "/projects/ssl/server.crt" },
							 { "ssl_certificate_key", "/projects/ssl/server.key" },
							 { "internal_base", "/_internal/server" },
							 { "upstream_node_type", "" },
							 { "upstream_node_nginx-endpoint", "nlbavlflex01.infor.com:7777" },
							 { "upstream_node_nginx-group", "bshell-workers" } },
		"/projects/neolm_licenses/"
	};

	license_server.start_server();

	license_server.run();
	std::cout << "exit!\n";
}

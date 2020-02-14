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

	for (auto i = 0; i != 100; i++)

	{
		neolm::license_manager<http::basic::threaded::server> license_server{
			http::configuration{ { "http_server_identification", "mir_http/8.0.01" },
								 { "http_listen_address", "::0" },
								 { "http_listen_port_begin", "3000" },
								 { "https_enable", "false" },
								 { "private_base", "/_internal" },
								 { "log_file", "accesslog.txt" },
								 { "log_level", "debug" },
								 { "upstream_node_type", "" },
								 { "upstream_node_nginx-endpoint", "nlbavlflex01.infor.com:7777" },
								 { "upstream_node_nginx-group", "bshell-workers" } },
			"/projects/neolm_licenses/"
		};

		license_server.start_server();

		license_server.run();
	}
}

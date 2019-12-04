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
	std::array<char, 8192> b;
	b.fill('a');
	b[b.size() - 1] = 0;
	std::string s = "aap3";

	lgr::logger log_output(std::cout);

	//	log_output << lgr::info("A info log message {s} {d} {x} {X} {s} {s} ...end\n", "aap", 10, 10, 24, &b[0], s);
	//	log_output << lgr::warning("A warning log message {s} {d} {x} {X} {s} {s} ...end\n", "aap", 10, 10, 24, &b[0],
	//s);

	network::init();
	network::ssl::init();

	neolm::license_manager<http::basic::threaded::server> license_server{
		http::configuration{ { "http_server_identification", "mir_http/8.0.01" },
							 { "http_listen_address", "::0" },
							 { "http_listen_port_begin", "3000" },
							 { "https_listen_port_begin", "0" },
							 { "https_listen_port_end", "0" },
							 { "private_base", "/_internal" },
							 { "log_file", "" },
							 { "upstream_node_type", "" },
							 { "upstream_node_nginx-endpoint", "nlbavlflex01.infor.com:7777" },
							 { "upstream_node_nginx-group", "bshell-workers" } },
		"/projects/neolm_licenses/",
		log_output
	};

	license_server.start_server();

	license_server.run();
	std::cout << "exit!\n";
}

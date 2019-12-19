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
	// std::array<char, 255> buf;
	// std::ofstream ofs("/projects/access.log", std::ofstream::out);

	// ofs.rdbuf()->pubsetbuf(&(*buf.begin()), buf.size());

	// lgr::logger log_output{ ofs, lgr::level::accesslog };

	network::init();
	network::ssl::init();

	neolm::license_manager<http::basic::threaded::server> license_server{
		http::configuration{ { "http_server_identification", "mir_http/8.0.01" },
							 { "http_listen_address", "::0" },
							 { "http_listen_port_begin", "3000" },
							 { "http_listen_port_end", "3010" },
							 { "https_listen_port_begin", "0" },
							 { "https_listen_port_end", "0" },
							 { "private_base", "/_internal" },
							 { "log_file", "/projects/accesslog.log" },
							 { "log_level", "debug" },
							 { "upstream_node_type", "" },
							 { "upstream_node_nginx-endpoint", "nlbavlflex01.infor.com:7777" },
							 { "upstream_node_nginx-group", "bshell-workers" } },
		"/projects/neolm_licenses/"
	};

	license_server.start_server();

	license_server.run();
	std::cout << "exit!\n";
}

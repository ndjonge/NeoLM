#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <numeric>
#include <unordered_map>

#include "http_basic.h"
#include "http_upstream_node.h"

#include "http_asio.h"
#include "neolm.h"

#include "process_utils.h"

using namespace std::literals;
using json = nlohmann::json;

int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

	process::spawn_as_user("notepad");

	// create an empty structure (null)
	json j;

	// add a number that is stored as double (note the implicit conversion of j to an object)
	j["pi"] = 3.141;

	neolm::license_manager<http::basic::threaded::server> license_server{ http::configuration{
																			  { "http_server_identification", "neolm/8.0.01" },
																			  { "http_listen_port_begin", "3000" },
																			  { "http_listen_port_end", "3000" },
																			  { "https_listen_port_begin", "5000" },
																			  { "https_listen_port_end", "5000" },
																			  { "keepalive_count", "1048576" },
																			  { "keepalive_timeout", "30" },
																			  { "thread_count", "8" },
																			  { "doc_root", "/Projects/doc_root" },
																			  { "ssl_certificate", "/projects/ssl/server.crt" },
																			  { "ssl_certificate_key", "/projects/ssl/server.key" },
																		  },
																		  "/projects/neolm_licenses/" };

	license_server.start_server();

	license_server.run();
	std::cout << "exit!\n";
}

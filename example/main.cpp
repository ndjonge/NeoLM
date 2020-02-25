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

#include "hyb_string.h"
#include "hyb_vector.h"

#include <vector>

using json = nlohmann::json;

void* operator new(std::size_t sz)
{
	if (sz == 32)
	{
		std::printf("global op new called, size = %zu\n", sz);
	}

	void* ptr = std::malloc(sz);
	if (ptr)
		return ptr;
	else
		throw std::bad_alloc{};
}

void operator delete(void* ptr) noexcept
{
	// std::puts("global op delete called");
	std::free(ptr);
}

int main()
{
	//hyb::string s1 = "aap";
	//hyb::string s2 = s1;
	//hyb::string s3{ s2 };
	//hyb::string s4{ s1 + s2 };

	//std::stringstream ss;

	//ss << s4;

	////bool s5 = (s1 == s2);
	////bool s6 = (s1 != s1);
	////bool s7 = (ss.str() == s4);

	//{

	//	hyb::vector<std::int16_t, 10> v1;

	//	for (std::int16_t x = 0; x != 9; x++)
	//		v1.emplace_back(x);

	//	hyb::vector<std::string, 10> v2{};

	//	for (std::int16_t x = 0; x != 9; x++)
	//		v2.emplace_back(std::to_string(x));

	//	hyb::vector<std::pair<std::string, std::string>, 4> v3{ { "key1", "value1" },
	//															{ "key2", "value2" },
	//															{ "key3", "value3" } };
	//}

	// auto v4{ std::move(v3) };

	// hib::vector<std::string, 20> v5{ "aa",
	//								 "bb"
	//								 "cc" };

	// auto x = v5.data();

	// std::cout << *x << std::endl;


	//hyb::string str("Please, erase trailing white-spaces   \n");
	//hyb::string whitespaces(" \t\f\v\n\r");

	//std::size_t found = str.find_last_not_of(whitespaces.data());
	//if (found != hyb::string::npos)
	//	str[found + 1] = 0;
	//else
	//	str.clear(); // str is all whitespace

	//std::cout << '[' << str << "]\n";

	//return 0;



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
								 { "log_file", "cerr" },
								 { "log_level", "none" },
								 { "upstream_node_type", "" },
								 { "upstream_node_nginx-endpoint", "nlbavlflex01.infor.com:7777" },
								 { "upstream_node_nginx-group", "bshell-workers" } },
			"/projects/neolm_licenses/"
		};

		license_server.start_server();

		// license_server.run_benchmark();
		license_server.run();
	}
}

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

//#include "http_asio.h"
#include "neolm.h"

#include "process_utils.h"

#include "trie.h"
#include <vector>

using json = nlohmann::json;

namespace http
{

namespace util
{

template <typename K, typename V, char D> class dispatch_map
{
	template <typename K, typename V> class node
	{
	public:
		node(const K& key) 
		{ 
			nodes_[key].reset();
		}

		node(const K& key, const V& value)
			: value_(new V{ value }){};

		friend dispatch_map;

	private:
		std::unique_ptr<V> value_;
		std::map<K, std::unique_ptr<V>> nodes_;
	};

public:
	dispatch_map() = default;

	void push_back(const K& key, const V& value)
	{
		size_t b = key.find_first_of(delimiter_);
		size_t e = key.find_first_of(delimiter_, b + 1);

		size_t token = 0;

		for (token = 0; b != std::string::npos; token++)
		{
			std::string current_token = key.substr(b, e - b);

			if (!root_)
			{
				root_.reset(new node<K, V>(current_token));
			}

			auto& i = root_->nodes_[current_token];

			if (!i)
			{
				i.reset(new node<K,V>(current_token));
			}

					/*if (!node)
						if (e == std::string::npos)
							root_->nodes_.emplace(current_token, value);
						else
							root_->nodes_.emplace(current_token);
					else if (e == std::string::npos && node->value_.empty())
							node->value_.reset(new V(value));

					*/

			//}

			if (e == std::string::npos) break;

			b = key.find_first_of('/', e);
			e = key.find_first_of('/', b + 1);
		}
	}

private:
	std::unique_ptr<node<K, V>> root_;
	char delimiter_{ D };
};

} // namespace util

} // namespace http

int main()
{
	http::util::dispatch_map<std::string, int, '/'> dispatch_map;

	dispatch_map.push_back("/test/test/abcd/abcd-2345", 101);
	dispatch_map.push_back("/test/test/test/test/test/test-12345", 100);

	network::init();
	network::ssl::init();

	/*try
	{
		process::spawn_as_user("cmd", "testuser", "test");
	}
	catch (std::runtime_error& e)
	{
		std::cout << e.what() << "\n";
	}*/

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

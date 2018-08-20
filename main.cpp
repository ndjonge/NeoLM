#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>

#include <signal.h>

#include "http_basic.h"

#include "http_asio.h"

#include "json.h"

using namespace std::literals;

namespace neolm
{
class instance;
template <class M> class product;

class user;
class server;
class named_user_license;
class concurrent_user_license;
class named_server_license;

using instances = std::unordered_map<std::string, neolm::instance>;
using concurrent_user_licenses = std::unordered_map<std::string, neolm::product<neolm::concurrent_user_license>>;
using named_user_licenses = std::unordered_map<std::string, neolm::product<neolm::named_user_license>>;
using named_server_licenses = std::unordered_map<std::string, neolm::product<neolm::named_server_license>>;

using users = std::unordered_map<std::string, neolm::user>;
using servers = std::unordered_map<std::string, neolm::server>;

template <class M> class product
{
public:
	product(std::string id, std::string description, M&& m)
		: id_(id)
		, description_(description)
		, model_(m){};


	friend json::value to_json(const product<M>& m);

private:
	std::string id_;
	std::string description_;

	M model_;
};


class user
{
public:
	user(std::string name)
		: name_(name){};

	std::string name_;
};

class server
{
public:
	server(std::string id, std::string hostname)
		: id_(id)
		, hostname_(hostname){};

	std::string id_;
	std::string hostname_;
};

class named_user_license
{
public:
	named_user_license(size_t max_heavy, size_t max_light) : max_heavy_(max_heavy), max_light_(max_light) {};

private:
	size_t max_heavy_;
	size_t max_light_;
};

class named_server_license
{
public:
	named_server_license(size_t max) : max_(max) {};

private:
	size_t max_;
};

class concurrent_user_license
{
public:
	concurrent_user_license(size_t max) : max_(max) {}


private:
	size_t max_;
};

class instance
{
public:
	instance(json::value& instance_license, json::value& instance_allocation)
	{
		id_ = json::get<std::string>(instance_license["id"]);
		name_ = json::get<std::string>(instance_license["name"]);
		license_key_ = json::get<std::string>(instance_license["key"]);
		license_hash_ = json::get<std::string>(instance_license["bind_to"]);

		auto named_user_license_definitions = instance_license["named-user"].as_array();
		auto named_server_license_definitions = instance_license["named-server"].as_array();
		auto concurrent_user_license_definitions = instance_license["concurrent-user"].as_array();

		for (auto& named_user_license_definition : named_user_license_definitions)
		{
			named_user_licenses_.emplace(
				json::get<std::string>(named_user_license_definition["id"]),
				product<named_user_license>(
					json::get<std::string>(named_user_license_definition["id"]),
					json::get<std::string>(named_user_license_definition["description"]),
						named_user_license(
							json::get<std::size_t>(named_user_license_definition["max_heavy"]),
							json::get<std::size_t>(named_user_license_definition["max_light"]))));
		}

		for (auto& named_server_license_definition : named_server_license_definitions)
		{
			named_server_licenses_.emplace(
				json::get<std::string>(named_server_license_definition["id"]),
			
				product<named_server_license>(
					json::get<std::string>(named_server_license_definition["id"]),
					json::get<std::string>(named_server_license_definition["description"]),
						named_server_license(
							json::get<std::size_t>(named_server_license_definition["max"]))));
		}

		for (auto& concurrent_user_license_definition : concurrent_user_license_definitions)
		{
			concurrent_user_licenses_.emplace(
				json::get<std::string>(concurrent_user_license_definition["id"]),

				product<concurrent_user_license>(
					json::get<std::string>(concurrent_user_license_definition["id"]),
					json::get<std::string>(concurrent_user_license_definition["description"]),
					concurrent_user_license(
							json::get<std::size_t>(concurrent_user_license_definition["max"]))));
		}

		auto users = instance_allocation["users"].as_array();
		auto servers = instance_allocation["servers"].as_array();

		for (auto& user : users)
		{
			users_.emplace(json::get<std::string>(user["name"]), json::get<std::string>(user["name"]));
		}

		for (auto& server : servers)
		{
			servers_.emplace(
				json::get<std::string>(server["name"]),
				neolm::server(json::get<std::string>(server["name"]), json::get<std::string>(server["name"])));
		}
	}

	std::string id_;
	std::string name_;
	std::string license_key_;
	std::string license_hash_;

	named_user_licenses named_user_licenses_;
	named_server_licenses named_server_licenses_;
	concurrent_user_licenses concurrent_user_licenses_;

	users users_;
	servers servers_;

	std::int32_t sequence_ = 0;

	class license_aquired
	{
	public:
		license_aquired(
			std::string id,
			std::string parameter,
			std::string tag,
			std::string hostname,
			std::int32_t process_id,
			std::int32_t sequence_id,
			std::int32_t number) 	
		: id_(id)
		, parameter_(parameter)
		, process_id_(process_id)
		, hostname_(hostname)
		, sequence_id_(sequence_id)
		, number_(number)
		, last_confirm_(0)
		{
		}

		friend class instance;
		friend json::value to_json(const instance::license_aquired& license_aquired);
	private:
		std::string id_;
		std::string parameter_;
		std::int32_t process_id_;
		std::string hostname_;
		std::int32_t sequence_id_;
		std::int32_t number_;
		std::int64_t last_confirm_;
	};

	/*
	request_license --> audit_trail --> audit_trail_hash
	confirm_license --> audit_trail --> audit_trail_hash
	confirm_license --> audit_trail --> audit_trail_hash
	confirm_license --> audit_trail --> audit_trail_hash
	confirm_license --> audit_trail --> audit_trail_hash
	confirm_license --> audit_trail --> audit_trail_hash
	release_license --> audit_trail --> audit_trail_hash
	*/



	json::object about_license(std::string license_id)
	{
		json::object ret;

		auto i = licenses_aquired_.at(std::string(license_id));

		ret.emplace("id", license_id);
		ret.emplace("hostname", i.hostname_);
		ret.emplace("last-confirm", i.last_confirm_);
		ret.emplace("number", i.number_);
		ret.emplace("parameter", i.parameter_);
		ret.emplace("process-id", i.process_id_);
		ret.emplace("sequence", i.sequence_id_);

		return ret;
	}

	json::object request_license(json::object& request_license, std::string hostname)
	{
		json::object ret;

		std::int32_t number = 0;

		std::string id = json::get<std::string>(request_license["id"]);
		std::string parameter = json::get<std::string>(request_license["parameter"]);
		std::string tag = json::get<std::string>(request_license["tag"]);


		std::stringstream s;

		s << id << parameter << hostname << sequence_++ << number;

		auto i = licenses_aquired_.emplace(
			std::make_pair(
				std::string(s.str()), 
				license_aquired(id, parameter, tag, "",0 ,0, 0)));



		ret.emplace("id", s.str());

		return ret;
	}

	json::object confirm_license(json::object& confirm_info, std::string hostname)
	{
		json::object ret;

		std::string id = json::get<std::string>(confirm_info["id"]);
		std::string parameter = json::get<std::string>(confirm_info["parameter"]);
		std::string tag = json::get<std::string>(confirm_info["tag"]);

		std::int32_t number = 0;
		
		std::stringstream s;

		s << id << parameter << hostname << sequence_++ << number;

		auto i = licenses_aquired_.at(std::string(s.str()));

		i.last_confirm_ = static_cast<std::int64_t>(std::time(0));

		return ret;
	}


	json::object release_license(json::object& release_info, std::string hostname)
	{
		json::object ret;

		std::string id = json::get<std::string>(release_info["id"]);
		std::string parameter = json::get<std::string>(release_info["parameter"]);
		std::string tag = json::get<std::string>(release_info["tag"]);

		std::int32_t number = 0;
		
		std::stringstream s;

		s << id << parameter << hostname << sequence_++ << number;

		auto i = licenses_aquired_.erase(s.str());

		return ret;
	}


	std::unordered_map<std::string, license_aquired> licenses_aquired_;
};

json::value to_json(const instance::license_aquired& license_aquired)
{
	json::object ret;

	ret.emplace(std::string("id"), json::string(license_aquired.id_));

	return ret;
}


json::value to_json(const product<concurrent_user_license>& concurrent_user_license)
{
	json::object ret;

	ret.emplace(std::string("id"), json::string(concurrent_user_license.id_));
	ret.emplace(std::string("description"), json::string(concurrent_user_license.description_));
	// product_json.emplace(std::string("id"), json::string(product.second.model_));

	return ret;
}

json::value to_json(const product<named_server_license>& name_server_license)
{
	json::object ret;

	ret.emplace(std::string("id"), json::string(name_server_license.id_));
	ret.emplace(std::string("description"), json::string(name_server_license.description_));
	// product_json.emplace(std::string("id"), json::string(product.second.model_));

	return ret;
}

json::value to_json(const product<named_user_license>& name_user_license)
{
	json::object ret;

	ret.emplace(std::string("id"), json::string(name_user_license.id_));
	ret.emplace(std::string("description"), json::string(name_user_license.description_));
	// product_json.emplace(std::string("id"), json::string(product.second.model_));

	return ret;
}

json::value to_json(const named_user_licenses& name_user_licenses)
{
	json::array ret;

	for (const auto& name_user_license : name_user_licenses)
	{
		ret.emplace_back(to_json(name_user_license.second));
	}

	return ret;
}

json::value to_json(const named_server_licenses& name_server_licenses)
{
	json::array ret;

	for (const auto& name_server_license : name_server_licenses)
	{
		ret.emplace_back(to_json(name_server_license.second));
	}

	return ret;
}

json::value to_json(const concurrent_user_licenses& concurrent_user_licenses)
{
	json::array ret;

	for (const auto& concurrent_user_license : concurrent_user_licenses)
	{
		ret.emplace_back(to_json(concurrent_user_license.second));
	}

	return ret;
}

json::value to_json(const instance& instance)
{
	json::object ret;

	ret.emplace(std::string("id"), json::string(instance.id_));
	ret.emplace(std::string("name"), json::string(instance.name_));
	ret.emplace(std::string("key"), json::string(instance.license_key_));
	ret.emplace(std::string("bind-to"), json::string(instance.license_hash_));

	json::array products_json;

	for (auto&& product : instance.named_user_licenses_)
	{
		products_json.emplace_back(to_json(product.second).as_object());
	}

	ret.emplace(std::string("named-user-licenses"), products_json);

	for (auto&& product : instance.named_server_licenses_)
	{
		products_json.emplace_back(to_json(product.second).as_object());
	}

	ret.emplace(std::string("named-server-licenses"), products_json);

	for (auto&& product : instance.concurrent_user_licenses_)
	{
		products_json.emplace_back(to_json(product.second).as_object());
	}

	ret.emplace(std::string("concurrent-user-licenses"), products_json);

	return ret;
}

json::value to_json(const instances& instances)
{
	json::array ret;

	for (const auto& instance : instances)
	{
		ret.emplace_back(to_json(instance.second).as_object());
	}

	return ret;
}

template<class S>
class license_manager
{
public:
private:
	class api_server : public S
	{
	public:
		api_server(license_manager& license_manager, http::configuration& configuration)
			: S(configuration)
			, license_manager_(license_manager)
		{
            S::router_.use("/static/");
            S::router_.use("/images/");
            S::router_.use("/styles/");
            S::router_.use("/index.html");
            S::router_.use("/");
            S::router_.use("/files/");
			// License instance configuration routes..

			S::router_.on_get(
				"/licenses/configuration", [this](http::session_handler& session, const http::api::params& params) {

				std::string instance_id = session.request().get("instance");

				if (instance_id.empty())
				{				
					instance_id = "main";
				}

				auto instance = license_manager_.get_instances().at(instance_id);

				json::object return_json;

				return_json.emplace(std::string("id"), json::string(instance.id_));
				return_json.emplace(std::string("name"), json::string(instance.name_));
				return_json.emplace(std::string("key"), json::string(instance.license_key_));
				return_json.emplace(std::string("bind-to"), json::string(instance.license_hash_));

				session.response().body() = json::serializer::serialize(return_json).str();
				session.response().type("json");
				
			});

			S::router_.on_get(
				"/licenses/:product-id/acquisition/:license-id",
				[this](http::session_handler& session, const http::api::params& params) {
					// refresh --> put
					std::string instance_id = session.request().get("instance");
					std::string license_id = session.request().get("license-id");

					if (instance_id.empty())
					{				
						instance_id = "main";
					}

					const std::string& product_id = params.get("product-id");

					auto instance = license_manager_.get_instances().at(instance_id);

					auto return_json = instance.about_license(license_id);

					session.response().body() = json::serializer::serialize(return_json).str();
					session.response().type("json");
					
			});

			S::router_.on_put(
				"/licenses/:product-id/acquisition",
				[this](http::session_handler& session, const http::api::params& params) {
				
					// 0 - Validate
					std::string instance_id = session.request().get("instance");
					const std::string& product_id = params.get("product-id");

					if (instance_id.empty())
					{				
						instance_id = "main";
					}

					auto instance = license_manager_.get_instances().at(instance_id);

					// 1 - Process
					auto request_json = json::parser::parse(session.request().body());

					// 2 - Return result
					auto return_json = instance.request_license(request_json.get_object(), session.request().get("Remote_Addr"));

					session.response().body() = json::serializer::serialize(return_json).str();
					session.response().type("json");
					
			});

			S::router_.on_post(
				"/licenses/:product-id/acquisition/:license-id",
				[this](http::session_handler& session, const http::api::params& params) {
					// request --> put					
					std::string instance_id = session.request().get("instance");

					if (instance_id.empty())
					{				
						instance_id = "main";
					}

					const std::string& product_id = params.get("product-id");

					auto instance = license_manager_.get_instances().at(instance_id);

					auto request_json = json::parser::parse(session.request().body());

					auto return_json = instance.request_license(request_json.get_object(), session.request().get("Remote_Addr"));

					session.response().body() = json::serializer::serialize(return_json).str();
					session.response().type("json");
					
			});


			S::router_.on_delete(
				"/licenses/:product-id/acquisition/:license-id",
				[this](http::session_handler& session, const http::api::params& params) {
					
					std::string instance_id = session.request().get("instance");

					if (instance_id.empty())
					{				
						instance_id = "main";
					}

					const std::string& product_id = params.get("product-id");

					auto instance = license_manager_.get_instances().at(instance_id);

					auto request_json = json::parser::parse(session.request().body());

					auto return_json = instance.release_license(request_json.get_object(), session.request().get("Remote_Addr"));

					session.response().body() = json::serializer::serialize(return_json).str();
					session.response().type("json");
					
			});


            S::router_.on_get("/status", [this](http::session_handler& session, const http::api::params& params) {
                S::server_info_.server_information(S::configuration_.to_string());
                S::server_info_.router_information(S::router_.to_string());
                session.response().body() = S::server_info_.to_string();
                session.response().type("text");
			});
		}


	private:
		friend class license_manager;
		license_manager& license_manager_;
	};


public:
public:
	license_manager(std::string home_dir)
		: configuration_{ { "server", "neolm/8.0.01" },
						  { "listen_port_begin", "3000" },
						  { "listen_port_end", "3010" },
						  { "keepalive_count", "1024" },
						  { "keepalive_timeout", "2" },
						  { "thread_count", "8" },
						  { "doc_root", "/Projects/doc_root" },
						  { "ssl_certificate", "/Projects/ssl/ssl.crt" },
						  { "ssl_certificate_key", "/Projects/ssl/ssl.key" } }
		, api_server_(*this, configuration_)
		, home_dir_(home_dir)
	{
		json::value instance_definitions = json::parser::parse(std::ifstream(home_dir_ + "instances.json"));

		for (auto& instance_definition : instance_definitions.get_array())
		{
			std::string instance_id = instance_definition["instance"].as_string();

			std::string license_file = home_dir_ + instance_id + "/license.json";
			std::string allocation_file = home_dir_ + instance_id + "/allocation.json";

			json::value instance_license = json::parser::parse(std::ifstream(license_file));
			json::value instance_allocation = json::parser::parse(std::ifstream(allocation_file));

			this->instances_.emplace(instance_id, instance(instance_license, instance_allocation));
		}
	}

	~license_manager() {}

	void start_server()
	{
		this->api_server_.start_server();
	}

	const instances& get_instances() { return instances_; }

private:
	http::configuration configuration_;
	api_server api_server_;
	std::string home_dir_;
	instances instances_;
};

} // namespace neolm

void test_req_p_sec_simple(std::int16_t port)
{
	auto start = std::chrono::system_clock::now();

	int test_connections = 100;
	int test_requests = 1000;

	std::string readbuffer;

	readbuffer.resize(1 * 1024);

	for (int j = 0; j < test_connections; j++)
	{
		std::string url = "::1";
		network::tcp::v6 s(url, port);
		network::error_code ec;
		s.connect(ec);

		// auto start_requests = std::chrono::system_clock::now();

		for (int i = 0; i < test_requests; i++)
		{

			http::request_message req("GET", "/null");

			network::write(s.socket(), http::to_string(req));

			int ret = -1;
			do
			{
				ret = network::read(s.socket(), network::buffer(&readbuffer[0], readbuffer.size()));
			} while(readbuffer.find("\r\n\r\n") == std::string::npos);
		}
		// auto end_requests = std::chrono::system_clock::now();
		// std::chrono::duration<double> diff = end_requests - start_requests;

		// std::cout << j << ":" << test_requests / diff.count() << " req/sec\n";
	}

	auto end = std::chrono::system_clock::now();
	std::chrono::duration<double> diff = end - start;

	std::cout << "" << (test_connections * test_requests) << " requests took: " << diff.count() << " (port:" << std::to_string(port) <<")\n";

}

void test_post_get(size_t size, size_t nr_routes, std::int16_t port)
{

	int test_connections = 10;
	int test_requests = 1000;
	int key_index = 0;

	std::string test_body;
	static int index = 0;

	test_body.resize(size * 1024, 'A' + index++);

	auto start = std::chrono::system_clock::now();

	for (int j = 0; j < test_connections; j++)
	{
		std::string url = "::1";
		network::tcp::v6 s(url, port);
		network::error_code ec;
		s.connect(ec);

		auto start_requests = std::chrono::system_clock::now();

		//std::vector<char> readbuffer;

		std::string readbuffer;

		readbuffer.resize(size * 1024);

		for (int i = 0; i < test_requests; i++)
		{
			std::string test_resource
				= "/key-value-store/test_" + std::to_string(key_index) + "/key_" + std::to_string(key_index);

			// std::cout << test_resource << "\n";

			http::request_message req("PUT", test_resource);

			req.set("Host", std::string("localhost:[8999]"));

			req.body() = test_body;
			req.content_length(req.body().length());

			network::write(s.socket(), http::to_string(req));

			int ret = -1;
			do
			{
				ret = network::read(s.socket(), network::buffer(&readbuffer[0], readbuffer.size()));
			} while(readbuffer.find("\r\n\r\n") == std::string::npos);

			bool ok = readbuffer.find("201") != std::string::npos;

			if (!ok)
				std::cout << "!ok" << readbuffer.c_str() << "\n";

			key_index++;

			if (nr_routes < key_index) key_index = 0;
		}
		auto end_requests = std::chrono::system_clock::now();
		std::chrono::duration<double> diff = end_requests - start_requests;
        network::shutdown(s.socket(), network::shutdown_send);
		//std::cout << j << ":" << test_requests / diff.count() << " req/sec\n";
	}

	auto end = std::chrono::system_clock::now();
	std::chrono::duration<double> diff = end - start;

	std::cout << "" << (test_connections * test_requests) << " " << std::to_string(size)
			  << "K requests took: " << diff.count() << " (port:" << std::to_string(port) <<")\n";
}

void load_test()
{
	size_t size = 4;

	std::vector<std::thread> clients;

		clients.reserve(32);
		
/*		for (int i=0; i!=8; i++)
		{
			clients.push_back(std::move(std::thread([size](){ test_post_get(size, 1000, 8999); })));
			clients.back().detach();
		}*/

		for (int i=0; i!=4; i++)
		{
			clients.push_back(std::move(std::thread([size](){ test_post_get(size, 1000, 3000); })));
			clients.back().detach();
		}

		/*for (int i=0; i!=4; i++)
		{
			clients.push_back(std::move(std::thread([size](){ test_req_p_sec_simple(80); })));
			clients.back().detach();
		}*/


		size = size;
		if (size > 32)
			size = 4;
}

int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

	neolm::license_manager<http::basic::threaded::server> license_server{ "/projects/neolm_licenses/" };

    //neolm::license_manager<http::basic::async::server> license_server{ "/projects/neolm_licenses/" };

	license_server.start_server();

//	license_server.add_test_routes();

	network::init();
	while (1)
	{
		//load_test();
        std::this_thread::sleep_for(10s);
	}
}

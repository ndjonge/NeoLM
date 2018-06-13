#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <array>

#include "http_basic.h"
//#include "http_advanced_server.h"
#include "json.h"

using namespace std::literals;

namespace neolm
{

class api_server : public http::basic::threaded::server
{
public:
	api_server(http::configuration& configuration)
		: http::basic::threaded::server(configuration)
	{
		router_.use("/static/");
		router_.use("/images/");
		router_.use("/styles/");
		router_.use("/index.html");
		router_.use("/");

		// License instance configuration routes..
		router_.on_get("/license/:instance", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_post("/license/:instance", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_put("/license/:instance", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_delete("/license/:instance", [this](http::session_handler& session, const http::api::params& params) {
		});

		// License model routes...
		router_.on_get("/license/:instance/model/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_post("/license/:instance/model/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_put("/license/:instance/model/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_delete("/license/:instance/model/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});


		// Allocation routes...
		router_.on_get("/license/:instance/allocation/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_post("/license/:instance/allocation/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_put("/license/:instance/allocation/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_delete("/license/:instance/allocation/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});


		// Acquired routes...
		router_.on_get("/license/:instance/acquired/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_post("/license/:instance/acquired/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_put("/license/:instance/acquired/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});

		router_.on_delete("/license/:instance/acquired/named-user/:product-id/:user-name", [this](http::session_handler& session, const http::api::params& params) {
		});


		router_.on_get("/status", [this](http::session_handler& session, const http::api::params& params) { 

			server_info_.server_information(configuration_.to_string());
			server_info_.router_information(router_.to_string());
			session.response().body() = server_info_.to_string(); 
		});
	}

private:

};

class license_manager
{
class instance;
template<class M> class product;

class user;
class server;
class named_user_license;
class concurrent_user_license;
class named_server_license;

using instances = std::unordered_map<std::string, license_manager::instance>;
using concurrent_user_licenses = std::unordered_map<std::string, license_manager::product<license_manager::concurrent_user_license>>;
using named_user_licenses = std::unordered_map<std::string, license_manager::product<license_manager::named_user_license>>;
using named_server_licenses = std::unordered_map<std::string, license_manager::product<license_manager::named_server_license>>;

using users = std::unordered_map<std::string, license_manager::user>;
using servers = std::unordered_map<std::string, license_manager::server>;

private:

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
				named_user_licenses_.emplace(json::get<std::string>(named_user_license_definition["id"]), product<named_user_license>(
					json::get<std::string>(named_user_license_definition["id"]),
					json::get<std::string>(named_user_license_definition["description"])
				));
			}

			for (auto& named_server_license_definition : named_server_license_definitions)
			{
				named_server_licenses_.emplace(json::get<std::string>(named_server_license_definition["id"]), product<named_server_license>(
					json::get<std::string>(named_server_license_definition["id"]),
					json::get<std::string>(named_server_license_definition["description"])
				));
			}

			for (auto& concurrent_user_license_definition : concurrent_user_license_definitions)
			{
				concurrent_user_licenses_.emplace(json::get<std::string>(concurrent_user_license_definition["id"]), product<concurrent_user_license>(
					json::get<std::string>(concurrent_user_license_definition["id"]),
					json::get<std::string>(concurrent_user_license_definition["description"])
				));
			}

			auto users = instance_allocation["users"].as_array();
			auto servers = instance_allocation["servers"].as_array();

			for (auto& user : users)
			{
				users_.emplace(json::get<std::string>(user["name"]), json::get<std::string>(user["name"]));
			}

			for (auto& server : servers)
			{
				servers_.emplace(json::get<std::string>(server["name"]), license_manager::server(json::get<std::string>(server["name"]), json::get<std::string>(server["name"])));
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
	};

	template<class M>
	class product
	{
	public:
		product(std::string id, std::string description) : id_(id), description_(description){};

		std::string id_;
		std::string description_;
	
		M model_;
	};

	class user
	{
	public:
		user(std::string name): name_(name) {};

		std::string name_;
	};

	class server
	{
	public:
		server(std::string id, std::string hostname) : id_(id), hostname_(hostname){};

		std::string id_;
		std::string hostname_;
	};

	class named_user_license
	{
	public:
		named_user_license() = default;
	};
	
	class named_server_license
	{
	public:
		named_server_license() = default;
	};

	class concurrent_user_license
	{
	public:
		concurrent_user_license() = default;
	};
	



public:
	license_manager(std::string license_file, std::string allocation_file) :
		configuration_{
			{ "server", "neolm-8.0.01" }, 
			{ "listen_port_begin", "3000" }, 
			{ "listen_port_end", "3010"}, 
			{ "keepalive_count", "30" }, 
			{ "keepalive_timeout", "5" }, 
			{ "thread_count", "10" }, 
			{ "doc_root", "C:/Projects/doc_root" }, 
			{ "ssl_certificate", "C:/ssl/ssl.crt" }, 
			{ "ssl_certificate_key", "C:/ssl/ssl.key" }},
		api_server_(configuration_),
		license_file_(license_file)
	{


		json::value instance_license = json::parser::parse(std::ifstream(license_file));
		json::value instance_allocation = json::parser::parse(std::ifstream(allocation_file));

		this->instances_.emplace("customer_001", instance(instance_license, instance_allocation));

		api_server_.start_server();	
	}

	~license_manager() {}

private:
	http::configuration configuration_;
	api_server api_server_;
	std::string license_file_;
	instances instances_;
};

}

int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

	neolm::license_manager license_server{"C:/Projects/license.json", "C:/Projects/allocation.json"};


	while (1)
	{
		std::this_thread::sleep_for(60s);
	}
}

/*
int main(int argc, char* argv[])
{
	//test_json();
	neolm::test_basic_server();

	http::request_message request;
	http::api::router<> neolm_router("C:/Development Libraries/doc_root");
	std::map<std::int64_t, std::string> products;

	neolm_router.use("/static/");
	neolm_router.use("/images/");
	neolm_router.use("/styles/");
	neolm_router.use("/");

	neolm_router.use("/", [&products](http::session_handler& session, const http::api::params& params)
	{
		std::stringstream s;
		s
			<< "\"" << session.request()["Remote_Addr"] << "\""
			<< " - \""
			<< session.request().method()
			<< " "
			<< session.request().target()
			<< " "
			<< session.request().version()
			<< "\" - \""
			<< session.request()["User-Agent"]
			<< "\"\n";

		std::cout << s.str();


		return true;
	});


	neolm_router.on_get("/products", [&products](http::session_handler& session, const http::api::params& params)
	{
		json::value result{json::array{}};

		for (auto p : products)
		{
			result.get_array().push_back(json::object{std::pair<json::string, json::number_signed_integer>{json::string(p.second), json::number_signed_integer(p.first)}});
		}

		session.response().body() = json::serializer::serialize(result, 1).str();

		printf("get call for product>\n%s\n", session.response().body().c_str());

		session.response().stock_reply(http::status::ok, "application/json");

		return true;
	});

	neolm_router.on_get("/echo", [](http::session_handler& session, const http::api::params& params)
	{
		std::stringstream s;
		s << "request:\n";
		s << "--------\n";
		s << http::to_string(session.request());


		session.response().body() = s.str();
		session.response().stock_reply(http::status::ok, "application/text");


		return true;
	});

	neolm_router.on_post("/products", [&products](http::session_handler& session, const http::api::params& params)
	{
		json::value new_product = json::parser::parse(session.request().body());

		auto u = json::get<std::int64_t>(new_product.get_object()["id"]);
		auto t = json::get<std::string>(new_product.get_object()["name"]);

		auto o = json::get<json::object>(new_product);

		printf("post call for product> %ld %s\n", (long)u, t.c_str());

		products.insert(std::pair<std::int64_t,std::string>(u, t));

		session.response().stock_reply(http::status::ok, "application/json");

		return true;
	});


	http::configuration configuration{
		{"server", "http 0.0.1"},
		{"keepalive_count", "7"},
		{"keepalive_timeout", "9"},
		{"thread_count", "10"},
		{"doc_root", "C:/Development Libraries/doc_root"},
		{"ssl_certificate", "C:/Development Libraries/ssl.crt"},
		{"ssl_certificate_key", "C:/Development Libraries/ssl.key"}
	};

	http::server<http::api::router<>, http::connection_handler_http, http::connection_handler_https> server{
		neolm_router, configuration};

	server.start_server();

	return 0;
}

*/
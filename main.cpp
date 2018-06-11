#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <array>

#include "http_basic.h"
//#include "http_advanced_server.h"
//#include "json.h"

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
		instance(std::string id, std::string name, std::string key, std::string domains) : id_(id), name_(name), license_key_(key), license_hash_(){};

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

	class product
	{
	public:
		product(std::string id, std::string description, std::string key, std::string domains) : id_(id), description_(description){};

		std::string id_;
		std::string description_;
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

public:
	license_manager() :
		configuration_{
			{ "server", "neolm-8.0.01" }, 
			{ "listen_port_begin", "3000" }, 
			{"listen_port_end", "3010"}, 
			{"keepalive_count", "30" }, 
			{ "keepalive_timeout", "5" }, 
			{ "thread_count", "10" }, 
			{ "doc_root", "C:/Projects/doc_root" }, 
			{ "ssl_certificate", "C:/ssl/ssl.crt" }, 
			{ "ssl_certificate_key", "C:/ssl/ssl.key" }},
		api_server_(configuration_) 
	{
			api_server_.start_server();	
	}

	~license_manager() {}

private:
	http::configuration configuration_;
	api_server api_server_;	
};

}

int main(int argc, char* argv[])
{
	network::init();
	network::ssl::init();

	neolm::license_manager test_server;

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
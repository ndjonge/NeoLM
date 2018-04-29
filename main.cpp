
#include <chrono>
#include <ctime>
#include <iostream>

#include "http_advanced_server.h"
#include "json.h"


namespace neolm
{

class neolm_api_server : public http::basic::server
{
public:
	neolm_api_server() : http::basic::server{{"server", "neo_lm 0.0.01"}, {"timeout", "15"}, {"doc_root", "/var/www"}}
	{
		router_.on_get("/", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "index!";
			return true;
		});

		/*
		router_.on_get("/about", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "NeoLM 1.0";
			return true;
		});

		router_.on_get("/info", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "Just some info!";
			return true;
		});

		router_.on_get("/about/company", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "small software company inc.";
			return true;
		});*/

		router_.on_get("/named-users-licenes/:product/:name", [](http::session_handler& session, const http::api::params& params) {

			session.response().body() = "product: ";

			session.response().body() += params.get("product");

			session.response().body() += session.request().query()["query1"];

			return true;
		});

/*		router_.on_get("/concurrent-users-licenes/:product/inuse", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "NEOLM - 1.1.01";
			return true;
		});*/

	}

	neolm_api_server(const neolm_api_server& ) = default;
private:

};

void test_basic_server()
{
	auto buffer_in = "GET /named-users-licenes/99999/ndejonge#query1=1&query2=2 HTTP/1.1\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";

	auto neolm_server = neolm::neolm_api_server();

	auto session = neolm_server.open_session();

	session->store_request_data(buffer_in, std::strlen(buffer_in));

	if (neolm_server.parse_session_data(session) == http::request_parser::good)
	{
		auto response = neolm_server.handle_session(session);		

		std::string data = http::to_string(response);

		printf("%s\n", data.c_str());
	}

	neolm_server.close_session(session);
}


}; // namespace neolm


int main(int argc, char* argv[])
{
	test_json();

	http::request_message request;

	http::api::router<> neolm_router("C:/Development Libraries/doc_root");

	neolm_router.use("index.html");
	neolm_router.use("static");
	neolm_router.use("images");
	neolm_router.use("styles");


	neolm_router.on_get("/users/:id(\\d+)", [](http::session_handler& session, const http::api::params& params)
	{		
		session.response().body() = "User:" + std::string(params.get("id"));

		return true;
	});

	neolm_router.on_get("/users", [](http::session_handler& session, const http::api::params& params)
	{
		session.response().body() = "User:";

		return true;
	});

	neolm_router.on_get("/", [](http::session_handler& session, const http::api::params& params)
	{
		session.response().body() = "/";

		return true;
	});

	
	http::server<http::api::router<>, http::connection_handler_http, http::connection_handler_https> server(
		neolm_router,		
		"C:\\Development Libraries\\ssl.crt", 
		"C:\\Development Libraries\\ssl.key");

	server.start_server();

	return 0;
}


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
	neolm_api_server(http::configuration configuration) : http::basic::server{configuration}
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

	http::configuration configuration{
		{"server", "http 0.0.1"}, 
		{"keepalive_count", "7"}, 
		{"keepalive_timeout", "9"}, 
		{"thread_count", "10"},
		{"doc_root", "C:/Development Libraries/doc_root"}, 
		{"ssl_certificate", "C:/Development Libraries/ssl.crt"}, 
		{"ssl_certificate_key", "C:/Development Libraries/ssl.key"}
	};

	auto neolm_server = neolm::neolm_api_server(configuration);

	auto session = neolm_server.open_session();

	session->store_request_data(buffer_in, std::strlen(buffer_in));

	if (neolm_server.parse_session_data(session) == http::request_parser::good)
	{
		auto& response = neolm_server.handle_session(session);		

		std::string data = http::to_string(response);
		printf("%s\n", data.c_str());
	}

	neolm_server.close_session(session);
}

}; // namespace neolm


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

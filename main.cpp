#include "http_basic_server.h"
#include "http.h"

namespace neolm
{

class neolm_api_server : public http::basic::server
{
public:
	neolm_api_server() : http::basic::server{{"server", "neo_lm 0.0.01"}, {"timeout", "15"}, {"doc_root", "/var/www"}}
	{
		router.on_get("/healthcheck", [](http::session_handler& session, const http::api::params& params) {
			if (1)
				session.response().body() = "HealthCheck: OK";
			else
				session.response().body() = "HealthCheck: FAILED";

			return true;
		});

		router.on_get("/info", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "NEOLM - 1.1.01";
			return true;
		});

		router.on_get("/.*", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "Index!";
			return true;
		});
	}
private:

};

}; // namespace neolm


int main(int argc, char* argv[])
{
	const char buffer_in[] = "GET /afile HTTP/1.1\r\nAccept: */*\r\n\r\n";

	neolm::neolm_api_server neolm_server;

	auto session = neolm_server.open_session();

	session->store_data(buffer_in, sizeof(buffer_in));

	auto result = neolm_server.parse_session_data(session);

	if (result == http::request_parser::good)
	{
		auto response = neolm_server.handle_session(session);		

		printf("%s\n", response.headers_to_string().c_str());
		printf("%s\n", response.body().c_str());

	}

	neolm_server.close_session(session);
}



	/*http::request_message request;

	http::api::router<> neolm_router("C:/Development Libraries/doc_root");

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

	
	http::server<http::api::router<>, http::connection_handler_http, http::connection_handler_https> server(
		neolm_router,		
		"C:\\Development Libraries\\ssl.crt", 
		"C:\\Development Libraries\\ssl.key");

	server.start_server();

	return 0;
}

int main(void)
{
	const char addRequest[] = "{\"jsonrpc\":\"2.0\",\"method\":\"add\",\"id\":0,\"params\":[3,2]}";
	const char concatRequest[] = "{\"jsonrpc\":\"2.0\",\"method\":\"concat\",\"id\":1,\"params\":[\"Hello, \",\"World!\"]}";
	const char addArrayRequest[] = "{\"jsonrpc\":\"2.0\",\"method\":\"add_array\",\"id\":2,\"params\":[[1000,2147483647]]}";
	const char toStructRequest[] = "{\"jsonrpc\":\"2.0\",\"method\":\"to_struct\",\"id\":5,\"params\":[[12,\"foobar\",[12,\"foobar\"]]]}";
	const char printNotificationRequest[] = "{\"jsonrpc\":\"2.0\",\"method\":\"print_notification\",\"params\":[\"This is just a notification, no response expected!\"]}";


	namespace x3 = boost::spirit::x3;

	std::string storage = addRequest;

	std::string::const_iterator iter = storage.begin();
	std::string::const_iterator iter_end = storage.end();

	json::value o;

	auto p = parse(storage.begin(), storage.end(), json::parser::json, o);

	std::stringstream s;
	boost::apply_visitor(json::writer(s), o);

	json::rpc::request::call_table_t table;

	json::rpc::request call(table, o);


	auto s2 = s.str();
	std::cout << s2 << std::endl;

	json::value o2;
	p = parse(s2.begin(), s2.end(), json::parser::json, o2);

	return 0;
}
*/

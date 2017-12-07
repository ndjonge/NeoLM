#include "http.h"
#include "server.h"
#include "json.h"

#include "http_c_wrapper.h"

namespace neolm
{

class neolm_api_server : public http_c::http_api_server
{
public:
	neolm_api_server()
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
	}
private:

};

}; // namespace neolm


int main(int argc, char* argv[])
{
	const char buffer_in[] = "GET /index.html HTTP/1.1\r\nAccept: */*\r\n\r\n";
	char buffer_out[1024];

	http_server_ptr server_ptr = http_server_create();

	http_session_ptr session_ptr = http_open_session(server_ptr);

	http_feed_session_data(session_ptr, buffer_in, sizeof(buffer_in));

	auto result = http_parse_session(server_ptr, session_ptr);

	if (result == 0)
	{
		http_handle_session(server_ptr, session_ptr);
	}
	else if (result == 2)
	{
		http_feed_session_data(session_ptr, buffer_in, sizeof(buffer_in));
	}
	else
	{
		// bad
	}

	http_close_session(server_ptr, session_ptr);

	http_server_destroy(server_ptr);
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
}*/

/*


namespace application
{
	namespace routers
	{
		namespace json_rpc
		{
			class router
			{
			public:
				router() = default;
			private:
				std::map<const char*, std::function<bool(json::array_t& args)> > dispTable;
			};
		}
	}
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

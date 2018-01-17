
#include <chrono>
#include <ctime>
#include <iostream>

#include "http_basic.h"
#include "picosha2.h"

namespace neolm
{

class block
{
public:
	block(const long int ts, const std::string& data, const std::string& prev_hash)
		: _ts(ts)
		, _data(data)
		, _prev_hash(prev_hash)
	{
	}

	std::string hash(void) const
	{
		std::stringstream ss;

		ss << _ts << _data << _prev_hash;

		std::string src = ss.str();
		std::vector<unsigned char> hash(32);
		picosha2::hash256(src.begin(), src.end(), hash.begin(), hash.end());

		return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
	}

	static block create_seed(void)
	{
		auto temp_ts = std::chrono::system_clock::now().time_since_epoch();

		return block(temp_ts.count(), "Seed block", "");
	}

	static block create_next(const block& b, const std::string& data)
	{
		auto temp_ts = std::chrono::system_clock::now().time_since_epoch();

		return block(temp_ts.count(), data, b.hash());
	}

public:
	const long ts() const { return _ts; }
	const std::string& data() const { return _data; }
	const std::string& prev_hash() const { return _prev_hash; }

private:
	long _ts;
	std::string _data;
	std::string _prev_hash;
};

void print_chain(std::vector<block> chain)
{

	int i = 0;

	for (block& b : chain)
	{

		std::cout << "index: " << i << std::endl << "ts: " << b.ts() << std::endl << "data: " << b.data() << std::endl << "this: " << b.hash() << std::endl << "prev: " << b.prev_hash() << std::endl << "-------------------------------------" << std::endl;

		i++;
	}
}

std::string make_data()
{

	std::stringstream ss;

	int a = std::rand();
	int b = std::rand();
	int c = std::rand();

	ss << "{ \"a\": " << a << ","
	   << "\"b\": " << b << ","
	   << "\"c\": " << c << " }";

	return ss.str();
}

class neolm_api_server : public http::basic::server
{
public:
	neolm_api_server() : http::basic::server{{"server", "neo_lm 0.0.01"}, {"timeout", "15"}, {"doc_root", "/var/www"}}
	{
		router_.on_get("/healthcheck", [](http::session_handler& session, const http::api::params& params) {
			if (1)
				session.response().body() = "HealthCheck: OK";
			else
				session.response().body() = "HealthCheck: FAILED";

			return true;
		});

		router_.on_get("/info", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "NEOLM - 1.1.01";
			return true;
		});

		router_.on_get("/.*", [](http::session_handler& session, const http::api::params& params) {
			session.response().body() = "Index!";
			return true;
		});
	}

	neolm_api_server(const neolm_api_server& ) = default;
private:

};

}; // namespace neolm


int main(int argc, char* argv[])
{
	auto buffer_in = "GET /healthcheck HTTP/1.1\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";

	auto neolm_server = neolm::neolm_api_server();

	auto session = neolm_server.open_session();

	session->store_request_data(buffer_in, std::strlen(buffer_in));

	if (neolm_server.parse_session_data(session) == http::request_parser::good)
	{
		auto response = neolm_server.handle_session(session);		

		std::string data = http::to_string(response);

		printf("%s\n", data.c_str());
	}

	neolm_server.reset_session(session);
	session->store_request_data(buffer_in, std::strlen(buffer_in));

	if (neolm_server.parse_session_data(session) == http::request_parser::good)
	{
		auto response = neolm_server.handle_session(session);		

		std::string data = http::to_string(response);

		printf("%s\n", data.c_str());
	}

	neolm_server.close_session(session);

	std::string src_str = "Neolm record 1";

	std::vector<unsigned char> hash(32);
	
	picosha2::hash256(src_str.begin(), src_str.end(), hash.begin(), hash.end());

	std::string hex_str = picosha2::bytes_to_hex_string(hash.begin(), hash.end());

	printf("%s\n", hex_str.c_str());

	std::vector<neolm::block> chain = { neolm::block::create_seed() };

	for (int i = 0; i < 5; i++)
	{
		// get the last block in the chain
		auto last = chain[chain.size() - 1];

		// create the next block
		chain.push_back(neolm::block::create_next(last, neolm::make_data()));
	}

	print_chain(chain);
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

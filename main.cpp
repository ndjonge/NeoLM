#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <unordered_map>

#if defined(WIN32)
#include <Ws2tcpip.h>
#include <winsock2.h>
#endif

#include "http_advanced_server.h"
#include "json.h"

using namespace std::literals;

namespace dshell
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

		router_.use("/api", [this](http::session_handler& session, const http::api::params& params) {
			// std::promise<bool> is_dshell_ready;

			/*DsThttpEvent httpEvent;
			httpEvent.type = DsNhttpEvent;
			httpEvent.process = 2;
			httpEvent.userContext = 0;

			std::pair<http::session_handler*, std::promise<bool>*> session_promise = std::make_pair(&session, &is_bshell_ready);

			httpEvent.session = static_cast<bs4>(sgm::make_wrapped_sgm_ptr<std::pair<http::session_handler*, std::promise<bool>*>>(session_promise).asHandle());


			{
				std::lock_guard<std::mutex> guard(event_mutex);
				event_queue.push(httpEvent);
				al_so_release( sync_ );
			}


			auto x = is_dshell_ready.get_future().get();*/

			session.response().body() = "HI\n";
			session.response().type("text");
			session.response().result(http::status::ok);
		});

		router_.on_get("/status", [this](http::session_handler& session, const http::api::params& params) { session.response().body() = server_info_.to_string(); });

		router_.on_post("/token", [this](http::session_handler& session, const http::api::params& params) {
			std::string code = session.request().query().get<std::string>("code");

			if (code.empty())
			{
				session.response().result(http::status::bad_request);
			}
			else
			{
				std::string token = std::to_string(std::hash<std::string>{}(code));
				tokens_.emplace(token, code);
				session.response().body() = token;
			}
		});

		router_.on_get("/token", [this](http::session_handler& session, const http::api::params& params) {
			std::string token = session.request().query().get<std::string>("token");

			if (token.empty())
			{
				session.response().result(http::status::bad_request);
			}
			else
			{
				auto value = tokens_.find(token);

				if (value != tokens_.end())
				{
					session.response().body() = value->second;
				}
				else
				{
					session.response().result(http::status::bad_request);
				}
			}
		});

		router_.on_post("/key-value-store/:key", [this](http::session_handler& session, const http::api::params& params) {
			auto& key = params.get("key");

			if (key.empty())
			{
				session.response().result(http::status::bad_request);
			}
			else
			{
				auto i = key_value_store.emplace(key, session.request().body());

				if (i.second)
					session.response().result(http::status::created);
				else
					session.response().result(http::status::not_found);
			}
		});

		router_.on_get("/key-value-store/:key", [this](http::session_handler& session, const http::api::params& params) {
			auto& key = params.get("key");

			if (key.empty())
			{
				session.response().result(http::status::not_found);
			}
			else
			{
				auto value = key_value_store.find(key);

				if (value != key_value_store.end())
				{
					session.response().body() = value->second;
				}
				else
				{
					session.response().result(http::status::not_found);
				}
			}
		});
	}

private:
	// al_sync_object* sync_;
	// std::queue<DsThttpEvent> event_queue;
	std::mutex event_mutex;

	std::unordered_map<std::string, std::string> tokens_;
	std::unordered_map<std::string, std::string> key_value_store;
};
}

int main(int argc, char* argv[])
{
	http::configuration configuration{
		{ "server", "http 0.0.1" }, { "keepalive_count", "30" }, { "keepalive_timeout", "5" }, { "thread_count", "10" }, { "doc_root", "C:/Development Libraries/doc_root" }, { "ssl_certificate", "C:/Development Libraries/ssl.crt" }, { "ssl_certificate_key", "C:/Development Libraries/ssl.key" }
	};

	dshell::api_server test_server(configuration);

	test_server.start_server();

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

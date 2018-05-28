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


#include <stdio.h>


#include <openssl/ssl.h>
#include <openssl/err.h>



namespace network
{
using socket_t = SOCKET;

namespace tcp
{

class endpoint
{
public:
	endpoint() = default;
	virtual void open(std::int16_t protocol) = 0;
	std::int16_t  protocol() {return protocol_;}
	virtual sockaddr* addr()=0;
	virtual int addr_size()=0;
	socket_t& socket() {return socket_;};

protected:
	socket_t  socket_;
	std::int16_t protocol_;
};

class v4 : public endpoint
{
public:
	v4(std::int16_t port) : sock_addr_({})
	{
		protocol_ = SOCK_STREAM;
		sock_addr_.sin_family = AF_INET;
		sock_addr_.sin_port = htons(port);
		sock_addr_.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	sockaddr* addr() {return reinterpret_cast<sockaddr*>(&sock_addr_);};
	std::int32_t addr_size() { return static_cast<std::int32_t>(sizeof(this->sock_addr_));}

	void open(std::int16_t protocol)
	{
		socket_ = ::socket(sock_addr_.sin_family, protocol, 0);
	}
private:
	sockaddr_in sock_addr_;
};

class v6 : public endpoint
{
public:
	v6(std::int16_t port) : sock_addr_({})
	{
		sock_addr_.sin6_family = AF_INET6;
		sock_addr_.sin6_port = ::htons(port);
		sock_addr_.sin6_addr = in6addr_any;
		protocol_ = SOCK_STREAM;
	}

	void open(std::int16_t protocol)
	{
		socket_ = ::socket(sock_addr_.sin6_family, protocol, 0);
	}
	
	sockaddr* addr() {return reinterpret_cast<sockaddr*>(&sock_addr_);};
	std::int32_t addr_size() { return static_cast<std::int32_t>(sizeof(this->sock_addr_));}


private:
	sockaddr_in6 sock_addr_;
};

class acceptor
{
public:
		acceptor() = default;

		void open(std::int16_t protocol) { protocol_ = protocol;}

		void bind(endpoint& endpoint) 
		{
			int ret = 0;
			endpoint_ = &endpoint;
			endpoint_->open(protocol_);

			ret = ::bind(endpoint_->socket(), endpoint_->addr(), endpoint_->addr_size());



			//ec.value = ret;
		}

		void listen() 
		{
			::listen(endpoint_->socket(), 1);
		}

		void accept(socket_t& socket) 
		{
			std::int32_t len = static_cast<int>(endpoint_->addr_size());
			socket = ::accept(endpoint_->socket(), endpoint_->addr(), &len);

		}

private:
	std::int16_t protocol_;
	endpoint* endpoint_;
};

}
}

void test_network()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	network::tcp::v6 endpoint_6{3000};
	network::tcp::acceptor acceptor_{};

	acceptor_.open(endpoint_6.protocol());
	acceptor_.bind(endpoint_6);
	acceptor_.listen();

	network::socket_t client_socket=0;

	acceptor_.accept(client_socket);

	network::read();
	network::write();

}


SOCKET create_socket(int port)
{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "/ssl/ssl.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/ssl/ssl.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{

	test_network();

    SOCKET sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4000);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;

        int len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        SOCKET client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, (int)client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            SSL_write(ssl, reply, (int)strlen(reply));
        }

        SSL_free(ssl);
        closesocket(client);
    }

    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}




#include "http_basic.h"
//#include "http_advanced_server.h"
//#include "json.h"

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

int xxmain(int argc, char* argv[])
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

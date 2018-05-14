#include <chrono>
#include <ctime>
#include <iostream>
#include <mutex>
#include <future>
#include <unordered_map>

#include <Ws2tcpip.h>
#include <winsock2.h>

#include "http_advanced_server.h"
#include "json.h"

using namespace std::literals;

namespace http
{

namespace basic_threaded
{

class server : public http::basic::server
{
	using socket_t = SOCKET;
	friend class connection_handler;

public:
	server(http::configuration& configuration)
		: http::basic::server{ configuration }
		, thread_count_(configuration.get<int>("thread_count", 5))
		, listen_port_(configuration.get<int>("listen_port_", 60005))
		, connection_timeout_(configuration.get<int>("keepalive_timeout", 4))
	{
		router_.use("/static/");
		router_.use("/images/");
		router_.use("/styles/");
		router_.use("/");

		router_.use("/", [this](http::session_handler& session, const http::api::params& params) {
			std::stringstream s;

			s << "\"" << session.request()["Remote_Addr"] << "\""
			  << " - \"" << session.request().method() 
			  << " " << session.request().target() << " " 
			  << session.request().version() << "\" - \"" 
			  << session.request()["User-Agent"] << "\"\n";

			access_log_.emplace_back(s.str());
			
			if (access_log_.size() >= 32)
				access_log_.erase(access_log_.begin());

			return true;
		});

		router_.on_get("/log", [this](http::session_handler& session, const http::api::params& params) {
						
			for (auto& access_log_entry : access_log_)
				session.response().body() += access_log_entry;

			session.response().stock_reply(http::status::ok, "text/plain");
			return true;
		});

		router_.on_post("/token", [this](http::session_handler& session, const http::api::params& params) {
			std::string code = session.request().query().get<std::string>("code");

			if (code.empty())
			{
				session.response().stock_reply(http::status::bad_request);
			}
			else
			{
				std::string token = std::to_string(std::hash<std::string>{}(code));

				tokens_.emplace(token, code);
				session.response().body() = token;
				session.response().stock_reply(http::status::ok);
			}

			return true;
		});


		router_.on_get("/token", [this](http::session_handler& session, const http::api::params& params) {
			std::string token = session.request().query().get<std::string>("token");

			if (token.empty())
			{
				session.response().stock_reply(http::status::bad_request);
			}
			else
			{
				auto value = tokens_.find(token);

				if (value != tokens_.end())
				{ 
					session.response().body() = value->second;
					session.response().stock_reply(http::status::ok);
				}
				else
				{
					session.response().stock_reply(http::status::bad_request);
				}
			}

			return true;
		});
	}

	server(const server&) = default;

	void start_server()
	{
		listener_handler();
		// listener_thread_pool.emplace_back([this](){ listener_handler(); }); // Move assign....
		// listener_thread_pool.back().detach();
	}

	static std::string get_client_info(SOCKET client_socket)
	{
		sockaddr_in6 sa = {0};
		socklen_t sl = sizeof(sa);
		char c[INET6_ADDRSTRLEN];

		getpeername(client_socket, (sockaddr *) &sa,  &sl);
		
		inet_ntop(AF_INET6, &(sa.sin6_addr), c, INET6_ADDRSTRLEN);

		return c;
	}

	void listener_handler()
	{
		try
		{
			SOCKET sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

			sockaddr_in6 serv_addr;
			memset(&serv_addr, 0, sizeof(serv_addr));

			serv_addr.sin6_family = AF_INET6;
			serv_addr.sin6_addr = in6addr_any;
			serv_addr.sin6_port = htons(listen_port_);

			int reuseaddr = 1;
			int ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr, sizeof(reuseaddr));

			int ipv6only = 0;
			ret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only));

			ret = bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

			ret = listen(sockfd, 5);

			while (1)
			{
				sockaddr_in6 cli_addr;
				socklen_t clilen = sizeof(cli_addr);

				SOCKET clientsockfd = accept(sockfd, reinterpret_cast<sockaddr*>(&cli_addr), &clilen);

				std::thread connection_thread([new_connection_handler = std::make_shared<connection_handler>(*this, clientsockfd, connection_timeout_)](){new_connection_handler->proceed();});
				connection_thread.detach();
			}
		}
		catch (...)
		{
			// TODO
		}
	}

	class connection_handler
	{
	public:
		connection_handler(http::basic_threaded::server& server, socket_t client_socket, int connection_timeout)
			: server_(server)
			, client_socket_(client_socket)
			, session_handler_(server.configuration_)
			, connection_timeout_(connection_timeout)
		{
		}

		~connection_handler()
		{
			shutdown(client_socket_, 2);
			closesocket(client_socket_);
		}

		void proceed()
		{
			std::array<char, 4096> buffer;
			http::basic::session_data connection_data;

			DWORD timeout_value = static_cast<DWORD>(connection_timeout_) * 1000;
			::setsockopt(client_socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout_value), sizeof(timeout_value));

			while (true)
			{
				int ret = ::recv(client_socket_, &buffer[0], static_cast<int>(buffer.size()), 0);
				// TODO ret = recv( clientsockfd, buf, sizeof(buf), MSG_WAITALL );
				if (ret == 0)
				{
					break;
				}
				if (ret < 0)
				{
					break;
				}

				store_request_data(&buffer[0], ret);

				http::session_handler::result_type parse_result;

				std::tie(parse_result, std::ignore) = session_handler_.parse_request(std::begin(request_data()), std::end(request_data()));

				if (parse_result == http::request_parser::result_type::good)
				{
					auto& response = session_handler_.response();
					auto& request = session_handler_.request();
					session_handler_.request()["Remote_Addr"] = get_client_info(client_socket_);

					server_.router_mutex.lock();
					session_handler_.handle_request(server_.router_);

					/*std::cout << http::to_string(request);
					std::cout << "\n";
					std::cout << http::to_string(response);
					std::cout << "\n";*/
					server_.router_mutex.unlock();

					if (response.body().empty())
					{
						{
							// tcp.port eq 60005
							std::string headers = response.header_to_string();

							ret = send(client_socket_, &headers[0], static_cast<int>(headers.length()), 0);

							std::array<char, 8192 * 8> file_buffer;
							std::ifstream is(session_handler_.request().target(), std::ios::in | std::ios::binary);

							is.seekg(0, std::ifstream::ios_base::beg);
							is.rdbuf()->pubsetbuf(file_buffer.data(), file_buffer.size());

							std::streamsize bytes_in = is.read(file_buffer.data(), file_buffer.size()).gcount();

							while (bytes_in > 0 && ret != -1)
							{
								ret = send(client_socket_, file_buffer.data(), static_cast<int>(bytes_in), 0);

								bytes_in = is.read(file_buffer.data(), file_buffer.size()).gcount();
							}
						}
					}
					else
					{
						connection_data.store_response_data(http::to_string(response));
						ret = send(client_socket_, &(connection_data.response_data()[0]), static_cast<int>(connection_data.response_data().size()), 0);
					}

					if (response.keep_alive() == true)
					{
						connection_data.reset();
						session_handler_.reset();
					}
					else
					{
						return;
					}
				}
				else
				{
					// TODO send http error
					connection_data.reset();
					session_handler_.reset();
					return;
				}
			}
		}

	private:
		http::basic_threaded::server& server_;
		socket_t client_socket_;
		http::session_handler session_handler_;
		int connection_timeout_;

		std::vector<char> data_request_;
		std::vector<char> data_response_;

		void store_request_data(const char* data, size_t size) { data_request_.insert(std::end(data_request_), &data[0], &data[0] + size); }
		void store_response_data(const std::string& response_string) { data_response_.insert(std::end(data_response_), response_string.begin(), response_string.end()); }

		std::vector<char>& request_data() { return data_request_; }
		std::vector<char>& response_data() { return data_response_; }

		void reset_session()
		{
			session_handler_.reset();
			data_request_.clear();
			data_response_.clear();
		}
	};

private:
	int thread_count_;
	int listen_port_;
	int connection_timeout_;
	std::mutex router_mutex;
	std::vector<std::string> access_log_;

	std::unordered_map<std::string, std::string> tokens_;
};

} // namespace basic_threaded
} // namespace http

int main(int argc, char* argv[])
{
	http::configuration configuration{
		{ "server", "http 0.0.1" }, { "keepalive_count", "5" }, { "keepalive_timeout", "5" }, { "thread_count", "10" }, { "doc_root", "C:/Development Libraries/doc_root" }, { "ssl_certificate", "C:/Development Libraries/ssl.crt" }, { "ssl_certificate_key", "C:/Development Libraries/ssl.key" }
	};

	http::basic_threaded::server test_server(configuration);

	test_server.start_server();

	while (1)
	{
		std::this_thread::sleep_for(1s);
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

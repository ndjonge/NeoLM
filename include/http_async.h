#pragma once

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include <deque>
#include <thread>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include "http_basic.h"

namespace http
{

namespace basic
{

namespace async
{

inline std::size_t get_static_id() noexcept
{
	static std::atomic<std::size_t> id{ 0 };
	return id++;
}

class upstreams
{
public:
	
	template <typename upstream_type>
	class connection
	{
	public:
		enum class state
		{
			waiting,
			idle
		};

		connection(asio::io_context& io_context, const std::string& host, std::string port, upstream_type& owner)
			: host_(host)
			, port_(port)
			, id_(host_ + '_' + port_ + "_" + std::to_string(get_static_id()))
			, resolver_(io_context)
			, socket_(io_context)
			, owner_(owner)
		{
			reopen();
		};

		connection(const connection& s) = delete;
		connection(connection&& s) = delete;

		connection& operator=(const connection& s) = delete;
		connection& operator=(connection&& s) = delete;

		void release() { state_ = state::idle; }

		void reopen()
		{
			asio::error_code error;
			if (socket_.is_open())
			{
				socket_.shutdown(asio::socket_base::shutdown_send, error);
				socket_.close();
			}

			asio::ip::tcp::resolver::query query(asio::ip::tcp::v4(), host_, port_);
			auto resolved_endpoints = resolver_.resolve(query, error);

			asio::connect(socket_, resolved_endpoints.cbegin(), resolved_endpoints.cend(), error);

			if (error)
			{
				std::cout << "not open\n";
			}
		}

		const std::string& id() const { return id_; }

		asio::ip::tcp::socket& socket() { return socket_; }
		std::atomic<state>& get_state() { return state_; }

		std::string host_;
		std::string port_;
		std::string id_;
		std::vector<char> buffer_;
		asio::ip::tcp::resolver resolver_;

		upstream_type& owner() { return owner_; }

	private:
		std::atomic<connection::state> state_{ state::idle };
		asio::ip::tcp::socket socket_;
		upstream_type& owner_;
	};



	void add_upstream(asio::io_context& io_context, const std::string& base_url) 
	{
		upstreams_.emplace_back(new upstream(io_context, base_url));
	}

	void erase_upstream(const std::string& base_url)
	{
		auto upstream_to_remove = std::find_if(
			upstreams_.cbegin(),
			upstreams_.cend(),
			[base_url](const std::unique_ptr<upstream>& rhs) {
				return (rhs->base_url_ == base_url);
			});

		if (upstream_to_remove != upstreams_.cend())
		{
			upstreams_.erase(upstream_to_remove);
		}
	}

	std::string to_string(const std::string& workspace) 
	{
		std::ostringstream ss;

		for (auto& upstream : upstreams_)
		{
			ss << workspace << " : " << upstream->base_url_ << " : " << std::to_string(upstream->connections_.size()) 
				<< ", 1xx: " << std::to_string(upstream->responses_1xx_) 
				<< ", 2xx: " << std::to_string(upstream->responses_2xx_) 
				<< ", 3xx: " << std::to_string(upstream->responses_3xx_)
				<< ", 4xx: " << std::to_string(upstream->responses_4xx_)
				<< ", 5xx: " << std::to_string(upstream->responses_5xx_)
				<< ", tot: " << std::to_string(upstream->responses_tot_)
				<< "\n";
		}
		return ss.str();
	}

	class upstream
	{
	public:
		using containter_type = std::vector<std::unique_ptr<http::basic::async::upstreams::connection<upstream>>>;
		using iterator = containter_type::iterator;

		upstream(asio::io_context& io_context, const std::string& base_url)
			: base_url_(base_url), io_context_(io_context)
		{
			//TODO: make more robust client url parsing.
			auto start_of_port = base_url.find_last_of(':') + 1;
			port_ = base_url.substr(start_of_port);
			host_ = base_url.substr(base_url.find_last_of('/') + 1);
			host_ = host_.substr(0, host_.find_last_of(':'));
		}

		void update_status_code_metrics(std::int32_t status) 
		{ 
			assert(status >= 100);
			assert(status < 600);

			if (status >= 100 && status < 200) responses_1xx_++;
			if (status >= 200 && status < 300) responses_2xx_++;
			if (status >= 300 && status < 400) responses_3xx_++;
			if (status >= 400 && status < 500) responses_4xx_++;
			if (status >= 500 && status < 600) responses_5xx_++;

			responses_tot_++;
		}

		std::atomic<std::uint16_t> responses_1xx_;
		std::atomic<std::uint16_t> responses_2xx_;
		std::atomic<std::uint16_t> responses_3xx_;
		std::atomic<std::uint16_t> responses_4xx_;
		std::atomic<std::uint16_t> responses_5xx_;
		std::atomic<std::uint16_t> responses_tot_;

		const std::string& base_url() const { return base_url_; }
		std::string base_url_;
		std::string host_;
		std::string port_;
		std::mutex sessions_initialise_mutex_;

		void add_connection() 
		{ 
			connections_.emplace_back(new connection<upstream>{io_context_, host_, port_, *this});
		}

		asio::io_context& io_context_;
		containter_type connections_;
		std::lock_guard<std::mutex> g{ sessions_initialise_mutex_ };
	};

	using containter_type = std::vector<std::unique_ptr<upstream>>;
	using iterator = containter_type::iterator;
	using connection_type = http::basic::async::upstreams::connection<upstream>;
	
	containter_type upstreams_;

	void forward(std::function<void(connection_type&)> forward_handler, lgr::logger& logger)
	{
		auto selected_upstream = std::min_element(
			upstreams_.cbegin(), upstreams_.cend(), [](const std::unique_ptr<upstream>& rhs, const std::unique_ptr<upstream>& lhs) {
				return rhs->connections_.size() < lhs->connections_.size();
			  });

		if (selected_upstream != upstreams_.cend())
		{
			bool found = false;
			do
			{
				for (auto& connection : selected_upstream->get()->connections_)
				{
					// Select the least connected upstream
					auto expected_state = http::basic::async::upstreams::connection_type::state::idle;

					if (connection->get_state().compare_exchange_strong(
							expected_state, http::basic::async::upstreams::connection_type::state::waiting)
						== true)
					{
						forward_handler(*connection);
						found = true;
						break;
					}
				}

				if (found == false)
				{
					selected_upstream->get()->add_connection();

					logger.api(
						"reverse proxy: adding new upstream connection to {s}\n", selected_upstream->get()->base_url());

				}
			} while (found == false);
		}
	}

};


class server : public http::basic::server
{
private:
	template <class connection_handler_derived, class socket_t>
	class connection_handler_base : public std::enable_shared_from_this<connection_handler_derived>
	{
	protected:
		asio::io_context& service_;
		asio::io_context::strand write_strand_;
		asio::streambuf in_packet_{8192};
		asio::steady_timer steady_timer_;

		std::deque<std::string> write_buffer_;
		http::session_handler session_handler_;
		server& server_;
		http::api::routing routing_{};

	public:
		connection_handler_base(asio::io_context& service, server& server, http::configuration& configuration)
			: service_(service)
			, write_strand_(service)
			, steady_timer_(service)
			, session_handler_(configuration)
			, server_(server)
		{
			server_.logger_.info("connection_handler: start\n");
		}

		virtual ~connection_handler_base() { server_.logger_.info("connection_handler: stop\n"); }

		connection_handler_base(connection_handler_base const&) = delete;
		void operator==(connection_handler_base const&) = delete;

		connection_handler_base(connection_handler_base&&) = delete;

		connection_handler_base& operator=(const connection_handler_base&) = delete;
		connection_handler_base& operator=(connection_handler_base&&) = delete;

		socket_t& socket_base() { return static_cast<connection_handler_derived*>(this)->socket(); };
		std::string remote_address_base() { return static_cast<connection_handler_derived*>(this)->remote_address(); };

		void stop() { --server_.manager().connections_current(); }

		void set_timeout()
		{
			steady_timer_.expires_from_now(std::chrono::seconds(session_handler_.keepalive_max()));

			auto me = this->shared_from_this();
			steady_timer_.async_wait([me](asio::error_code const& ec) {
				if (!ec) me->stop();
			});
		}

		void cancel_timeout()
		{
			asio::error_code ec;
			steady_timer_.cancel(ec);
		}

		void read_request_headers()
		{
			// Header
			auto me = this->shared_from_this();
			asio::async_read_until(
				this->socket_base(), in_packet_, "\r\n\r\n", [me](asio::error_code const& ec, std::size_t bytes_xfer) {
					me->read_request_headers_complete(ec, bytes_xfer);
				});
		}

		void read_request_headers_complete(asio::error_code const& ec, std::size_t bytes_transferred)
		{
			if (!ec)
			{
				http::request_parser::result_type result;

				std::tie(result, std::ignore) = session_handler_.parse_request(
					asio::buffers_begin(in_packet_.data()), asio::buffers_begin(in_packet_.data()) + bytes_transferred);

				in_packet_.consume(bytes_transferred);

				if (result == http::request_parser::good)
				{
					this->cancel_timeout();

					session_handler_.request().set("Remote_Addr", this->remote_address_base());

					if (session_handler_.request().content_length())
					{
						this->session_handler_.request().body() += std::string(
							asio::buffers_begin(in_packet_.data()), asio::buffers_end(in_packet_.data()));
						auto s = asio::buffers_end(in_packet_.data()) - asio::buffers_begin(in_packet_.data());

						in_packet_.consume(s);

						this->session_handler_.request().body().reserve(session_handler_.request().content_length());

						read_request_body();
					}
					else
					{
						read_request_body_complete(asio::error_code{}, 0);
					}
				}
				else if (result == http::request_parser::bad)
				{
					session_handler_.response().status(http::status::bad_request);
					write_buffer_.push_back(http::to_string(session_handler_.response()));

					write_response();
				}
				else
				{
					read_request_headers();
				}
			}
			else
			{
				stop();
			}
		}

		void read_request_body()
		{
			asio::error_code ec;
			if (session_handler_.request().body().size() < session_handler_.request().content_length())
			{
				auto me = this->shared_from_this();
				asio::async_read(
					this->socket_base(),
					in_packet_,
					asio::transfer_at_least(1),
					[me](asio::error_code const& ec, std::size_t bytes_xfer) {
						auto content_length = me->session_handler_.request().content_length();
						auto body_size = me->session_handler_.request().body().length();

						size_t chunk_size
							= asio::buffers_end(me->in_packet_.data()) - asio::buffers_begin(me->in_packet_.data());

						if (content_length - body_size < chunk_size) chunk_size = content_length - body_size;

						std::string chunk = std::string(
							asio::buffers_begin(me->in_packet_.data()),
							asio::buffers_begin(me->in_packet_.data()) + chunk_size);

						me->in_packet_.consume(chunk_size);

						me->session_handler_.request().body() += chunk;

						body_size = me->session_handler_.request().body().length();

						if (body_size < content_length)
						{
							me->read_request_body();
						}
						else
						{
							me->read_request_body_complete(ec, bytes_xfer);
						}
					});
			}
			else if (session_handler_.request().body().size() == session_handler_.request().content_length())
			{
				read_request_body_complete(ec, session_handler_.request().body().size());
			}
			else
			{
				ec.assign(1, ec.category());
				read_request_body_complete(ec, 0);
			}
		}

		void read_request_body_complete(asio::error_code const& ec, std::size_t)
		{
			if (!ec)
			{
				routing_ = session_handler_.handle_request(server_.router_);

				auto upstreams
					= session_handler_.request().get_attribute<http::basic::async::upstreams*>(
						"proxy_pass", nullptr);

				session_handler_.t2() = std::chrono::steady_clock::now();

				if (upstreams) 
					upstreams->forward(
						[this](http::basic::async::upstreams::connection_type& connection) {
						write_forwarded_request(connection);
						},
						server_.logger()
				);
				else
					write_response();
			}
		}

		void write_forwarded_request(http::basic::async::upstreams::connection_type& upstream_connection)
		{
			asio::error_code error;
			char peek_buffer[1];

			upstream_connection.socket().non_blocking(true);
			upstream_connection.socket().receive(
				asio::buffer(peek_buffer), asio::ip::tcp::socket::message_peek, error);
			upstream_connection.socket().non_blocking(false);

			if (error != asio::error::would_block)
			{
				upstream_connection.reopen();
			}

			session_handler_.request().set("Accept-Encoding", "gzip");
			write_buffer_.emplace_back(http::to_string(session_handler_.request()));

			auto me = this->shared_from_this();

			asio::async_write(
				upstream_connection.socket(),
				asio::buffer(write_buffer_.front()),
				[me, &upstream_connection](asio::error_code const& ec, std::size_t) 
			{
					me->write_buffer_.pop_front();

					if (!ec) 
						me->read_forwarded_response_headers(upstream_connection);
			});


		}


		void read_forwarded_response_headers(http::basic::async::upstreams::connection_type& upstream_connection)
		{
			auto me = this->shared_from_this();

			upstream_connection.buffer_.clear();

			asio::async_read_until(
				upstream_connection.socket(),
				asio::dynamic_buffer(upstream_connection.buffer_),
				"\r\n\r\n",
				[me, &upstream_connection](asio::error_code ec, size_t bytes_red) {
				// TODO response body complete? no -> st
				if (!ec) 
					me->read_forwarded_response_headers_complete(upstream_connection, bytes_red);
				}
			);

		}

		void read_forwarded_response_headers_complete(
			http::basic::async::upstreams::connection_type& upstream_connection, size_t bytes_red)
		{
			http::response_parser response_parser;
			http::response_parser::result_type result;
			const char* c = nullptr;

			std::tie(result, c) = response_parser.parse(
				session_handler_.response(),
				upstream_connection.buffer_.data(),
				upstream_connection.buffer_.data() + bytes_red);

			if (result == http::response_parser::result_type::good)
			{
				auto content_length = session_handler_.response().content_length();
				if (content_length)
				{
					session_handler_.request().set("X-Request-ID", upstream_connection.id());
					session_handler_.response().set("X-Upstream-Server", upstream_connection.id());

					auto content_already_received
						= static_cast<size_t>( upstream_connection.buffer_.data() + upstream_connection.buffer_.size() - c );

					auto status_code = http::status::to_int(session_handler_.response().status());

					upstream_connection.owner().update_status_code_metrics(status_code);

					session_handler_.response().body().reserve(content_length);

					session_handler_.response().body().assign(c, content_already_received);

					if (content_already_received < content_length)
					{
						read_forwarded_response_body(upstream_connection);
					}
					else
					{
						read_forwarded_response_body_complete(upstream_connection);
					}
				}
				else if (session_handler_.response().chunked())
				{
					session_handler_.response().status(http::status::internal_server_error);
					session_handler_.response().body() = "chunked upstream response received\n";
					read_forwarded_response_body_complete(upstream_connection);
				}
			}
		}

		void read_forwarded_response_body(http::basic::async::upstreams::connection_type& upstream_connection) 
		{
			asio::error_code ec;
			if (session_handler_.response().body().size() < session_handler_.response().content_length())
			{
				auto me = this->shared_from_this();
				upstream_connection.buffer_.clear();
				asio::async_read(
					upstream_connection.socket(),
					asio::dynamic_buffer(upstream_connection.buffer_),
					asio::transfer_at_least(1),
					[me, &upstream_connection](asio::error_code const&, std::size_t bytes_xfer) {
						auto content_length = me->session_handler_.response().content_length();

						me->session_handler_.response().body().append(upstream_connection.buffer_.data(), bytes_xfer);

						if (me->session_handler_.response().body().length() < content_length)
						{
							me->read_forwarded_response_body(upstream_connection);
						}
						else
						{
							me->read_forwarded_response_body_complete(upstream_connection);
						}
					});
			}
			else if (session_handler_.response().body().size() == session_handler_.response().content_length())
			{
				read_forwarded_response_body_complete(upstream_connection);
			}
			else
			{
				assert(1==0);
				read_forwarded_response_body_complete(upstream_connection);
			}
		}

		void read_forwarded_response_body_complete(http::basic::async::upstreams::connection_type& upstream_connection) 
		{
			if (session_handler_.response().connection_close() == true)
			{
				upstream_connection.reopen();
			}

			upstream_connection.release();

			write_response();
		}

		void write_response()
		{
			auto me = this->shared_from_this();
			session_handler_.set_response_headers<http::api::router<>>(routing_);

			write_buffer_.emplace_back(http::to_string(session_handler_.response()));

			asio::async_write(
				socket_base(),
				asio::buffer(this->write_buffer_.front()),
				write_strand_.wrap([me](asio::error_code, std::size_t) {
					me->write_buffer_.pop_front();
					me->write_response_complete();
				}));
		}

		void write_response_complete()
		{
			++server_.manager().requests_handled();

			if (routing_.match_result() == http::api::router_match::match_found)
			{
				routing_.the_route().metric_response_latency(
					std::chrono::duration<std::uint64_t, std::nano>(
						std::chrono::steady_clock::now() - session_handler_.t2())
						.count());

				if (server_.logger_.current_level() >= lgr::level::accesslog)
				{
					auto log_msg = server_.manager().log_access(session_handler_, routing_.the_route().route_metrics())
								   + "\n";

					server_.logger_.accesslog(log_msg);
				}
			}
			else
			{
				std::string log_msg
					= server_.manager().log_access(session_handler_, http::api::routing::metrics{}) + "\n";

				server_.logger_.accesslog(log_msg);
			}

			if (session_handler_.response().connection_keep_alive())
			{
				session_handler_.reset();
				static_cast<connection_handler_derived*>(this)->start();
			}
			else
			{
				// socket().shutdown(asio::ip::tcp::socket::shutdown_both);
			}
		}
	};

	class connection_handler_http
		: public server::connection_handler_base<connection_handler_http, asio::ip::tcp::socket>
	{
	public:
		connection_handler_http(asio::io_context& service, server& server, http::configuration& configuration)
			: connection_handler_base(service, server, configuration), socket_(service)
		{
		}

		asio::ip::tcp::socket& socket() { return socket_; }

		std::string remote_address()
		{
			asio::error_code ec;

			try
			{
				std::string ret = socket_.remote_endpoint().address().to_string(ec);

				if (ec) ret = "?";

				return ret;
			}
			catch (...)
			{
				return "-";
			}
		}

		void start()
		{
			set_timeout();
			asio::error_code ec;
			socket_.set_option(asio::ip::tcp::no_delay(true), ec);
			if (!ec)
				read_request_headers();
		}

		void stop()
		{
			if (socket_.is_open())
			{
				asio::error_code error;
				this->socket_.shutdown(asio::socket_base::shutdown_send, error);
				this->socket_.close();
			}
		}

	private:
		asio::ip::tcp::socket socket_;
	};

	class connection_handler_https
		: public server::connection_handler_base<connection_handler_https, asio::ssl::stream<asio::ip::tcp::socket>>
	{

	public:
		connection_handler_https(
			asio::io_context& service,
			server& server,
			http::configuration& configuration,
			asio::ssl::context& ssl_context)
			: connection_handler_base(service, server, configuration), socket_(service, ssl_context)
		{
		}

		asio::ssl::stream<asio::ip::tcp::socket>& socket() { return socket_; };

		std::string remote_address()
		{
			asio::error_code ec;

			try
			{
				std::string ret = socket_.lowest_layer().remote_endpoint().address().to_string(ec);

				if (ec) ret = "?";

				return ret;
			}
			catch (...)
			{
				return "-";
			}
		}

		void start()
		{
			auto me = shared_from_this();
			socket_.async_handshake(asio::ssl::stream_base::server, [me](asio::error_code const& ec) {
				if (ec)
				{
				}
				else
				{
					me->set_timeout();
					me->read_request_headers();
				}
			});
		}

	private:
		asio::ssl::stream<asio::ip::tcp::socket> socket_;
	};

	using shared_connection_handler_http_t = std::shared_ptr<server::connection_handler_http>;
	using shared_https_connection_handler_http_t = std::shared_ptr<server::connection_handler_https>;

public:
	server(http::configuration& configuration)
		: http::basic::server{ configuration }
		, thread_count_(configuration.get<std::uint8_t>(
			  "thread_count", static_cast<std::uint8_t>(std::thread::hardware_concurrency())))
		, http_watchdog_idle_timeout_(configuration.get<std::int16_t>("http_watchdog_idle_timeout", 0))
		, http_watchdog_max_requests_concurrent_(
			  configuration.get<std::int16_t>("http_watchdog_max_requests_concurrent", 0))
		, http_use_portsharding_(configuration.get<bool>("http_use_portsharding", false))
		, http_enabled_(configuration.get<bool>("http_enabled", true))
		, http_listen_port_begin_(configuration.get<std::int16_t>("http_listen_port_begin", 3000))
		, http_listen_port_end_(configuration.get<int16_t>("http_listen_port_end", http_listen_port_begin_))
		, http_listen_port_(network::tcp::socket::invalid_socket)
		, http_listen_address_(configuration.get<std::string>("http_listen_address", "::0"))
		, https_use_portsharding_(configuration.get<bool>("https_use_portsharding", false))
		, https_enabled_(configuration.get<bool>("https_enabled", false))
		, https_listen_port_begin_(configuration.get<std::int16_t>(
			  "https_listen_port_begin", configuration.get<int16_t>("http_listen_port_begin") + 1000))
		, https_listen_port_end_(configuration.get<int16_t>("https_listen_port_end", https_listen_port_begin_))
		, https_listen_port_(network::tcp::socket::invalid_socket)
		, https_listen_address_(configuration.get<std::string>("https_listen_address", "::0"))
		, gzip_min_length_(configuration.get<size_t>("gzip_min_length", 1024 * 10))
		, io_context_pool_(thread_count_)
		, http_acceptor_(io_context_pool_.get_io_context())
		, https_acceptor_(io_context_pool_.get_io_context())
		, https_ssl_context_(asio::ssl::context::tlsv13)
	{
		if (https_enabled_)
		{
			asio::error_code error_code;
			https_ssl_context_.use_certificate_chain_file(
				configuration_.get<std::string>("https_certificate_certificate_file", "server.crt"), error_code);
			
			if (error_code) std::cout << "https error: " << error_code.message() << "\n";

			https_ssl_context_.use_private_key_file(
				configuration_.get<std::string>("https_certificate_certificate_key", "server.key"),
				asio::ssl::context::pem,
				error_code);

			if (error_code) std::cout << "https error: " << error_code.message() << "\n";

		}

		if (configuration_.get("ssl_certificate_verify").size() > 0)
		{
			https_ssl_context_.load_verify_file(configuration_.get("ssl_certificate_verify"));
			https_ssl_context_.set_verify_mode(
				asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert | asio::ssl::verify_client_once);
			// set_session_id_context = true;
		}
	}

	virtual ~server()
	{
		if (is_active() || is_activating()) this->stop();

		logger_.debug("server deleted\n");
	}

	virtual server::state start() override
	{
		auto http_handler = std::make_shared<server::connection_handler_http>(
			io_context_pool_.get_io_context(), *this, configuration_);

		auto https_handler = std::make_shared<server::connection_handler_https>(
			io_context_pool_.get_io_context(), *this, configuration_, https_ssl_context_);

		asio::ip::tcp::endpoint http_endpoint(asio::ip::make_address(http_listen_address_), http_listen_port_begin_);
		asio::ip::tcp::endpoint https_endpoint(asio::ip::make_address(https_listen_address_), https_listen_port_begin_);

		asio::error_code ec;

		auto http_listen_port_probe = http_listen_port_begin_;

		for (; http_listen_port_probe <= http_listen_port_end_; http_listen_port_probe++)
		{
			http_endpoint.port(http_listen_port_probe);
			http_acceptor_.open(http_endpoint.protocol());

			if (http_listen_port_begin_ == http_listen_port_end_)
			{
				http_acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
			}

			http_acceptor_.bind(http_endpoint, ec);
			if (ec)
			{
				http_listen_port_probe++;
				continue;
			}
			else
				break;
		}

		if (ec)
			throw std::runtime_error(std::string(
				"cannot bind/listen to port in range: [ " + std::to_string(http_listen_port_begin_) + ":"
				+ std::to_string(http_listen_port_end_) + " ]"));

		http_acceptor_.listen(asio::socket_base::max_connections);
		configuration_.set("http_listen_port", std::to_string(http_listen_port_probe));
		logger_.info("http listener on port: {d} started\n", http_listen_port_probe);
		http_listen_port_.store(http_listen_port_probe);

		if (https_enabled_)
		{
			// setup listener for https if enabled
			auto https_listen_port_probe = https_listen_port_begin_;

			for (; https_listen_port_probe <= https_listen_port_end_; https_listen_port_probe++)
			{
				https_endpoint.port(https_listen_port_probe);
				https_acceptor_.open(https_endpoint.protocol());

				if (https_listen_port_begin_ == https_listen_port_end_)
				{
					https_acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
				}

				https_acceptor_.bind(https_endpoint, ec);
				if (ec)
				{
					https_listen_port_probe++;
					continue;
				}
				else
					break;
			}

			if (ec)
				throw std::runtime_error(std::string(
					"cannot bind/listen to port in range: [ " + std::to_string(https_listen_port_begin_) + ":"
					+ std::to_string(https_listen_port_end_) + " ]"));

			https_acceptor_.listen(asio::socket_base::max_connections);

			configuration_.set("https_listen_port", std::to_string(https_listen_port_probe));
			logger_.info("https listener on port: {d} started\n", https_listen_port_probe);
			http_listen_port_.store(https_listen_port_probe);

		}

		http_acceptor_.async_accept(http_handler->socket(), [this, http_handler](const asio::error_code error) {
			this->handle_new_connection(http_handler, error);
		});

		if (https_enabled_)
		{

			https_acceptor_.async_accept(
				https_handler->socket().lowest_layer(), [this, https_handler](const asio::error_code error) {
					this->handle_new_https_connection(https_handler, error);
				});
		}

		io_context_pool_.run();

		state_.store(http::basic::server::state::active);
		return state_;
	}

	virtual server::state stop() override
	{
		state_.store(state::not_active);

		io_context_pool_.stop();

		return state_;
	}

	asio::io_context& get_io_context() { return io_context_pool_.get_io_context(); }

private:
	void handle_new_connection(const shared_connection_handler_http_t& handler, const asio::error_code error)
	{
		if (error)
		{
			return;
		}

		++manager().connections_accepted();
		++manager().connections_current();

		handler->start();

		auto new_handler = std::make_shared<server::connection_handler_http>(
			io_context_pool_.get_io_context(), *this, configuration_);

		http_acceptor_.async_accept(new_handler->socket(), [this, new_handler](const asio::error_code error) {
			this->handle_new_connection(new_handler, error);
		});
	}

	void
	handle_new_https_connection(const shared_https_connection_handler_http_t& handler, const asio::error_code error)
	{
		if (error)
		{
			return;
		}

		handler->start();

		auto new_handler = std::make_shared<server::connection_handler_https>(
			io_context_pool_.get_io_context(), *this, configuration_, https_ssl_context_);

		https_acceptor_.async_accept(
			new_handler->socket().lowest_layer(), [this, new_handler](const asio::error_code error) {
				this->handle_new_https_connection(new_handler, error);
			});
	}

	std::uint8_t thread_count_;
	std::int16_t http_watchdog_idle_timeout_;
	std::int16_t http_watchdog_max_requests_concurrent_;

	bool http_use_portsharding_;
	bool http_enabled_;
	std::int16_t http_listen_port_begin_;
	std::int16_t http_listen_port_end_;
	std::atomic<network::socket_t> http_listen_port_;
	std::string http_listen_address_;

	bool https_use_portsharding_;
	bool https_enabled_;
	std::int16_t https_listen_port_begin_;
	std::int16_t https_listen_port_end_;
	std::atomic<network::socket_t> https_listen_port_;
	std::string https_listen_address_;

	size_t gzip_min_length_;

	class io_context_pool
	{
	public:
		io_context_pool(std::uint8_t thread_count) : thread_count_(thread_count), selected_io_context_(0)
		{
			for (std::uint8_t i = 0; i < thread_count_; ++i)
			{
				io_contexts_.emplace_back(new asio::io_context{});
				work_guards_for_io_contexts_.emplace_back(asio::make_work_guard(*io_contexts_[i]));
			}
		}

		asio::io_context& get_io_context() { return *io_contexts_[selected_io_context_++ % thread_count_].get(); }

		void run()
		{
			for (std::uint8_t i = 0; i < thread_count_; ++i)
			{
				thread_pool_.emplace_back([this, i] { io_contexts_[i]->run(); });
			}
		}

		void stop()
		{
			for (std::uint8_t i = 0; i < thread_count_; ++i)
			{
				io_contexts_[i]->stop();
				thread_pool_[i].join();
			}
		}

	private:
		size_t thread_count_;
		std::vector<std::unique_ptr<asio::io_context>> io_contexts_;
		std::vector<asio::executor_work_guard<asio::io_context::executor_type>> work_guards_for_io_contexts_;

		std::vector<std::thread> thread_pool_;
		std::atomic<size_t> selected_io_context_;
	};

	io_context_pool io_context_pool_;

	asio::ip::tcp::acceptor http_acceptor_;
	asio::ip::tcp::acceptor https_acceptor_;
	asio::ssl::context https_ssl_context_;
};

} // namespace async
} // namespace basic
} // namespace http
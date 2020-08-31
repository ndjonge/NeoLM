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
//#include <asio/log/trivial.hpp>

#include "http_basic.h"

namespace http
{

namespace basic
{

namespace async
{

namespace client
{

class session
{
public:
	enum class state
	{
		waiting,
		idle
	};

	session(asio::io_context& io_context, const std::string& host, const std::string& port)
		: io_context_(io_context)
		, host_(host)
		, port_(port)
		, resolver_(io_context)
		, socket_(io_context)
		, id_(session::instances__++)
	{
		recieve_buffer.reserve(1500);
		reopen();
	};

	session(const session& s)
		: io_context_(s.io_context_), host_(s.host_), port_(s.port_), resolver_(s.io_context_), socket_(s.io_context_)
	{
		reopen();
	};

	void reopen() 
	{
		if (socket_.is_open())
		{
			socket_.close();
		}

		asio::ip::tcp::resolver::query query(host_, port_);
		auto resolved_endpoints = resolver_.resolve(query);
		asio::error_code error;

		asio::connect(socket_, resolved_endpoints.cbegin(), resolved_endpoints.cend(), error);

		if (error)
		{
			std::cout << "not open\n";
		}
	}

	asio::ip::tcp::socket& socket() { return socket_; }
	std::atomic<state>& get_state() { return state_; }

	std::size_t id() { return id_; };
	static std::size_t instances__;

	std::string recieve_buffer;

private:

	asio::io_context& io_context_;
	std::string host_;
	std::string port_;

	asio::ip::tcp::resolver resolver_;
	asio::ip::tcp::socket socket_;
	std::atomic<session::state> state_{ state::idle };
	std::size_t id_{0};

};

std::size_t session::instances__{ 0 };

void forward_request(
	http::basic::async::client::session& upstream_client_session,
	http::session_handler& downstream_session_handler,
	std::string& ec)
{
	std::string request = http::to_string(downstream_session_handler.request());

	asio::error_code error;
	auto bytes_written = asio::write(upstream_client_session.socket(), asio::buffer(request.data(), request.size()), error);

	if (error)
	{
		upstream_client_session.reopen();
		bytes_written
			= asio::write(upstream_client_session.socket(), asio::buffer(request.data(), request.size()), error);
		if (error)
		{
			downstream_session_handler.response().status(http::status::bad_gateway);
			ec = error.message();
			upstream_client_session.get_state().store(http::basic::async::client::session::state::idle);

			return;
		}
	}

	error.clear();
	upstream_client_session.recieve_buffer.clear();
	auto bytes_red = asio::read_until(
		upstream_client_session.socket(),
		asio::dynamic_buffer(upstream_client_session.recieve_buffer, upstream_client_session.recieve_buffer.capacity()),
		"\r\n\r\n",
		error);

	if (error)
	{
		downstream_session_handler.response().status(http::status::bad_gateway);
		downstream_session_handler.response().body() = error.message();
		ec = error.message();
		upstream_client_session.get_state().store(http::basic::async::client::session::state::idle);
		return;
	}

	http::response_parser response_parser;
	http::response_parser::result_type result;
	const char* c = nullptr;

	std::tie(result, c) = response_parser.parse(
		downstream_session_handler.response(),
		upstream_client_session.recieve_buffer.data(),
		upstream_client_session.recieve_buffer.data() + bytes_red);

	if (result == http::response_parser::result_type::good)
	{
		auto content_length = downstream_session_handler.response().content_length();
		if (content_length)
		{
			downstream_session_handler.response().body().reserve(content_length);
			downstream_session_handler.response().body().assign(c, content_length);

			// read more?
		}
		else if (downstream_session_handler.response().chunked())
		{
			std::uint64_t offset = 0;
			auto chunk_size = std::stoul(c, &offset, 16);
			auto chuck_data = c + offset + 2;
			downstream_session_handler.response().body().assign(chuck_data, chunk_size);
			// TODO: chunked
		}

		if (downstream_session_handler.response().connection_close() == true) 
		{
			//std::cout << std::to_string(upstream_client_session.id()) + " : closed \n";
			upstream_client_session.reopen();	
		}
	}

	upstream_client_session.get_state().store(http::basic::async::client::session::state::idle);
	return;
}


} // namespace client

class server : public http::basic::server
{
private:
	template <class connection_handler_derived, class socket_t>
	class connection_handler_base : public std::enable_shared_from_this<connection_handler_derived>
	{
	protected:
		asio::io_context& service_;
		asio::io_context::strand write_strand_;
		asio::streambuf in_packet_;
		asio::steady_timer steady_timer_;

		std::deque<std::string> write_buffer_;
		http::session_handler session_handler_;
		server& server_;

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

		void stop() {}

		void set_timeout()
		{
			steady_timer_.expires_from_now(std::chrono::seconds(session_handler_.keepalive_max()));

			steady_timer_.async_wait([me = this->shared_from_this()](asio::error_code const& ec) {
				if (!ec) me->stop();
			});
		}

		void cancel_timeout()
		{
			asio::error_code ec;
			steady_timer_.cancel(ec);
		}

		void do_read_header()
		{
			// Header
			asio::async_read_until(
				this->socket_base(),
				in_packet_,
				"\r\n\r\n",
				[me = this->shared_from_this()](asio::error_code const& ec, std::size_t bytes_xfer) {
					me->do_read_header_done(ec, bytes_xfer);
				});
		}

		void do_read_header_done(asio::error_code const& ec, std::size_t bytes_transferred)
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

						do_read_body();
					}
					else
					{
						do_read_body_done(asio::error_code{}, 0);
					}
				}
				else if (result == http::request_parser::bad)
				{
					session_handler_.response().status(http::status::bad_request);
					write_buffer_.push_back(http::to_string(session_handler_.response()));

					do_write_header();
				}
				else
				{
					do_read_header();
				}
			}
			else
			{
				stop();
			}
		}

		void do_read_body()
		{
			if (this->session_handler_.request().body().size() < this->session_handler_.request().content_length())
			{
				asio::async_read(
					this->socket_base(),
					in_packet_,
					asio::transfer_at_least(1),
					[me = this->shared_from_this()](asio::error_code const& ec, std::size_t bytes_xfer) {
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
							me->do_read_body();
						}
						else
						{
							me->do_read_body_done(ec, bytes_xfer);
						}
					});
			}
			else
			{
				asio::error_code ec;
				ec.assign(1, ec.category());
				this->do_read_body_done(ec, 0);
			}
		}

		void do_read_body_done(asio::error_code const& ec, std::size_t)
		{
			if (!ec)
			{
				auto result = session_handler_.handle_request(server_.router_);
				++server_.manager().requests_handled();
				do_write_header();
			}
		}

		void do_write_body()
		{
			if (!session_handler_.response().body().empty())
			{
				asio::error_code ec;
				asio::write(socket_base(), asio::buffer(session_handler_.response().body()), ec);
			}
			do_write_content_done();
		}

		void do_write_content_done() { do_write_header_done(); }

		void do_write_header()
		{
			write_buffer_.emplace_back(session_handler_.response().header_to_string());

			asio::async_write(
				socket_base(),
				asio::buffer(this->write_buffer_.front()),
				write_strand_.wrap([me = this->shared_from_this()](asio::error_code, std::size_t) {
					me->write_buffer_.pop_front();

					me->do_write_body();
				}));
		}

		void do_write_header_done()
		{
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
			socket_.set_option(asio::ip::tcp::no_delay(true));
			do_read_header();
		}

		void stop() { this->socket_.close(); }

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

		std::string remote_address() { return socket_.lowest_layer().remote_endpoint().address().to_string(); }

		void start()
		{

			socket_.async_handshake(
				asio::ssl::stream_base::server, [me = this->shared_from_this()](asio::error_code const& ec) {
					if (ec)
					{
					}
					else
					{
						me->set_timeout();
						me->do_read_header();
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
		, thread_count_(configuration.get<int>("thread_count", std::thread::hardware_concurrency()))
		, http_watchdog_idle_timeout_(configuration.get<std::int16_t>("http_watchdog_idle_timeout", 0))
		, http_watchdog_max_requests_concurrent_(
			  configuration.get<std::int16_t>("http_watchdog_max_requests_concurrent", 0))
		, http_use_portsharding_(configuration.get<bool>("http_use_portsharding", false))
		, http_enabled_(configuration.get<bool>("http_enabled", true))
		, http_listen_port_begin_(configuration.get<std::int16_t>("http_listen_port_begin", 3000))
		, http_listen_port_end_(configuration.get<int16_t>("http_listen_port_end", http_listen_port_begin_))
		, http_listen_port_(network::tcp::socket::invalid_socket)
		//			, http_listen_address_(
		//				  configuration.get<std::string>("http_listen_address", "::0"), http_listen_port_begin_)
		, https_use_portsharding_(configuration.get<bool>("https_use_portsharding", false))
		, https_enabled_(configuration.get<bool>("https_enabled", false))
		, https_listen_port_begin_(configuration.get<std::int16_t>(
			  "https_listen_port_begin", configuration.get<int16_t>("http_listen_port_begin") + 2000))
		, https_listen_port_end_(configuration.get<int16_t>("https_listen_port_end", http_listen_port_begin_))
		, https_listen_port_(network::tcp::socket::invalid_socket)
		//			, https_listen_address_(
		//				  configuration.get<std::string>("https_listen_address", "::0"), https_listen_port_begin_)
		, gzip_min_length_(configuration.get<size_t>("gzip_min_length", 1024 * 10))
		, io_context_pool_(thread_count_)
		, acceptor_(io_context_pool_.get_io_context())
		, ssl_acceptor_(io_context_pool_.get_io_context())
		, ssl_context(asio::ssl::context::tlsv12)
	{
		// ssl_context.use_certificate_chain_file(configuration_.get("ssl_certificate"));
		// ssl_context.use_private_key_file(configuration_.get("ssl_certificate_key"), asio::ssl::context::pem);

		if (configuration_.get("ssl_certificate_verify").size() > 0)
		{
			ssl_context.load_verify_file(configuration_.get("ssl_certificate_verify"));
			ssl_context.set_verify_mode(
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
		auto http_handler = std::make_shared<server::connection_handler_http>(io_context_pool_.get_io_context(), *this, configuration_);

		asio::ip::tcp::endpoint http_endpoint(asio::ip::tcp::v6(), http_listen_port_begin_);

		acceptor_.open(http_endpoint.protocol());

		if (http_listen_port_begin_ == http_listen_port_end_)
		{
			acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
		}

		asio::error_code ec;

		auto http_listen_port_probe = http_listen_port_begin_;

		for (; http_listen_port_probe <= http_listen_port_end_; http_listen_port_probe++)
		{
			http_endpoint.port(http_listen_port_probe);
			acceptor_.close();
			acceptor_.open(http_endpoint.protocol());
			acceptor_.bind(http_endpoint, ec);
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

		acceptor_.listen(asio::socket_base::max_connections);

		configuration_.set("http_listen_port", std::to_string(http_listen_port_probe));
		logger_.info("http listener on port: {d} started\n", http_listen_port_probe);
		http_listen_port_.store(http_listen_port_probe);

		acceptor_.async_accept(http_handler->socket(), [this, http_handler](auto error) {
			this->handle_new_connection(http_handler, error);
		});

		io_context_pool_.run();


		/*ssl_acceptor_.async_accept(
			https_handler->socket().lowest_layer(), [this, https_handler](auto error) {
		   this->handle_new_https_connection(https_handler, error); });
		*/

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

		acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error) {
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
			io_context_pool_.get_io_context(), *this, configuration_, ssl_context);

		ssl_acceptor_.async_accept(new_handler->socket().lowest_layer(), [this, new_handler](auto error) {
			this->handle_new_https_connection(new_handler, error);
		});
	}

	int thread_count_;
	std::int16_t http_watchdog_idle_timeout_;
	std::int16_t http_watchdog_max_requests_concurrent_;

	bool http_use_portsharding_;
	bool http_enabled_;
	std::int16_t http_listen_port_begin_;
	std::int16_t http_listen_port_end_;
	std::atomic<network::socket_t> http_listen_port_;

	bool https_use_portsharding_;
	bool https_enabled_;
	std::int16_t https_listen_port_begin_;
	std::int16_t https_listen_port_end_;
	std::atomic<network::socket_t> https_listen_port_;

	size_t gzip_min_length_;
	
	class io_context_pool
	{
	public:
		io_context_pool(size_t thread_count)
			: thread_count_(thread_count), selected_io_context_(0)
		{
			for (auto i = 0; i < thread_count_; ++i)
			{
				io_contexts_.emplace_back(std::make_unique<asio::io_context>());
				work_guards_for_io_contexts_.emplace_back(asio::make_work_guard(*io_contexts_[i]));
			}
		}

		asio::io_context& get_io_context() {return *io_contexts_[selected_io_context_++ % thread_count_].get(); }

		void run() 
		{
			for (auto i = 0; i < thread_count_; ++i)
			{
				thread_pool_.emplace_back([this, i] { io_contexts_[i]->run(); });
			}
		}

		void stop() 
		{
			for (auto i = 0; i < thread_count_; ++i)
			{
				io_contexts_[i]->stop();
				thread_pool_[i].join();
			}
		}

	private:
		size_t thread_count_;
		std::vector < std::unique_ptr<asio::io_context> > io_contexts_;
		std::vector<asio::executor_work_guard<asio::io_context::executor_type>> work_guards_for_io_contexts_;

		std::vector<std::thread> thread_pool_;
		std::atomic<size_t> selected_io_context_;
	};

	io_context_pool io_context_pool_;

	asio::ip::tcp::acceptor acceptor_;
	asio::ip::tcp::acceptor ssl_acceptor_;
	asio::ssl::context ssl_context;
};

} // namespace async
} // namespace basic
} // namespace http

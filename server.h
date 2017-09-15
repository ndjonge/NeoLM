#pragma once

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include <deque>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>

#include <boost/log/trivial.hpp>

namespace http
{

template <class connection_handler_derived, class socket_t> class connection_handler_base : public std::enable_shared_from_this<connection_handler_derived>
{
protected:
	boost::asio::io_service& service_;
	boost::asio::io_service::strand write_strand_;
	boost::asio::streambuf in_packet_;
	boost::asio::steady_timer steady_timer_;

	std::deque<std::string> write_buffer_;

	http::session_handler session_handler_;

public:
	connection_handler_base(boost::asio::io_service& service, http::api::router& router)
		: service_(service)
		, write_strand_(service)
		, steady_timer_(service)
		, session_handler_("C:\\temp", router)
	{
	}

	~connection_handler_base() = default;

	connection_handler_base(connection_handler_base const&) = delete;
	void operator==(connection_handler_base const&) = delete;

	socket_t& socket_base() { return static_cast<connection_handler_derived*>(this)->socket(); };

	void stop() {}

	void set_timeout()
	{
		steady_timer_.expires_from_now(std::chrono::seconds(session_handler_.keepalive_max()));

		steady_timer_.async_wait([me = shared_from_this()](boost::system::error_code const& ec) {
			if (!ec) me->stop();
		});
	}

	void cancel_timeout()
	{
		boost::system::error_code ec;
		steady_timer_.cancel(ec);
	}

	void do_read()
	{

		boost::asio::async_read_until(
			this->socket_base(), in_packet_,
			"\r\n\r\n", [me = shared_from_this()](boost::system::error_code const& ec, std::size_t bytes_xfer) { me->do_read_done(ec, bytes_xfer); });
	}

	void do_read_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
	{
		if (!ec)
		{
			http::request_parser::result_type result;

			std::tie(result, std::ignore) = session_handler_.parse_request(
				boost::asio::buffers_begin(in_packet_.data()), boost::asio::buffers_begin(in_packet_.data()) + bytes_transferred);

			in_packet_.consume(bytes_transferred);

			if (result == http::request_parser::good)
			{
				session_handler_.handle_request();

				write_buffer_.push_back(reply().headers_to_string());

				do_write_header();
			}
			else if (result == http::request_parser::bad)
			{
				reply() = http::reply::stock_reply(http::reply::bad_request);
				do_write_header();
			}
			else
			{
				do_read();
			}
		}
		else if (ec == boost::asio::error::operation_aborted)
		{
			stop();
		}
	}

	void do_write_content()
	{
		auto result = http::util::read_from_disk<std::array<char, 16384>>(
			reply().document_path().c_str(), [ this, chunked = reply().chunked_encoding() ](std::array<char, 16384> & buffer, size_t bytes_in) {
				std::stringstream ss;

				if (!chunked)
					ss << std::string(buffer.begin(), buffer.begin() + bytes_in);
				else
					ss << std::hex << bytes_in << misc_strings::crlf << std::string(buffer.begin(), buffer.begin() + bytes_in) << misc_strings::crlf;

				if (bytes_in == buffer.size())
				{
					boost::asio::write(socket_base(), boost::asio::buffer(ss.str()));
				}
				else
				{
					if (!chunked)
					{
						boost::asio::write(socket_base(), boost::asio::buffer(ss.str()));
						do_write_content_done();
					}
					else
					{
						boost::asio::write(socket_base(), boost::asio::buffer(ss.str()));

						ss.str("");
						ss << std::hex << 0 << misc_strings::crlf;

						boost::asio::write(socket_base(), boost::asio::buffer(ss.str()));

						do_write_content_done();
					}
				}

				return true;
			});
	}

	void do_write_content_done() { do_write_header_done(); }

	void do_write_header()
	{
		boost::asio::async_write(
			socket_base(), boost::asio::buffer(this->write_buffer_.front()),
			write_strand_.wrap([ this, me = shared_from_this() ](boost::system::error_code ec, std::size_t) {
				me->write_buffer_.pop_front();

				me->do_write_content();
			}));
	}

	void do_write_header_done()
	{
		if (reply().keep_alive() && session_handler_.keepalive_count() > 0)
		{
			session_handler_.keepalive_count()--;
			session_handler_.reset();

			static_cast<connection_handler_derived*>(this)->start();
		}
		else
		{
			// socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
		}
	}
};

class connection_handler_https : public http::connection_handler_base<connection_handler_https, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
{

public:
	connection_handler_https(boost::asio::io_service& service, http::api::router& router, boost::asio::ssl::context& ssl_context)
		: connection_handler_base(service, router)
		, ssl_context_(ssl_context)
		, socket_(service, ssl_context)
	{
	}

	boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket() { return socket_; };

	void start()
	{

		socket_.async_handshake(boost::asio::ssl::stream_base::server, [me = shared_from_this()](boost::system::error_code const& ec) {
			if (ec)
			{
			}
			else
			{
				me->set_timeout();

				me->do_read();
			}
		});
	}

private:
	boost::asio::ssl::context& ssl_context_;
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
};

class connection_handler_http : public http::connection_handler_base<connection_handler_http, boost::asio::ip::tcp::socket>
{
public:
	connection_handler_http(boost::asio::io_service& service, http::api::router& router)
		: connection_handler_base(service, router)
		, socket_(service)
	{
	}

	boost::asio::ip::tcp::socket& socket() { return socket_; }

	void start()
	{
		set_timeout();
		do_read();
	}

	void stop() { this->socket_.close(); }

private:
	boost::asio::ip::tcp::socket socket_;
};

template <typename connection_handler_http_t, typename ssl_connection_handler_t> class server
{
	using shared_connection_handler_http_t = std::shared_ptr<http::connection_handler_http>;
	using shared_https_connection_handler_http_t = std::shared_ptr<http::connection_handler_https>;

public:
	server(
		const std::string& cert_file,
		const std::string& private_key_file,
		const std::string& verify_file = std::string(),
		int thread_count = 10,
		int keep_alive_count = 5,
		int keepalive_timeout = 2)
		: thread_count(thread_count)
		, keep_alive_count(keep_alive_count)
		, keepalive_timeout(keepalive_timeout)
		, acceptor_(io_service)
		, ssl_acceptor_(io_service)
		, ssl_context(io_service, boost::asio::ssl::context::tlsv12)
	{
		ssl_context.use_certificate_chain_file(cert_file);
		ssl_context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);

		if (verify_file.size() > 0)
		{
			ssl_context.load_verify_file(verify_file);
			ssl_context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
			// set_session_id_context = true;
		}
	}

	void start_server()
	{
		auto http_handler = std::make_shared<http::connection_handler_http>(io_service, router_);
		auto https_handler = std::make_shared<http::connection_handler_https>(io_service, router_, ssl_context);

		boost::asio::ip::tcp::endpoint http_endpoint(boost::asio::ip::tcp::v4(), 60005);
		boost::asio::ip::tcp::endpoint https_endpoint(boost::asio::ip::tcp::v4(), 60006);

		acceptor_.open(http_endpoint.protocol());
		ssl_acceptor_.open(https_endpoint.protocol());

		acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

		acceptor_.bind(http_endpoint);
		ssl_acceptor_.bind(https_endpoint);

		acceptor_.listen();
		ssl_acceptor_.listen();

		acceptor_.async_accept(http_handler->socket(), [this, http_handler](auto error) { this->handle_new_connection(http_handler, error); });

		ssl_acceptor_.async_accept(
			https_handler->socket().lowest_layer(), [this, https_handler](auto error) { this->handle_new_https_connection(https_handler, error); });

		for (auto i = 0; i < thread_count; ++i)
		{
			thread_pool.emplace_back([this] { io_service.run(); });
		}

		for (auto i = 0; i < thread_count; ++i)
		{
			thread_pool[i].join();
		}
	}

private:
	void handle_new_connection(shared_connection_handler_http_t handler, const boost::system::error_code error)
	{
		if (error)
		{
			return;
		}

		handler->start();

		auto new_handler = std::make_shared<http::connection_handler_http>(io_service, router_);

		acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error) { this->handle_new_connection(new_handler, error); });
	}

	void handle_new_https_connection(shared_https_connection_handler_http_t handler, const boost::system::error_code error)
	{
		if (error)
		{
			return;
		}

		handler->start();

		auto new_handler = std::make_shared<http::connection_handler_https>(io_service, router_, ssl_context);

		ssl_acceptor_.async_accept(
			new_handler->socket().lowest_layer(), [this, new_handler](auto error) { this->handle_new_https_connection(new_handler, error); });
	}

	int thread_count;
	int keep_alive_count;
	int keepalive_timeout;

	std::vector<std::thread> thread_pool;

	boost::asio::io_service io_service;
	boost::asio::ip::tcp::acceptor acceptor_;
	boost::asio::ip::tcp::acceptor ssl_acceptor_;
	http::api::router router_;

	boost::asio::ssl::context ssl_context;
};

} // namespace http
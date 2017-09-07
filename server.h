#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <iostream>
#include <fstream>

#include <thread>
#include <deque>

#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

namespace http
{

template<class connection_handler_derived_t>
class connection_handler_base
{
protected:
	boost::asio::io_service& service_;
	boost::asio::io_service::strand write_strand_;
	boost::asio::streambuf in_packet_;

	std::array<char, 8192> buffer_;
	std::deque<std::string> write_buffer;

	http::request_handler request_handler_;

	http::session session;

	http::request request_;

	http::request_parser request_parser_;

	http::reply reply_;

public:
	connection_handler_base(boost::asio::io_service& service)
		: service_(service),
		session(10, 5),
		write_strand_(service),
		request_handler_("C:\\temp")
	{
	}

	connection_handler_base(connection_handler_base const &) = delete;
	void operator==(connection_handler_base const &) = delete;

	void start()
	{
		static_cast<connection_handler_derived_t*>(this)->do_start();
	}

	void stop()
	{
		static_cast<connection_handler_derived_t*>(this)->do_start();
	}

	void do_read()
	{
		static_cast<connection_handler_derived_t*>(this)->do_read();
	};

	void do_read_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
	{
		static_cast<connection_handler_derived_t*>(this)->do_read_done();
	};

	void do_write_header()
	{
		static_cast<connection_handler_derived_t*>(this)->do_write_header();
	};

	void do_write_header_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
	{
		static_cast<T*>(this)->do_write_header_done();
	};

	void do_write_content()
	{
		static_cast<connection_handler_derived_t*>(this)->do_write_content();
	};

	void do_write_content_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
	{
		static_cast<connection_handler_derived_t*>(this)->do_write_content_done();
	};
};




class connection_handler_https :
	public std::enable_shared_from_this<http::connection_handler_https>,
	public http::connection_handler_base<connection_handler_https>
{
	using ssl_socket_t = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;


public:
	connection_handler_https(boost::asio::io_service& service, boost::asio::ssl::context& ssl_context)
		: connection_handler_base(service),
		ssl_context_(ssl_context),
		socket_(service, ssl_context)
	{
	}


	~connection_handler_https()
	{
	}

	ssl_socket_t::lowest_layer_type& socket()
	{
		return socket_.lowest_layer();
	}

	void start()
	{

		socket_.async_handshake(boost::asio::ssl::stream_base::server, [me = shared_from_this()](boost::system::error_code const& ec)
		{
			if (ec)
			{
			}
			else
			{
				me->do_read();
			}
		});
	}

	void do_read()
	{

		boost::asio::async_read_until(socket_, in_packet_, "\r\n\r\n",
			[me = shared_from_this()](boost::system::error_code const& ec, std::size_t bytes_xfer)
		{
			me->do_read_done(ec, bytes_xfer);
		});
	}

	void do_read_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
	{
		if (!ec)
		{
			http::request_parser::result_type result;

			std::tie(result, std::ignore) = request_parser_.parse(request_, boost::asio::buffers_begin(in_packet_.data()), boost::asio::buffers_begin(in_packet_.data()) + bytes_transferred);

			in_packet_.consume(bytes_transferred);

			if (result == http::request_parser::good)
			{
				request_handler_.handle_request(request_, reply_, session);

				if (!reply_.chunked_encoding())
				{
					size_t bytes_total = fs::file_size(reply_.document_path());
					reply_.headers.emplace_back(http::header("Content-Length", std::to_string(bytes_total)));
				}
				write_buffer.push_back(reply_.to_string());

				do_write_header();
			}
			else if (result == http::request_parser::bad)
			{
				reply_ = http::reply::stock_reply(http::reply::bad_request);
				do_write_header();
			}
			else
			{
				do_read();
			}
		}
		else if (ec != boost::asio::error::operation_aborted)
		{
			socket().shutdown(boost::asio::ip::tcp::socket::shutdown_receive);
		}
	}

	void do_write_content()
	{
		auto result = http::util::read_from_disk<std::array<char, 16384>>(reply_.document_path().c_str(),
			[this, chunked = reply_.chunked_encoding()](std::array<char, 16384>& buffer, size_t bytes_in)
		{
			std::stringstream ss;

			if (!chunked)
				ss << std::string(buffer.begin(), buffer.begin() + bytes_in);
			else
				ss << std::hex << bytes_in << misc_strings::crlf << std::string(buffer.begin(), buffer.begin() + bytes_in) << misc_strings::crlf;

			if (bytes_in == buffer.size())
			{
				boost::asio::write(socket_, boost::asio::buffer(ss.str()));
			}
			else
			{
				if (!chunked)
				{
					boost::asio::write(socket_, boost::asio::buffer(ss.str()));
				}
				else
				{
					boost::asio::write(socket_, boost::asio::buffer(ss.str()));

					ss.str("");
					ss << std::hex << 0 << misc_strings::crlf;

					boost::asio::write(socket_, boost::asio::buffer(ss.str()));

					do_write_content_done();
				}
			}

			return true;
		}
		);
	}

	void do_write_content_done()
	{
		do_write_header_done();
	}

	void do_write_header()
	{
		boost::asio::async_write(socket_, boost::asio::buffer(this->write_buffer.front()), write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
		{
			me->write_buffer.pop_front();

			me->do_write_content();
		}));
	}

	void do_write_header_done()
	{
		if (reply_.keep_alive() && session.keepalive_count_ > 0)
		{
			session.keepalive_count_--;
			request_parser_.reset();
			request_.reset();
			reply_.reset();
			do_read();
		}
		else
		{
			socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
		}
	}


private:

	boost::asio::ssl::context& ssl_context_;
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;

};
	


	class connection_handler_http : 
		public std::enable_shared_from_this<http::connection_handler_http>,
		public http::connection_handler_base<connection_handler_http>
	{
	public:
		connection_handler_http(boost::asio::io_service& service)
			: connection_handler_base(service),
			socket_(service)
		{
		}

		~connection_handler_http()
		{
		}

		boost::asio::ip::tcp::socket& socket()
		{
			return socket_;
		}

		void start()
		{
			do_read();
		}

		void do_read()
		{
			boost::asio::async_read_until(socket_, in_packet_, "\r\n\r\n",
				[me = shared_from_this()](boost::system::error_code const& ec, std::size_t bytes_xfer)
			{
				me->do_read_done(ec, bytes_xfer);
			});
		}

		void do_read_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
		{
			if (!ec)
			{
				http::request_parser::result_type result;

				std::tie(result, std::ignore) = request_parser_.parse(request_, boost::asio::buffers_begin(in_packet_.data()), boost::asio::buffers_begin(in_packet_.data()) + bytes_transferred);

				in_packet_.consume(bytes_transferred);

				if (result == http::request_parser::good)
				{
					request_handler_.handle_request(request_, reply_, session);

					if (!reply_.chunked_encoding())
					{
						size_t bytes_total = fs::file_size(reply_.document_path());
						reply_.headers.emplace_back(http::header("Content-Length", std::to_string(bytes_total)));
					}
					write_buffer.push_back(reply_.to_string());

					do_write_header(); 


				}
				else if (result == http::request_parser::bad)
				{
					reply_ = http::reply::stock_reply(http::reply::bad_request);
					do_write_header();
				}
				else
				{
					do_read();
				}
			}
			else if (ec != boost::asio::error::operation_aborted)
			{
			}

		}

		void do_write_content()
		{
			auto result = http::util::read_from_disk<std::array<char, 16384>>(reply_.document_path().c_str(),
				[this, chunked = reply_.chunked_encoding()](std::array<char, 16384>& buffer, size_t bytes_in)
			{
				std::stringstream ss;

				if (!chunked)
					ss << std::string(buffer.begin(), buffer.begin() + bytes_in);
				else
					ss << std::hex << bytes_in << misc_strings::crlf << std::string(buffer.begin(), buffer.begin() + bytes_in) << misc_strings::crlf;

				if (bytes_in == buffer.size())
				{
					boost::asio::write(socket_, boost::asio::buffer(ss.str()));
				}
				else
				{
					if (!chunked)
					{
						boost::asio::write(socket_, boost::asio::buffer(ss.str()));
					}
					else
					{
						boost::asio::write(socket_, boost::asio::buffer(ss.str()));

						ss.str("");
						ss << std::hex << 0 << misc_strings::crlf;

						boost::asio::write(socket_, boost::asio::buffer(ss.str()));

						do_write_content_done();
					}
				}

				return true;
			}
			);
		}

		void do_write_content_done()
		{
			do_write_header_done();
		}

		void do_write_header()
		{
			boost::asio::async_write(socket_, boost::asio::buffer(this->write_buffer.front()), write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
			{
				me->write_buffer.pop_front();

				me->do_write_content();
			}));
		}

		void do_write_header_done()
		{
			if (reply_.keep_alive() && session.keepalive_count_ > 0)
			{
				session.keepalive_count_--;
				request_parser_.reset();
				request_.reset();
				reply_.reset();
				do_read();
			}
			else
			{
				socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			}
		}

	private:
		boost::asio::ip::tcp::socket socket_;
	};

	template <typename connection_handler_http_t, typename ssl_connection_handler_t> class server
	{
		using shared_connection_handler_http_t = std::shared_ptr<http::connection_handler_http>;
		using shared_https_connection_handler_http_t = std::shared_ptr<http::connection_handler_https>;

	public:
		server(const std::string &cert_file, const std::string &private_key_file, const std::string &verify_file = std::string(), int thread_count = 10, int keep_alive_count = 5, int keepalive_timeout = 2) :
			thread_count(thread_count),
			keep_alive_count(keep_alive_count),
			keepalive_timeout(keepalive_timeout),
			acceptor_(io_service),
			ssl_acceptor_(io_service),
			ssl_context(io_service, boost::asio::ssl::context::tlsv12)
		{
			ssl_context.use_certificate_chain_file(cert_file);
			ssl_context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);

			if (verify_file.size() > 0) {
				ssl_context.load_verify_file(verify_file);
				ssl_context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
				//set_session_id_context = true;
			}
		}

		void start_server()
		{
			auto http_handler = std::make_shared<http::connection_handler_http>(io_service);
			auto https_handler = std::make_shared<http::connection_handler_https>(io_service, ssl_context);

			boost::asio::ip::tcp::endpoint http_endpoint(boost::asio::ip::tcp::v4(), 60005);
			boost::asio::ip::tcp::endpoint https_endpoint(boost::asio::ip::tcp::v4(), 60006);

			acceptor_.open(http_endpoint.protocol());
			ssl_acceptor_.open(https_endpoint.protocol());

			acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

			acceptor_.bind(http_endpoint);
			ssl_acceptor_.bind(https_endpoint);

			acceptor_.listen();
			ssl_acceptor_.listen();

			acceptor_.async_accept(http_handler->socket(), [this, http_handler](auto error)
			{
				this->handle_new_connection(http_handler, error);
			});

			ssl_acceptor_.async_accept(https_handler->socket(), [this, https_handler](auto error)
			{
				this->handle_new_https_connection(https_handler, error);
			});

			for (auto i = 0; i < thread_count; ++i)
			{
				thread_pool.emplace_back([this]
				{
					io_service.run();
				});
			}

			for (auto i = 0; i < thread_count; ++i)
			{
				thread_pool[i].join();
			}
		}

	private:
		void handle_new_connection(shared_connection_handler_http_t handler, const boost::system::error_code error)
		{
			if (error) { return; }

			handler->start();

			auto new_handler = std::make_shared<http::connection_handler_http>(io_service);

			acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error)
			{
				std::cout << "accepted a non-ssl-connection from: " << new_handler->socket().remote_endpoint().address().to_string() << "\n";
				this->handle_new_connection(new_handler, error);
			});
		}

		void handle_new_https_connection(shared_https_connection_handler_http_t handler, const boost::system::error_code error)
		{
			if (error) { return; }

			handler->start();

			auto new_handler = std::make_shared<http::connection_handler_https>(io_service, ssl_context);

			ssl_acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error)
			{
				std::cout << "accepted a ssl-connection from: " << new_handler->socket().remote_endpoint().address().to_string() << "\n";
				this->handle_new_https_connection(new_handler, error);
			});
		}

		int thread_count;
		int keep_alive_count;
		int keepalive_timeout;

		std::vector<std::thread> thread_pool;

		boost::asio::io_service io_service;
		boost::asio::ip::tcp::acceptor acceptor_;
		boost::asio::ip::tcp::acceptor ssl_acceptor_;

		boost::asio::ssl::context ssl_context;
	};

} // namespace http
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
	class server : public http::basic::server
	{
	private:
		template <class connection_handler_derived, class socket_t> class connection_handler_base : public std::enable_shared_from_this<connection_handler_derived>
		{
		protected:
			asio::io_service& service_;
			asio::io_service::strand write_strand_;
			asio::streambuf in_packet_;
			asio::steady_timer steady_timer_;

			std::deque<std::string> write_buffer_;
			http::session_handler session_handler_;
			server& server_;

		public:
			connection_handler_base(asio::io_service& service, server& server, http::configuration& configuration)
				: service_(service)
				, write_strand_(service)
				, steady_timer_(service)
				, session_handler_(configuration)
				, server_(server)
			{
			}

			~connection_handler_base() = default;

			connection_handler_base(connection_handler_base const&) = delete;
			void operator==(connection_handler_base const&) = delete;

			socket_t& socket_base() { return static_cast<connection_handler_derived*>(this)->socket(); };
			std::string remote_address_base() { return static_cast<connection_handler_derived*>(this)->remote_address(); };


			void stop() {}

			void set_timeout()
			{
				steady_timer_.expires_from_now(std::chrono::seconds(session_handler_.keepalive_max()));

				steady_timer_.async_wait([me = this->shared_from_this()](asio::error_code const& ec) {

					if (!ec)
						me->stop();
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
					this->socket_base(), in_packet_,
					"\r\n\r\n", [me = this->shared_from_this()](asio::error_code const& ec, std::size_t bytes_xfer)
				{
					me->do_read_header_done(ec, bytes_xfer);
				});
			}

			void do_read_header_done(asio::error_code const& ec, std::size_t bytes_transferred)
			{
				if (!ec)
				{
					http::request_parser::result_type result;

					std::tie(result, std::ignore) = session_handler_.parse_request(asio::buffers_begin(in_packet_.data()), asio::buffers_begin(in_packet_.data()) + bytes_transferred);

					in_packet_.consume(bytes_transferred);

					if (result == http::request_parser::good)
					{
						this->cancel_timeout();

						session_handler_.request().set("Remote_Addr", this->remote_address_base());					

						if (session_handler_.request().has_content_lenght())
						{
							this->session_handler_.request().body() += std::string(asio::buffers_begin(in_packet_.data()), asio::buffers_end(in_packet_.data()));
							auto s = asio::buffers_end(in_packet_.data()) - asio::buffers_begin(in_packet_.data());

							in_packet_.consume(s);

							this->session_handler_.request().body().reserve(session_handler_.request().content_length());

							do_read_body();
						}
						else
						{
							session_handler_.handle_request(server_.router_);
							server_.manager().requests_handled(server_.manager().requests_handled() + 1);
							server_.manager().log_access(session_handler_);

							do_write_header();
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
				auto t = this->session_handler_.request().body().size();
				if (this->session_handler_.request().body().size() < this->session_handler_.request().content_length())
				{
					asio::async_read(
						this->socket_base(), in_packet_, asio::transfer_at_least(1), [me = this->shared_from_this()](asio::error_code const& ec, std::size_t bytes_xfer)
					{			
						auto content_length = me->session_handler_.request().content_length();
						auto body_size = me->session_handler_.request().body().length();
						
						size_t chunk_size = asio::buffers_end(me->in_packet_.data()) - asio::buffers_begin(me->in_packet_.data());

						if (content_length - body_size < chunk_size)							
							chunk_size = content_length - body_size;


						std::string chunk = std::string(asio::buffers_begin(me->in_packet_.data()), asio::buffers_begin(me->in_packet_.data()) + chunk_size);

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

			void do_read_body_done(asio::error_code const& ec, std::size_t bytes_transferred)
			{
				if (!ec)
				{
					session_handler_.handle_request(server_.router_);
					server_.manager().requests_handled(server_.manager().requests_handled() + 1);
					server_.manager().log_access(session_handler_);

					do_write_header();
				}
			}

			void do_write_body()
			{
				if (!session_handler_.response().body().empty())
				{
					asio::error_code ec;
					std::string& body = session_handler_.response().body();
					asio::write(socket_base(), asio::buffer(session_handler_.response().body()), ec);

					do_write_content_done();
				}
				else
				{
					auto result = http::util::read_from_disk(
						session_handler_.request().target(), [this, chunked = session_handler_.response().chunked()](std::array<char, 8192> & buffer, size_t bytes_in)
					{
						std::stringstream ss;

						if (!chunked)
						{
							ss << std::string(buffer.begin(), buffer.begin() + bytes_in);

							asio::write(socket_base(), asio::buffer(ss.str()));

							if (bytes_in != buffer.size())
								do_write_content_done();
						}
						else
						{
							std::stringstream ss;
							ss << std::hex << bytes_in << misc_strings::crlf << std::string(buffer.begin(), buffer.begin() + bytes_in) << misc_strings::crlf;

							if (bytes_in == buffer.size())
							{
								asio::write(socket_base(), asio::buffer(ss.str()));
							}
							else
							{
								asio::write(socket_base(), asio::buffer(ss.str()));

								ss.str("");
								ss << std::hex << 0 << misc_strings::crlf;

								asio::write(socket_base(), asio::buffer(ss.str()));
								do_write_content_done();
							}
						}

						return true;
					});
				}
			}

			void do_write_content_done()
			{
				do_write_header_done();
			}

			void do_write_header()
			{
				if ((session_handler_.request().http_version11() == true && session_handler_.keepalive_count() > 1 && session_handler_.request().connection_close() == false)
					|| (session_handler_.request().http_version11() == false && session_handler_.request().connection_keep_alive() && session_handler_.keepalive_count() > 1
						&& session_handler_.request().connection_close() == false))
				{
					session_handler_.keepalive_count(session_handler_.keepalive_count() - 1);
					session_handler_.response().set("Connection", "Keep-Alive");
					//session_handler_.response().set("Keep-Alive", std::string("timeout=") + std::to_string(session_handler_.keepalive_max()) + ", max="  + std::to_string(session_handler_.keepalive_count()));
				}
				else
				{
					session_handler_.response().set("Connection", "close");
				}

				write_buffer_.emplace_back(session_handler_.response().header_to_string());

				asio::async_write(
					socket_base(), asio::buffer(this->write_buffer_.front()),
					write_strand_.wrap([this, me = this->shared_from_this()](asio::error_code ec, std::size_t) {
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
					//socket().shutdown(asio::ip::tcp::socket::shutdown_both);
				}
			}
		};



		class connection_handler_http : public server::connection_handler_base<connection_handler_http, asio::ip::tcp::socket>
		{
		public:
			connection_handler_http(asio::io_service& service, server& server, http::configuration& configuration)
				: connection_handler_base(service, server, configuration)
				, socket_(service)
			{
			}

			asio::ip::tcp::socket& socket() { return socket_; }

			std::string remote_address() 
            {
                asio::error_code ec;
                
                try
                {
                    std::string ret = socket_.remote_endpoint().address().to_string(ec);

                    if (ec)
                        ret = "?";

                    return ret;
                }
                catch(...)
                {
                    return "-";
                }
            }

			void start()
			{
				set_timeout();
				do_read_header();
			}

			void stop() { this->socket_.close(); }

		private:
			asio::ip::tcp::socket socket_;
		};

		class connection_handler_https : public server::connection_handler_base<connection_handler_https, asio::ssl::stream<asio::ip::tcp::socket>>
		{

		public:
			connection_handler_https(asio::io_service& service, server& server, http::configuration& configuration, asio::ssl::context& ssl_context)
				: connection_handler_base(service, server, configuration)
				, ssl_context_(ssl_context)
				, socket_(service, ssl_context)
			{
			}

			asio::ssl::stream<asio::ip::tcp::socket>& socket() { return socket_; };

			std::string remote_address() { return socket_.lowest_layer().remote_endpoint().address().to_string(); }

			void start()
			{

				socket_.async_handshake(asio::ssl::stream_base::server, [me = this->shared_from_this()](asio::error_code const& ec) {
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
			asio::ssl::context& ssl_context_;
			asio::ssl::stream<asio::ip::tcp::socket> socket_;
		};

		using shared_connection_handler_http_t = std::shared_ptr<server::connection_handler_http>;
		using shared_https_connection_handler_http_t = std::shared_ptr<server::connection_handler_https>;

	public:
		server(http::configuration& configuration)
			: http::basic::server{ configuration }
			, thread_count_(configuration.get<int>("thread_count", 5))
			, listen_port_(0)
			, listen_port_begin_(
				  configuration.get<int>("listen_port", (getenv("PORT_NUMBER") ? atoi(getenv("PORT_NUMBER")) : 3000)))
			, listen_port_end_(configuration.get<int>("listen_port_end", listen_port_begin_))
			, connection_timeout_(configuration.get<int>("keepalive_timeout", 4))
			, gzip_min_length_(configuration.get<size_t>("gzip_min_length", 1024 * 10))
			, acceptor_(io_service)
			, ssl_acceptor_(io_service)
			, ssl_context(asio::ssl::context::tlsv12)
		{
			//ssl_context.use_certificate_chain_file(configuration_.get("ssl_certificate"));
			//ssl_context.use_private_key_file(configuration_.get("ssl_certificate_key"), asio::ssl::context::pem);

			if (configuration_.get("ssl_certificate_verify").size() > 0)
			{
				ssl_context.load_verify_file(configuration_.get("ssl_certificate_verify"));
				ssl_context.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert | asio::ssl::verify_client_once);
				// set_session_id_context = true;
			}
		}

		void start_server()
		{
			//auto https_handler = std::make_shared<server::connection_handler_https>(io_service, *this, configuration_, ssl_context);
			//asio::ip::tcp::endpoint https_endpoint(asio::ip::tcp::v6(), listen_port_begin_+1);
			//ssl_acceptor_.open(https_endpoint.protocol());
			//ssl_acceptor_.bind(https_endpoint);
			//ssl_acceptor_.listen();

			auto http_handler = std::make_shared<server::connection_handler_http>(io_service, *this, configuration_);

			asio::ip::tcp::endpoint http_endpoint(asio::ip::tcp::v6(), listen_port_begin_);

			acceptor_.open(http_endpoint.protocol());

			if (listen_port_begin_ == listen_port_end_)
			{
				acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
			}
			
			asio::error_code ec;
			acceptor_.bind(http_endpoint, ec);

			if ((ec == asio::error::address_in_use) && (listen_port_begin_ < listen_port_end_))
			{
				for (listen_port_ = listen_port_begin_; listen_port_ <= listen_port_end_;)
				{
					http_endpoint.port(listen_port_);
					acceptor_.close();
					acceptor_.open(http_endpoint.protocol());
					acceptor_.bind(http_endpoint, ec);
					if (ec)
					{
						listen_port_++;
						continue;						
					}
					else
						break;
				}
			}

			if (ec)
				throw std::runtime_error(std::string("cannot bind/listen to port in range: [ " + std::to_string(listen_port_begin_) + ":" + std::to_string(listen_port_end_) + " ]"));

			acceptor_.listen();


			acceptor_.async_accept(http_handler->socket(), [this, http_handler](auto error) { this->handle_new_connection(http_handler, error); });

			for (auto i = 0; i < thread_count_; ++i)
			{
				thread_pool.emplace_back([this] { io_service.run(); });
			}

			/*ssl_acceptor_.async_accept(
				https_handler->socket().lowest_layer(), [this, https_handler](auto error) { this->handle_new_https_connection(https_handler, error); });
			*/



			/*for (auto i = 0; i < thread_count_; ++i)
			{
				thread_pool[i].join();
			}*/
		}

	private:
		void handle_new_connection(shared_connection_handler_http_t handler, const asio::error_code error)
		{
			if (error)
			{
				return;
			}

			auto current_connections = server_manager().connections_current();
			server_manager().connections_accepted(server_manager().connections_accepted() + 1);
			server_manager().connections_current(current_connections + 1);

			handler->start();

			auto new_handler = std::make_shared<server::connection_handler_http>(io_service, *this, configuration_);

			acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error) { this->handle_new_connection(new_handler, error); });
		}

		void handle_new_https_connection(shared_https_connection_handler_http_t handler, const asio::error_code error)
		{
			if (error)
			{
				return;
			}

			handler->start();

			auto new_handler = std::make_shared<server::connection_handler_https>(io_service,  *this, configuration_, ssl_context);

			ssl_acceptor_.async_accept(
				new_handler->socket().lowest_layer(), [this, new_handler](auto error) { this->handle_new_https_connection(new_handler, error); });
		}

		int thread_count_;
		int listen_port_begin_;
		int listen_port_end_;
		int listen_port_;
		int connection_timeout_;
		size_t gzip_min_length_;

		asio::io_service io_service;
		asio::ip::tcp::acceptor acceptor_;
		asio::ip::tcp::acceptor ssl_acceptor_;
		asio::ssl::context ssl_context;
		std::vector<std::thread> thread_pool;
	};

} // basic
} // async
} // namespace http

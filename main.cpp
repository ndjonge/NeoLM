#include <memory>
#include <chrono>
#include <iostream>
#include <fstream>

#include <thread>
#include <deque>

#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>

namespace http
{
	namespace status_strings
	{
		const char ok[] = "HTTP/1.0 200 OK\r\n";
		const char created[]  = "HTTP/1.0 201 Created\r\n";
		const char accepted[] = "HTTP/1.0 202 Accepted\r\n";
		const char no_content[] = "HTTP/1.0 204 No Content\r\n";
		const char multiple_choices[] = "HTTP/1.0 300 Multiple Choices\r\n";
		const char moved_permanently[] = "HTTP/1.0 301 Moved Permanently\r\n";
		const char moved_temporarily[] = "HTTP/1.0 302 Moved Temporarily\r\n";
		const char not_modified[] = "HTTP/1.0 304 Not Modified\r\n";
		const char bad_request[] = "HTTP/1.0 400 Bad Request\r\n";
		const char unauthorized[] = "HTTP/1.0 401 Unauthorized\r\n";
		const char forbidden[] = "HTTP/1.0 403 Forbidden\r\n";
		const char not_found[] = "HTTP/1.0 404 Not Found\r\n";
		const char internal_server_error[] = "HTTP/1.0 500 Internal Server Error\r\n";
		const char not_implemented[] = "HTTP/1.0 501 Not Implemented\r\n";
		const char bad_gateway[] = "HTTP/1.0 502 Bad Gateway\r\n";
		const char service_unavailable[] = "HTTP/1.0 503 Service Unavailable\r\n";
	}

	namespace misc_strings
	{

		const char name_value_separator[] = { ':', ' ' };
		const char crlf[] = { '\r', '\n' };

	} // namespace misc_strings

	namespace stock_replies
	{

		const char ok[] = "";
		const char created[] =
			"<html>"
			"<head><title>Created</title></head>"
			"<body><h1>201 Created</h1></body>"
			"</html>";
		const char accepted[] =
			"<html>"
			"<head><title>Accepted</title></head>"
			"<body><h1>202 Accepted</h1></body>"
			"</html>";
		const char no_content[] =
			"<html>"
			"<head><title>No Content</title></head>"
			"<body><h1>204 Content</h1></body>"
			"</html>";
		const char multiple_choices[] =
			"<html>"
			"<head><title>Multiple Choices</title></head>"
			"<body><h1>300 Multiple Choices</h1></body>"
			"</html>";
		const char moved_permanently[] =
			"<html>"
			"<head><title>Moved Permanently</title></head>"
			"<body><h1>301 Moved Permanently</h1></body>"
			"</html>";
		const char moved_temporarily[] =
			"<html>"
			"<head><title>Moved Temporarily</title></head>"
			"<body><h1>302 Moved Temporarily</h1></body>"
			"</html>";
		const char not_modified[] =
			"<html>"
			"<head><title>Not Modified</title></head>"
			"<body><h1>304 Not Modified</h1></body>"
			"</html>";
		const char bad_request[] =
			"<html>"
			"<head><title>Bad Request</title></head>"
			"<body><h1>400 Bad Request</h1></body>"
			"</html>";
		const char unauthorized[] =
			"<html>"
			"<head><title>Unauthorized</title></head>"
			"<body><h1>401 Unauthorized</h1></body>"
			"</html>";
		const char forbidden[] =
			"<html>"
			"<head><title>Forbidden</title></head>"
			"<body><h1>403 Forbidden</h1></body>"
			"</html>";
		const char not_found[] =
			"<html>"
			"<head><title>Not Found</title></head>"
			"<body><h1>404 Not Found</h1></body>"
			"</html>";
		const char internal_server_error[] =
			"<html>"
			"<head><title>Internal Server Error</title></head>"
			"<body><h1>500 Internal Server Error</h1></body>"
			"</html>";
		const char not_implemented[] =
			"<html>"
			"<head><title>Not Implemented</title></head>"
			"<body><h1>501 Not Implemented</h1></body>"
			"</html>";
		const char bad_gateway[] =
			"<html>"
			"<head><title>Bad Gateway</title></head>"
			"<body><h1>502 Bad Gateway</h1></body>"
			"</html>";
		const char service_unavailable[] =
			"<html>"
			"<head><title>Service Unavailable</title></head>"
			"<body><h1>503 Service Unavailable</h1></body>"
			"</html>";

	} // namespace stock_replies



	class header
	{
	public:
		header() = default;

		std::string name;
		std::string value;
	};

	class request
	{
	public:
		std::string method;
		std::string uri;
		int http_version_major;
		int http_version_minor;
		std::vector<http::header> headers;
	};

	class request_parser
	{
	public:
		request_parser() : state_(method_start) {};

		void reset()
		{
			state_ = method_start;
		};

		enum result_type { good, bad, indeterminate };

		template <typename InputIterator> std::tuple<result_type, InputIterator> parse(http::request& req, InputIterator begin, InputIterator end)
		{
			while (begin != end)
			{
				result_type result = consume(req, *begin++);

				if (result == good || result == bad)
					return std::make_tuple(result, begin);
			}

			return std::make_tuple(indeterminate, begin);
		}

	private:
		result_type consume(http::request& req, char input)
		{
			switch (state_)
			{
			case method_start:
				if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					state_ = method;
					req.method.push_back(input);
					return indeterminate;
				}
			case method:
				if (input == ' ')
				{
					state_ = uri;
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					req.method.push_back(input);
					return indeterminate;
				}
			case uri:
				if (input == ' ')
				{
					state_ = http_version_h;
					return indeterminate;
				}
				else if (is_ctl(input))
				{
					return bad;
				}
				else
				{
					req.uri.push_back(input);
					return indeterminate;
				}
			case http_version_h:
				if (input == 'H')
				{
					state_ = http_version_t_1;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_t_1:
				if (input == 'T')
				{
					state_ = http_version_t_2;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_t_2:
				if (input == 'T')
				{
					state_ = http_version_p;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_p:
				if (input == 'P')
				{
					state_ = http_version_slash;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_slash:
				if (input == '/')
				{
					req.http_version_major = 0;
					req.http_version_minor = 0;
					state_ = http_version_major_start;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_major_start:
				if (is_digit(input))
				{
					req.http_version_major = req.http_version_major * 10 + input - '0';
					state_ = http_version_major;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_major:
				if (input == '.')
				{
					state_ = http_version_minor_start;
					return indeterminate;
				}
				else if (is_digit(input))
				{
					req.http_version_major = req.http_version_major * 10 + input - '0';
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_minor_start:
				if (is_digit(input))
				{
					req.http_version_minor = req.http_version_minor * 10 + input - '0';
					state_ = http_version_minor;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case http_version_minor:
				if (input == '\r')
				{
					state_ = expecting_newline_1;
					return indeterminate;
				}
				else if (is_digit(input))
				{
					req.http_version_minor = req.http_version_minor * 10 + input - '0';
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case expecting_newline_1:
				if (input == '\n')
				{
					state_ = header_line_start;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case header_line_start:
				if (input == '\r')
				{
					state_ = expecting_newline_3;
					return indeterminate;
				}
				else if (!req.headers.empty() && (input == ' ' || input == '\t'))
				{
					state_ = header_lws;
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					req.headers.push_back(http::header());
					req.headers.back().name.push_back(input);
					state_ = header_name;
					return indeterminate;
				}
			case header_lws:
				if (input == '\r')
				{
					state_ = expecting_newline_2;
					return indeterminate;
				}
				else if (input == ' ' || input == '\t')
				{
					return indeterminate;
				}
				else if (is_ctl(input))
				{
					return bad;
				}
				else
				{
					state_ = header_value;
					req.headers.back().value.push_back(input);
					return indeterminate;
				}
			case header_name:
				if (input == ':')
				{
					state_ = space_before_header_value;
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					req.headers.back().name.push_back(input);
					return indeterminate;
				}
			case space_before_header_value:
				if (input == ' ')
				{
					state_ = header_value;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case header_value:
				if (input == '\r')
				{
					state_ = expecting_newline_2;
					return indeterminate;
				}
				else if (is_ctl(input))
				{
					return bad;
				}
				else
				{
					req.headers.back().value.push_back(input);
					return indeterminate;
				}
			case expecting_newline_2:
				if (input == '\n')
				{
					state_ = header_line_start;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case expecting_newline_3:
				return (input == '\n') ? good : bad;
			default:
				return bad;
			}
		}

		/// Check if a byte is an HTTP character.
		static bool is_char(int c)
		{
			return c >= 0 && c <= 127;
		}

		/// Check if a byte is an HTTP control character.
		static bool is_ctl(int c)
		{
			return (c >= 0 && c <= 31) || (c == 127);
		}
		/// Check if a byte is defined as an HTTP tspecial character.
		static bool is_tspecial(int c)
		{
			switch (c)
			{
			case '(': case ')': case '<': case '>': case '@':
			case ',': case ';': case ':': case '\\': case '"':
			case '/': case '[': case ']': case '?': case '=':
			case '{': case '}': case ' ': case '\t':
				return true;
			default:
				return false;
			}
		}

		/// Check if a byte is a digit.
		static bool is_digit(int c)
		{
			return c >= '0' && c <= '9';
		}

		/// The current state of the parser.
		enum state
		{
			method_start,
			method,
			uri,
			http_version_h,
			http_version_t_1,
			http_version_t_2,
			http_version_p,
			http_version_slash,
			http_version_major_start,
			http_version_major,
			http_version_minor_start,
			http_version_minor,
			expecting_newline_1,
			header_line_start,
			header_lws,
			header_name,
			space_before_header_value,
			header_value,
			expecting_newline_2,
			expecting_newline_3
		} state_;
	};


	class reply
	{
	public:
		reply() = default;

		/// The status of the reply.
		enum status_type
		{
			ok = 200,
			created = 201,
			accepted = 202,
			no_content = 204,
			multiple_choices = 300,
			moved_permanently = 301,
			moved_temporarily = 302,
			not_modified = 304,
			bad_request = 400,
			unauthorized = 401,
			forbidden = 403,
			not_found = 404,
			internal_server_error = 500,
			not_implemented = 501,
			bad_gateway = 502,
			service_unavailable = 503
		} status;



		/// Convert the reply into a vector of buffers. The buffers do not own the
		/// underlying memory blocks, therefore the reply object must remain valid and
		/// not be changed until the write operation has completed.
		std::vector<boost::asio::const_buffer> to_buffers()
		{
			std::vector<boost::asio::const_buffer> buffers;
			buffers.push_back(http::reply::to_buffer(status));
			for (std::size_t i = 0; i < headers.size(); ++i)
			{
				http::header& h = headers[i];
				buffers.push_back(boost::asio::buffer(h.name));
				buffers.push_back(boost::asio::buffer(misc_strings::name_value_separator));
				buffers.push_back(boost::asio::buffer(h.value));
				buffers.push_back(boost::asio::buffer(misc_strings::crlf));
			}
			buffers.push_back(boost::asio::buffer(misc_strings::crlf));
			buffers.push_back(boost::asio::buffer(content));
			return buffers;
		};

		/// The headers to be included in the reply.
		std::vector<http::header> headers;

		/// The content to be sent in the reply.
		std::string content;

		/// Get a stock reply.
		static http::reply stock_reply(http::reply::status_type status)
		{
			http::reply reply;
			reply.status = status;
			reply.content = to_string(status);
			reply.headers.resize(2);
			reply.headers[0].name = "Content-Length";
			reply.headers[0].value = std::to_string(reply.content.size());
			reply.headers[1].name = "Content-Type";
			reply.headers[1].value = "text/html";
			return reply;
		}

	private:

		static std::string to_string(http::reply::status_type status)
		{
			switch (status)
			{
			case http::reply::ok:
				return http::status_strings::ok;
			case http::reply::created:
				return http::status_strings::created;
			case http::reply::accepted:
				return http::status_strings::accepted;
			case http::reply::no_content:
				return http::status_strings::no_content;
			case http::reply::multiple_choices:
				return http::status_strings::multiple_choices;
			case http::reply::moved_permanently:
				return http::status_strings::moved_permanently;
			case http::reply::moved_temporarily:
				return http::status_strings::moved_temporarily;
			case http::reply::not_modified:
				return http::status_strings::not_modified;
			case http::reply::bad_request:
				return http::status_strings::bad_request;
			case http::reply::unauthorized:
				return http::status_strings::unauthorized;
			case http::reply::forbidden:
				return http::status_strings::forbidden;
			case http::reply::not_found:
				return http::status_strings::not_found;
			case http::reply::internal_server_error:
				return http::status_strings::internal_server_error;
			case http::reply::not_implemented:
				return http::status_strings::not_implemented;
			case http::reply::bad_gateway:
				return http::status_strings::bad_gateway;
			case http::reply::service_unavailable:
				return http::status_strings::service_unavailable;
			default:
				return http::status_strings::internal_server_error;
			}
		}


		static boost::asio::const_buffer to_buffer(http::reply::status_type status)
		{
			switch (status)
			{
			case http::reply::ok:
				return boost::asio::buffer(http::status_strings::ok);
			case http::reply::created:
				return boost::asio::buffer(http::status_strings::created);
			case http::reply::accepted:
				return boost::asio::buffer(http::status_strings::accepted);
			case http::reply::no_content:
				return boost::asio::buffer(http::status_strings::no_content);
			case http::reply::multiple_choices:
				return boost::asio::buffer(http::status_strings::multiple_choices);
			case http::reply::moved_permanently:
				return boost::asio::buffer(http::status_strings::moved_permanently);
			case http::reply::moved_temporarily:
				return boost::asio::buffer(http::status_strings::moved_temporarily);
			case http::reply::not_modified:
				return boost::asio::buffer(http::status_strings::not_modified);
			case http::reply::bad_request:
				return boost::asio::buffer(http::status_strings::bad_request);
			case http::reply::unauthorized:
				return boost::asio::buffer(http::status_strings::unauthorized);
			case http::reply::forbidden:
				return boost::asio::buffer(http::status_strings::forbidden);
			case http::reply::not_found:
				return boost::asio::buffer(http::status_strings::not_found);
			case http::reply::internal_server_error:
				return boost::asio::buffer(http::status_strings::internal_server_error);
			case http::reply::not_implemented:
				return boost::asio::buffer(http::status_strings::not_implemented);
			case http::reply::bad_gateway:
				return boost::asio::buffer(http::status_strings::bad_gateway);
			case http::reply::service_unavailable:
				return boost::asio::buffer(http::status_strings::service_unavailable);
			default:
				return boost::asio::buffer(http::status_strings::internal_server_error);
			}
		}
	};

	namespace mime_types
	{
		struct mapping
		{
			const char* extension;
			const char* mime_type;
		}

		mappings[] =
		{
			{ "gif", "image/gif" },
			{ "htm", "text/html" },
			{ "html", "text/html" },
			{ "jpg", "image/jpeg" },
			{ "png", "image/png" }
		};

		std::string extension_to_type(const std::string& extension)
		{
			for (mapping m : mappings)
			{
				if (m.extension == extension)
				{
					return m.mime_type;
				}
			}

			return "text/plain";
		}
	} // namespace mime_types

	class request_handler
	{
	public:
		request_handler(const request_handler&) = delete;
		request_handler& operator=(const request_handler&) = delete;

		/// Construct with a directory containing files to be served.
		explicit request_handler(const std::string& doc_root) : doc_root_(doc_root)
		{
		}

		/// Handle a request and produce a reply.
		void handle_request(const http::request& request, http::reply& reply)
		{
			// Decode url to path.
			std::string request_path;

			if (!url_decode(request.uri, request_path))
			{
				reply = http::reply::stock_reply(http::reply::bad_request);
				return;
			}

			// Request path must be absolute and not contain "..".
			if (request_path.empty() || request_path[0] != '/'
				|| request_path.find("..") != std::string::npos)
			{
				reply = http::reply::stock_reply(http::reply::bad_request);
				return;
			}

			// If path ends in slash (i.e. is a directory) then add "index.html".
			if (request_path[request_path.size() - 1] == '/')
			{
				request_path += "index.html";
			}

			// Determine the file extension.
			std::size_t last_slash_pos = request_path.find_last_of("/");
			std::size_t last_dot_pos = request_path.find_last_of(".");
			std::string extension;
			if (last_dot_pos != std::string::npos && last_dot_pos > last_slash_pos)
			{
				extension = request_path.substr(last_dot_pos + 1);
			}

			// Open the file to send back.
			std::string full_path = doc_root_ + request_path;
			std::ifstream is(full_path.c_str(), std::ios::in | std::ios::binary);
			if (!is)
			{
				reply = http::reply::stock_reply(http::reply::not_found);
				return;
			}

			// Fill out the reply to be sent to the client.
			reply.status = http::reply::ok;
			char buf[512];
			while (is.read(buf, sizeof(buf)).gcount() > 0)
				reply.content.append(buf, is.gcount());
			reply.headers.resize(2);
			reply.headers[0].name = "Content-Length";
			reply.headers[0].value = std::to_string(reply.content.size());
			reply.headers[1].name = "Content-Type";
			reply.headers[1].value = mime_types::extension_to_type(extension);
		}

	private:
		/// The directory containing the files to be served.
		std::string doc_root_;

		/// Perform URL-decoding on a string. Returns false if the encoding was
		/// invalid.
		static bool url_decode(const std::string& in, std::string& out)
		{
			out.clear();
			out.reserve(in.size());
			for (std::size_t i = 0; i < in.size(); ++i)
			{
				if (in[i] == '%')
				{
					if (i + 3 <= in.size())
					{
						int value = 0;
						std::istringstream is(in.substr(i + 1, 2));
						if (is >> std::hex >> value)
						{
							out += static_cast<char>(value);
							i += 2;
						}
						else
						{
							return false;
						}
					}
					else
					{
						return false;
					}
				}
				else if (in[i] == '+')
				{
					out += ' ';
				}
				else
				{
					out += in[i];
				}
			}
			return true;
		}
	};

	class ssl_client_connection_handler : public std::enable_shared_from_this<http::ssl_client_connection_handler>
	{
		using ssl_socket_t = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
	public:
		ssl_client_connection_handler(boost::asio::io_service& service, boost::asio::ssl::context& ssl_context) : service_(service), ssl_socket_(service, ssl_context), write_strand_(service), request_handler_("C:\\temp")
		{
		}

		http::ssl_client_connection_handler(http::ssl_client_connection_handler const &) = delete;
		void operator==(http::ssl_client_connection_handler const &) = delete;
		~ssl_client_connection_handler() = default;

		ssl_socket_t::lowest_layer_type& socket()
		{
			return ssl_socket_.lowest_layer();
		}

		void start()
		{
			ssl_socket_.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true));

			ssl_socket_.async_handshake(boost::asio::ssl::stream_base::server, [me = shared_from_this()](boost::system::error_code const& ec)
			{
				if (ec)
				{
					std::cout << ec.message() << std::endl;
				}
				else
				{
					me->do_read();
				}
			});
		}

		void do_read()
		{
			boost::asio::async_read_until(ssl_socket_, in_packet_, "\r\n\r\n",
				[me = shared_from_this()](boost::system::error_code const& ec, std::size_t bytes_xfer)
			{
				//if (ec)
				//{
				//	std::cout << ec.message() << std::endl;
					me->do_read_done(ec, bytes_xfer);
				//}
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
					request_handler_.handle_request(request_, reply_);

					do_write();
				}
				else if (result == http::request_parser::bad)
				{
					reply_ = http::reply::stock_reply(http::reply::bad_request);
					do_write();
				}
				else
				{
					do_read();
				}
			}
			else if (ec != boost::asio::error::operation_aborted)
			{
				//connection_manager_.stop(shared_from_this());
			}

		}

		void do_write()
		{
			boost::asio::async_write(ssl_socket_, reply_.to_buffers(), write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
			{
				if (ec != boost::asio::error::operation_aborted)
				{
					me->do_write_done(ec);
				}
			}));
		}

		void do_write_done(boost::system::error_code const & error)
		{
			if (!error)
			{
				/*			send_packet_queue_.pop_front();
				if (!send_packet_queue_.empty()) { this->start_packet_send(); }*/
			}
		}

	private:
		boost::asio::io_service& service_;
//		boost::asio::ip::tcp::socket socket_;

		boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_;

		boost::asio::io_service::strand write_strand_;
		boost::asio::streambuf in_packet_;

		/// The handler used to process the incoming request.
		http::request_handler request_handler_;

		/// Buffer for incoming data.
		std::array<char, 8192> buffer_;

		/// The incoming request.
		http::request request_;

		/// The parser for the incoming request.
		http::request_parser request_parser_;

		/// The reply to be sent back to the client.
		http::reply reply_;

	};

	class client_connection_handler : public std::enable_shared_from_this<http::client_connection_handler>
	{
	public:
		client_connection_handler(boost::asio::io_service& service) : service_(service), socket_(service), write_strand_(service), request_handler_("C:\\temp")
		{
		}

		http::client_connection_handler(http::client_connection_handler const &) = delete;
		void operator==(http::client_connection_handler const &) = delete;
		~client_connection_handler() = default;

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
			boost::asio::async_read_until(socket_, in_packet_, '\n',
				[me=shared_from_this()](boost::system::error_code const& ec, std::size_t bytes_xfer)
			{
				me->do_read_done(ec, bytes_xfer);
			});
		}

		void do_read_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
		{
			if (!ec)
			{
				http::request_parser::result_type result;

				std::tie(result, std::ignore) = request_parser_.parse(request_, boost::asio::buffers_begin(in_packet_.data()), boost::asio::buffers_begin(in_packet_.data())+ bytes_transferred);

				in_packet_.consume(bytes_transferred);


				if (result == http::request_parser::good)
				{
					request_handler_.handle_request(request_, reply_);

					do_write();
				}
				else if (result == http::request_parser::bad)
				{
					reply_ = http::reply::stock_reply(http::reply::bad_request);
					do_write();
				}
				else
				{
					do_read();
				}
			}
			else if (ec != boost::asio::error::operation_aborted)
			{
				//connection_manager_.stop(shared_from_this());
			}

		}

		void do_write()
		{
			boost::asio::async_write(socket_, reply_.to_buffers(), write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
			{
				if (ec != boost::asio::error::operation_aborted)
				{
					me->do_write_done(ec);
				}
			}));
		}

		void do_write_done(boost::system::error_code const & error)
		{
			if (!error)
			{
				/*			send_packet_queue_.pop_front();
				if (!send_packet_queue_.empty()) { this->start_packet_send(); }*/
			}
		}

	private:
		boost::asio::io_service& service_;
		boost::asio::ip::tcp::socket socket_;

		boost::asio::io_service::strand write_strand_;
		boost::asio::streambuf in_packet_;

		/// The handler used to process the incoming request.
		http::request_handler request_handler_;

		/// Buffer for incoming data.
		std::array<char, 8192> buffer_;

		/// The incoming request.
		http::request request_;

		/// The parser for the incoming request.
		http::request_parser request_parser_;

		/// The reply to be sent back to the client.
		http::reply reply_;

	};





	template <typename client_connection_handler_t, typename ssl_connection_handler_t> class server
	{
		using shared_client_connection_handler_t = std::shared_ptr<http::client_connection_handler>;
		using shared_https_client_connection_handler_t = std::shared_ptr<http::ssl_client_connection_handler>;

	public:
		server(const std::string &cert_file, const std::string &private_key_file, const std::string &verify_file = std::string(), int thread_count = 10) : thread_count(thread_count), acceptor_(io_service), ssl_acceptor_(io_service), ssl_context(io_service, boost::asio::ssl::context::tlsv12)
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



			auto http_handler = std::make_shared<http::client_connection_handler>(io_service);
			auto https_handler = std::make_shared<http::ssl_client_connection_handler>(io_service, ssl_context);

			boost::asio::ip::tcp::endpoint http_endpoint(boost::asio::ip::tcp::v4(),  60005);
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
		void handle_new_connection(shared_client_connection_handler_t handler, const boost::system::error_code error)
		{
			if (error) { return; }

			handler->start();

			auto new_handler = std::make_shared<http::client_connection_handler>(io_service);

			acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error)
			{
				this->handle_new_connection(new_handler, error);
			});
		}

		void handle_new_https_connection(shared_https_client_connection_handler_t handler, const boost::system::error_code error)
		{
			if (error) { return; }

			handler->start();

			auto new_handler = std::make_shared<http::ssl_client_connection_handler>(io_service, ssl_context);

			ssl_acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error)
			{
				this->handle_new_https_connection(new_handler, error);
			});
		}

		int thread_count;
		std::vector<std::thread> thread_pool;

		boost::asio::io_service io_service;
		boost::asio::ip::tcp::acceptor acceptor_;
		boost::asio::ip::tcp::acceptor ssl_acceptor_;

		boost::asio::ssl::context ssl_context;
	};

}


int main(int argc, char* argv[])
{

	http::server<http::client_connection_handler, http::ssl_client_connection_handler> server("C:\\Development Libraries\\ssl.crt", "C:\\Development Libraries\\ssl.key");

	server.start_server();

	return 0;
}


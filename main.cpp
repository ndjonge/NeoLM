#include <boost/asio.hpp>
#include <memory>
#include <chrono>
#include <iostream>
#include <fstream>

#include <thread>
#include <deque>

class http_reply;

namespace http_status_strings
{
	const std::string ok = "HTTP/1.0 200 OK\r\n";
	const std::string created = "HTTP/1.0 201 Created\r\n";
	const std::string accepted = "HTTP/1.0 202 Accepted\r\n";
	const std::string no_content = "HTTP/1.0 204 No Content\r\n";
	const std::string multiple_choices = "HTTP/1.0 300 Multiple Choices\r\n";
	const std::string moved_permanently = "HTTP/1.0 301 Moved Permanently\r\n";
	const std::string moved_temporarily = "HTTP/1.0 302 Moved Temporarily\r\n";
	const std::string not_modified = "HTTP/1.0 304 Not Modified\r\n";
	const std::string bad_request = "HTTP/1.0 400 Bad Request\r\n";
	const std::string unauthorized = "HTTP/1.0 401 Unauthorized\r\n";
	const std::string forbidden = "HTTP/1.0 403 Forbidden\r\n";
	const std::string not_found = "HTTP/1.0 404 Not Found\r\n";
	const std::string internal_server_error = "HTTP/1.0 500 Internal Server Error\r\n";
	const std::string not_implemented = "HTTP/1.0 501 Not Implemented\r\n";
	const std::string bad_gateway = "HTTP/1.0 502 Bad Gateway\r\n";
	const std::string service_unavailable = "HTTP/1.0 503 Service Unavailable\r\n";
}

namespace misc_strings
{

	const char name_value_separator[] = { ':', ' ' };
	const char crlf[] = { '\r', '\n' };

} // namespace misc_strings

namespace http_stock_replies
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



class http_header
{
public:
	http_header() = default;

	std::string name;
	std::string value;
};

class http_request
{
public:
	std::string method;
	std::string uri;
	int http_version_major;
	int http_version_minor;
	std::vector<http_header> headers;
};

class http_request_parser
{
public:
	http_request_parser() : state_(method_start) {};

	void reset() {
		state_ = method_start;
	};

	enum result_type { good, bad, indeterminate };

	template <typename InputIterator> std::tuple<result_type, InputIterator> parse(http_request& req, InputIterator begin, InputIterator end)
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
	result_type consume(http_request& req, char input)
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
					req.headers.push_back(http_header());
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


class http_reply
{
public:
	http_reply() = default;

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
		buffers.push_back(http_reply::to_buffer(status));
		for (std::size_t i = 0; i < headers.size(); ++i)
		{
			http_header& h = headers[i];
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
	std::vector<http_header> headers;

	/// The content to be sent in the reply.
	std::string content;

	/// Get a stock reply.
	static http_reply stock_reply(http_reply::status_type status)
	{
		http_reply reply;
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

	static std::string to_string(http_reply::status_type status)
	{
		switch (status)
		{
		case http_reply::ok:
			return http_status_strings::ok;
		case http_reply::created:
			return http_status_strings::created;
		case http_reply::accepted:
			return http_status_strings::accepted;
		case http_reply::no_content:
			return http_status_strings::no_content;
		case http_reply::multiple_choices:
			return http_status_strings::multiple_choices;
		case http_reply::moved_permanently:
			return http_status_strings::moved_permanently;
		case http_reply::moved_temporarily:
			return http_status_strings::moved_temporarily;
		case http_reply::not_modified:
			return http_status_strings::not_modified;
		case http_reply::bad_request:
			return http_status_strings::bad_request;
		case http_reply::unauthorized:
			return http_status_strings::unauthorized;
		case http_reply::forbidden:
			return http_status_strings::forbidden;
		case http_reply::not_found:
			return http_status_strings::not_found;
		case http_reply::internal_server_error:
			return http_status_strings::internal_server_error;
		case http_reply::not_implemented:
			return http_status_strings::not_implemented;
		case http_reply::bad_gateway:
			return http_status_strings::bad_gateway;
		case http_reply::service_unavailable:
			return http_status_strings::service_unavailable;
		default:
			return http_status_strings::internal_server_error;
		}
	}


	static boost::asio::const_buffer to_buffer(http_reply::status_type status)
	{
		switch (status)
		{
		case http_reply::ok:
			return boost::asio::buffer(http_status_strings::ok);
		case http_reply::created:
			return boost::asio::buffer(http_status_strings::created);
		case http_reply::accepted:
			return boost::asio::buffer(http_status_strings::accepted);
		case http_reply::no_content:
			return boost::asio::buffer(http_status_strings::no_content);
		case http_reply::multiple_choices:
			return boost::asio::buffer(http_status_strings::multiple_choices);
		case http_reply::moved_permanently:
			return boost::asio::buffer(http_status_strings::moved_permanently);
		case http_reply::moved_temporarily:
			return boost::asio::buffer(http_status_strings::moved_temporarily);
		case http_reply::not_modified:
			return boost::asio::buffer(http_status_strings::not_modified);
		case http_reply::bad_request:
			return boost::asio::buffer(http_status_strings::bad_request);
		case http_reply::unauthorized:
			return boost::asio::buffer(http_status_strings::unauthorized);
		case http_reply::forbidden:
			return boost::asio::buffer(http_status_strings::forbidden);
		case http_reply::not_found:
			return boost::asio::buffer(http_status_strings::not_found);
		case http_reply::internal_server_error:
			return boost::asio::buffer(http_status_strings::internal_server_error);
		case http_reply::not_implemented:
			return boost::asio::buffer(http_status_strings::not_implemented);
		case http_reply::bad_gateway:
			return boost::asio::buffer(http_status_strings::bad_gateway);
		case http_reply::service_unavailable:
			return boost::asio::buffer(http_status_strings::service_unavailable);
		default:
			return boost::asio::buffer(http_status_strings::internal_server_error);
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

class http_request_handler
{
public:
	http_request_handler(const http_request_handler&) = delete;
	http_request_handler& operator=(const http_request_handler&) = delete;

	/// Construct with a directory containing files to be served.
	explicit http_request_handler(const std::string& doc_root) : doc_root_(doc_root)
	{
	}

	/// Handle a request and produce a reply.
	void handle_request(const http_request& request, http_reply& reply)
	{
		// Decode url to path.
		std::string request_path;

		if (!url_decode(request.uri, request_path))
		{
			reply = http_reply::stock_reply(http_reply::bad_request);
			return;
		}

		// Request path must be absolute and not contain "..".
		if (request_path.empty() || request_path[0] != '/'
			|| request_path.find("..") != std::string::npos)
		{
			reply = http_reply::stock_reply(http_reply::bad_request);
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
			reply = http_reply::stock_reply(http_reply::not_found);
			return;
		}

		// Fill out the reply to be sent to the client.
		reply.status = http_reply::ok;
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



class http_client_connection_handler : public std::enable_shared_from_this<http_client_connection_handler>
{
public:
	http_client_connection_handler(boost::asio::io_service& service) : service_(service), socket_(service), write_strand_(service), http_request_handler_("C:\\temp")
	{
	}

	http_client_connection_handler(http_client_connection_handler const &) = delete;
	void operator==(http_client_connection_handler const &) = delete;
	~http_client_connection_handler() = default;

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
			[=](boost::system::error_code const& ec, std::size_t bytes_xfer)
		{
			do_read_done(ec, bytes_xfer);
		});
	}

	void do_read_done(boost::system::error_code const& ec, std::size_t bytes_transferred)
	{
		if (!ec)
		{
			std::istream stream(&in_packet_);
			std::string packet_string;
			stream >> packet_string;

			http_request_parser::result_type result;

			std::tie(result, std::ignore) = http_request_parser_.parse(http_request_, buffer_.data(), buffer_.data() + bytes_transferred);


			if (result == http_request_parser::good)
			{
				http_request_handler_.handle_request(http_request_, http_reply_);

				do_write();
			}
			else if (result == http_request_parser::bad)
			{
				http_reply_ = http_reply::stock_reply(http_reply::bad_request);
				do_write();
			}
			else
			{
			do_read();
			}

			do_read();
		}
		else if (ec != boost::asio::error::operation_aborted)
		{
			//connection_manager_.stop(shared_from_this());
		}

	}

	void do_write()
	{
		boost::asio::async_write(socket_, http_reply_.to_buffers(), write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
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
	http_request_handler http_request_handler_;

	/// Buffer for incoming data.
	std::array<char, 8192> buffer_;

	/// The incoming request.
	http_request http_request_;

	/// The parser for the incoming request.
	http_request_parser http_request_parser_;

	/// The reply to be sent back to the client.
	http_reply http_reply_;

};





template <typename http_client_connection_handler> class http_server
{
	using shared_http_client_connection_handler_t = std::shared_ptr<http_client_connection_handler>;

public:
	http_server(int thread_count = 1) : thread_count(thread_count), acceptor_(io_service)
	{
	}

	void start_server(uint16_t port)
	{
		auto handler = std::make_shared<http_client_connection_handler>(io_service);

		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port);
		acceptor_.open(endpoint.protocol());

		acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
		acceptor_.bind(endpoint);
		acceptor_.listen();

        acceptor_.async_accept(handler->socket(), [=](auto error)
        {
			this->handle_new_connection(handler, error);
		});

		for (auto i = 0; i < thread_count; ++i)
		{
			thread_pool.emplace_back([=] { io_service.run(); });
		}
	}

private:
    void handle_new_connection(shared_http_client_connection_handler_t handler, const boost::system::error_code error)
	{
		if (error) { return; }

		handler->start();

		auto new_handler = std::make_shared<http_client_connection_handler>(io_service);

		acceptor_.async_accept(new_handler->socket(), [=](auto error)
		{
			this->handle_new_connection(new_handler, error);
		});
	}
	
    int thread_count;
	std::vector<std::thread> thread_pool;
	boost::asio::io_service io_service;
	boost::asio::ip::tcp::acceptor acceptor_;
};



int main(int argc, char* argv[])
{

	http_server<http_client_connection_handler> server;
	server.start_server(8888);


	for (;;)
	{
	}

	return 0;
}


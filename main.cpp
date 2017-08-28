#include <string>
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
	
	namespace util
	{
		inline bool case_insensitive_equal(const std::string &str1, const std::string &str2) noexcept
		{
			return str1.size() == str2.size() &&
				std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b)
			{
				return tolower(a) == tolower(b);
			});
		}
	}

	namespace status_strings
	{
		namespace http_10
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

		namespace http_11
		{
			const std::string ok = "HTTP/1.1 200 OK\r\n";
			const std::string created = "HTTP/1.1 201 Created\r\n";
			const std::string accepted = "HTTP/1.1 202 Accepted\r\n";
			const std::string no_content = "HTTP/1.1 204 No Content\r\n";
			const std::string multiple_choices = "HTTP/1.1 300 Multiple Choices\r\n";
			const std::string moved_permanently = "HTTP/1.1 301 Moved Permanently\r\n";
			const std::string moved_temporarily = "HTTP/1.1 302 Moved Temporarily\r\n";
			const std::string not_modified = "HTTP/1.1 304 Not Modified\r\n";
			const std::string bad_request = "HTTP/1.1 400 Bad Request\r\n";
			const std::string unauthorized = "HTTP/1.1 401 Unauthorized\r\n";
			const std::string forbidden = "HTTP/1.1 403 Forbidden\r\n";
			const std::string not_found = "HTTP/1.1 404 Not Found\r\n";
			const std::string internal_server_error = "HTTP/1.1 500 Internal Server Error\r\n";
			const std::string not_implemented = "HTTP/1.1 501 Not Implemented\r\n";
			const std::string bad_gateway = "HTTP/1.1 502 Bad Gateway\r\n";
			const std::string service_unavailable = "HTTP/1.1 503 Service Unavailable\r\n";
		}
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

	enum version
	{
		HTTP_10,
		HTTP_11
	};

	class header
	{
	public:
		header() = default;

		header(const std::string&& name, const std::string&& value = "") : name(std::move(name)), value(std::move(value)) {};

		std::string name;
		std::string value;
	};

	class request
	{
	public:
		request() = default;

		void reset()
		{
			method.clear();
			uri.clear();
			headers.clear();

			http_version_major = 0;
			http_version_minor = 0;

		}

		const http::version version() const
		{
			if (http_version_major == 1 && http_version_major == 1)
				return http::version::HTTP_11;
			else 
				return http::version::HTTP_11;
		}


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
			std::stringstream trace;

			while (begin != end)
			{
				/* trace << *begin; */

				result_type result = consume(req, *begin++);

				if (result == good || result == bad)
				{
					/* std::cout << trace.str(); */
					return std::make_tuple(result, begin);
				}
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
		reply() : document_path_ { "" }, keep_alive_ { false }, chunked_encoding_{ false } {};

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

		void reset()
		{
			headers.clear();
			content.clear();
		}

		std::string& document_path() noexcept
		{
			return document_path_;
		}

		bool& keep_alive()
		{
			return keep_alive_;
		}

		bool& chunked_encoding()
		{
			return chunked_encoding_;
		}

		/// Convert the reply into a vector of buffers. The buffers do not own the
		/// underlying memory blocks, therefore the reply object must remain valid and
		/// not be changed until the write operation has completed.
		std::vector<boost::asio::const_buffer> to_buffers()
		{
			std::vector<boost::asio::const_buffer> buffers;

			buffers.push_back(http::reply::to_buffer(status, version));

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

		http::version version;

		/// Get a stock reply.
		static http::reply stock_reply(http::reply::status_type status, http::version version)
		{
			http::reply reply;
			reply.status = status;
			reply.content = to_string(status, version);
			reply.headers.resize(2);
			reply.headers[0].name = "Content-Length";
			reply.headers[0].value = std::to_string(reply.content.size());
			reply.headers[1].name = "Content-Type";
			reply.headers[1].value = "text/html";
			return reply;
		}

	private:
		bool chunked_encoding_;
		bool keep_alive_;
		std::string document_path_;

		static std::string to_string(http::reply::status_type status, http::version version)
		{
			switch (version)
			{
			case HTTP_11:
				switch (status)
				{
					case http::reply::ok:
						return http::status_strings::http_11::ok;
					case http::reply::created:
						return http::status_strings::http_11::created;
					case http::reply::accepted:
						return http::status_strings::http_11::accepted;
					case http::reply::no_content:
						return http::status_strings::http_11::no_content;
					case http::reply::multiple_choices:
						return http::status_strings::http_11::multiple_choices;
					case http::reply::moved_permanently:
						return http::status_strings::http_11::moved_permanently;
					case http::reply::moved_temporarily:
						return http::status_strings::http_11::moved_temporarily;
					case http::reply::not_modified:
						return http::status_strings::http_11::not_modified;
					case http::reply::bad_request:
						return http::status_strings::http_11::bad_request;
					case http::reply::unauthorized:
						return http::status_strings::http_11::unauthorized;
					case http::reply::forbidden:
						return http::status_strings::http_11::forbidden;
					case http::reply::not_found:
						return http::status_strings::http_11::not_found;
					case http::reply::internal_server_error:
						return http::status_strings::http_11::internal_server_error;
					case http::reply::not_implemented:
						return http::status_strings::http_11::not_implemented;
					case http::reply::bad_gateway:
						return http::status_strings::http_11::bad_gateway;
					case http::reply::service_unavailable:
						return http::status_strings::http_11::service_unavailable;
					default:
						return http::status_strings::http_11::internal_server_error;
				}
			default:
				switch (status)
				{
				case http::reply::ok:
					return http::status_strings::http_10::ok;
				case http::reply::created:
					return http::status_strings::http_10::created;
				case http::reply::accepted:
					return http::status_strings::http_10::accepted;
				case http::reply::no_content:
					return http::status_strings::http_10::no_content;
				case http::reply::multiple_choices:
					return http::status_strings::http_10::multiple_choices;
				case http::reply::moved_permanently:
					return http::status_strings::http_10::moved_permanently;
				case http::reply::moved_temporarily:
					return http::status_strings::http_10::moved_temporarily;
				case http::reply::not_modified:
					return http::status_strings::http_10::not_modified;
				case http::reply::bad_request:
					return http::status_strings::http_10::bad_request;
				case http::reply::unauthorized:
					return http::status_strings::http_10::unauthorized;
				case http::reply::forbidden:
					return http::status_strings::http_10::forbidden;
				case http::reply::not_found:
					return http::status_strings::http_10::not_found;
				case http::reply::internal_server_error:
					return http::status_strings::http_10::internal_server_error;
				case http::reply::not_implemented:
					return http::status_strings::http_10::not_implemented;
				case http::reply::bad_gateway:
					return http::status_strings::http_10::bad_gateway;
				case http::reply::service_unavailable:
					return http::status_strings::http_10::service_unavailable;
				default:
					return http::status_strings::http_10::internal_server_error;
				}
			}
		}


		static boost::asio::const_buffer to_buffer(http::reply::status_type status, http::version version)
		{
			switch (version)
			{
			case HTTP_11:
				switch (status)
				{
				case http::reply::ok:
					return boost::asio::buffer(http::status_strings::http_11::ok);
				case http::reply::created:
					return boost::asio::buffer(http::status_strings::http_11::created);
				case http::reply::accepted:
					return boost::asio::buffer(http::status_strings::http_11::accepted);
				case http::reply::no_content:
					return boost::asio::buffer(http::status_strings::http_11::no_content);
				case http::reply::multiple_choices:
					return boost::asio::buffer(http::status_strings::http_11::multiple_choices);
				case http::reply::moved_permanently:
					return boost::asio::buffer(http::status_strings::http_11::moved_permanently);
				case http::reply::moved_temporarily:
					return boost::asio::buffer(http::status_strings::http_11::moved_temporarily);
				case http::reply::not_modified:
					return boost::asio::buffer(http::status_strings::http_11::not_modified);
				case http::reply::bad_request:
					return boost::asio::buffer(http::status_strings::http_11::bad_request);
				case http::reply::unauthorized:
					return boost::asio::buffer(http::status_strings::http_11::unauthorized);
				case http::reply::forbidden:
					return boost::asio::buffer(http::status_strings::http_11::forbidden);
				case http::reply::not_found:
					return boost::asio::buffer(http::status_strings::http_11::not_found);
				case http::reply::internal_server_error:
					return boost::asio::buffer(http::status_strings::http_11::internal_server_error);
				case http::reply::not_implemented:
					return boost::asio::buffer(http::status_strings::http_11::not_implemented);
				case http::reply::bad_gateway:
					return boost::asio::buffer(http::status_strings::http_11::bad_gateway);
				case http::reply::service_unavailable:
					return boost::asio::buffer(http::status_strings::http_11::service_unavailable);
				default:
					return boost::asio::buffer(http::status_strings::http_11::internal_server_error);
				}
			default:
				switch (status)
				{
				case http::reply::ok:
					return boost::asio::buffer(http::status_strings::http_10::ok);
				case http::reply::created:
					return boost::asio::buffer(http::status_strings::http_10::created);
				case http::reply::accepted:
					return boost::asio::buffer(http::status_strings::http_10::accepted);
				case http::reply::no_content:
					return boost::asio::buffer(http::status_strings::http_10::no_content);
				case http::reply::multiple_choices:
					return boost::asio::buffer(http::status_strings::http_10::multiple_choices);
				case http::reply::moved_permanently:
					return boost::asio::buffer(http::status_strings::http_10::moved_permanently);
				case http::reply::moved_temporarily:
					return boost::asio::buffer(http::status_strings::http_10::moved_temporarily);
				case http::reply::not_modified:
					return boost::asio::buffer(http::status_strings::http_10::not_modified);
				case http::reply::bad_request:
					return boost::asio::buffer(http::status_strings::http_10::bad_request);
				case http::reply::unauthorized:
					return boost::asio::buffer(http::status_strings::http_10::unauthorized);
				case http::reply::forbidden:
					return boost::asio::buffer(http::status_strings::http_10::forbidden);
				case http::reply::not_found:
					return boost::asio::buffer(http::status_strings::http_10::not_found);
				case http::reply::internal_server_error:
					return boost::asio::buffer(http::status_strings::http_10::internal_server_error);
				case http::reply::not_implemented:
					return boost::asio::buffer(http::status_strings::http_10::not_implemented);
				case http::reply::bad_gateway:
					return boost::asio::buffer(http::status_strings::http_10::bad_gateway);
				case http::reply::service_unavailable:
					return boost::asio::buffer(http::status_strings::http_10::service_unavailable);
				default:
					return boost::asio::buffer(http::status_strings::http_10::internal_server_error);
				}
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


	template <typename socket_type_t>
	class session
	{
		public:
			session(const socket_type_t& socket, int keepalive_count, int keepalive_max)
				: socket(socket),
				  keepalive_count(keepalive_count), 
				  keepalive_max(keepalive_max) 
			{
			};

			session(const session& rhs) : socket(rhs.socket), keepalive_count(rhs.keepalive_count), keepalive_max(rhs.keepalive_max) 
			{ 
			};

			session& operator=(const session& rhs) = default;

			~session()
			{
			};

			const socket_type_t& socket;
			int keepalive_count;
			int keepalive_max;

	};

	template <typename socket_type_t>
	class request_handler
	{
	public:
		request_handler(const request_handler&) = delete;
		request_handler& operator=(const request_handler&) = delete;

		/// Construct with a directory containing files to be served.
		explicit request_handler(const std::string& doc_root) : doc_root_{ doc_root }
		{
		}

		const std::string date_header_value() const
		{
			std::string returnvalue;

			/// The value to use to format an HTTP date into RFC1123 format.
			static const char DATE_FORMAT[] = { "%a, %d %b %Y %H:%M:%S GMT" };

			char buffer[30];

			time_t now;
			tm	tm;

			time(&now);

			::localtime_s(&tm, &now);

			std::strftime(buffer, 30, DATE_FORMAT, &tm);

			returnvalue = buffer;

			return returnvalue;
		}


		/// Handle a request and produce a reply.
		void handle_request(const http::request& request, http::reply& reply, const session<socket_type_t>& session)
		{
			// Decode url to path.
			std::string request_path;

			if (!url_decode(request.uri, request_path))
			{
				reply = http::reply::stock_reply(http::reply::bad_request, request.version());
				return;
			}

			// Request path must be absolute and not contain "..".
			if (request_path.empty() || request_path[0] != '/'
				|| request_path.find("..") != std::string::npos)
			{
				reply = http::reply::stock_reply(http::reply::bad_request, request.version());
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

			reply.document_path() = doc_root_ + request_path;

			// Fill out the reply to be sent to the client.
			reply.status = http::reply::ok;

			for (auto& request_header : request.headers)
			{
				//if (http::util::case_insensitive_equal(request_header.name, "Content-Encoding") && http::util::case_insensitive_equal(request_header.name, "chunked"))
					reply.chunked_encoding() = true;

				//if (http::util::case_insensitive_equal(request_header.name, "Keep-Alive"))
					reply.keep_alive() = true;

			}

			reply.headers.emplace_back(http::header("Server", "NeoLM / 0.01 (Windows)"));
			reply.headers.emplace_back(http::header("Date", date_header_value()));
			reply.headers.emplace_back(http::header("Content-Type", mime_types::extension_to_type(extension)));


			if (reply.chunked_encoding())
				reply.headers.emplace_back(http::header("Transfer-Encoding", "chunked"));


			if (reply.keep_alive() == true)
			{
				reply.headers.emplace_back(http::header("Connection", "Keep-Alive"));
				reply.headers.emplace_back(http::header("Keep-Alive", std::string("timeout=") + std::to_string(session.keepalive_max) + std::string(" max=") + std::to_string(session.keepalive_count)));
			}
			else
			{
				reply.headers.emplace_back(http::header("Connection", "close"));
			}

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
		ssl_client_connection_handler(boost::asio::io_service& service, boost::asio::ssl::context& ssl_context, int keep_alive_count = 14, int keepalive_timeout = 3) 
			: service_(service), 
			  session(ssl_socket_, keep_alive_count, keepalive_timeout),
			  ssl_socket_(service, ssl_context), 
			  write_strand_(service), 
			  request_handler_("C:\\temp")
		{
		}

		http::ssl_client_connection_handler(http::ssl_client_connection_handler const &) = delete;
		void operator==(http::ssl_client_connection_handler const &) = delete;
		~ssl_client_connection_handler()
		{
			std::string s = socket().remote_endpoint().address().to_string();

			//std::cout << "done with connection from: " << s << "\n";
		}
			

		ssl_socket_t::lowest_layer_type& socket()
		{
			return ssl_socket_.lowest_layer();
		}

		void start()
		{
			std::string s = socket().remote_endpoint().address().to_string();
			//std::cout << "new connection from: " << s << "\n";

			ssl_socket_.async_handshake(boost::asio::ssl::stream_base::server, [me = shared_from_this()](boost::system::error_code const& ec)
			{
				if (ec)
				{
					//std::cout << "handshake incomplete : \n" << ec.message() << " : this=" << reinterpret_cast<int64_t>(me.get()) << std::endl;
				}
				else
				{
					//std::cout << "handshake complete   : \n" << ec.message() << " : this=" << reinterpret_cast<int64_t>(me.get()) << std::endl;
					me->do_read();
				}
			});
		}

		void do_read()
		{

			boost::asio::async_read_until(ssl_socket_, in_packet_, "\r\n\r\n",
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

					do_write();
				}
				else if (result == http::request_parser::bad)
				{
					reply_ = http::reply::stock_reply(http::reply::bad_request, request_.version());
					do_write();
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

		void do_write()
		{
			std::vector<boost::asio::const_buffer> data = std::move(reply_.to_buffers());

			boost::asio::async_write(ssl_socket_, data, write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
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
				if (reply_.keep_alive() && session.keepalive_count > 0)
				{
					session.keepalive_count--;
					request_parser_.reset();
					request_.reset();
					reply_.reset();
					do_read();
				}
				else
				{
					//std::cout << "closing connection\n";
					socket().shutdown(boost::asio::ip::tcp::socket::shutdown_receive);
				}
			}
		}

	private:
		boost::asio::io_service& service_;
		
		http::session<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> session;
		
		boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_;

		boost::asio::io_service::strand write_strand_;
		boost::asio::streambuf in_packet_;

		/// The handler used to process the incoming request.
		http::request_handler<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> request_handler_;

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
		client_connection_handler(boost::asio::io_service& service, const int keep_alive_count = 15, const int keepalive_timeout = 3) 
			: service_(service), 
			socket_(service), 
			session(socket_, keep_alive_count, keepalive_timeout),
			write_strand_(service), 
			request_handler_("C:\\temp")
		{

		}

		http::client_connection_handler(http::client_connection_handler const &) = delete;
		void operator==(http::client_connection_handler const &) = delete;

		~client_connection_handler() 
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
					request_handler_.handle_request(request_, reply_, session);

					do_write();
				}
				else if (result == http::request_parser::bad)
				{
					reply_ = http::reply::stock_reply(http::reply::bad_request, request_.version());
					do_write();
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

		void do_chunked_write(bool finished)
		{
			std::vector<boost::asio::const_buffer> data; 
			
			data.emplace_back(boost::asio::buffer(this->write_buffer.back()));

			boost::asio::async_write(socket_, data, write_strand_.wrap([this, finished, me = shared_from_this()](boost::system::error_code ec, std::size_t)
			{
				if (finished)
					me->do_write_done(ec);
			}));


		}

		void do_write()
		{
			if (reply_.chunked_encoding())
			{				
				std::vector<boost::asio::const_buffer> data = std::move(reply_.to_buffers());

				boost::asio::async_write(socket_, data, write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
				{
					reply_.content.clear();

					std::ifstream is(reply_.document_path().c_str(), std::ios::in | std::ios::binary);

					// Open the file to send back.
					std::string buffer;
					buffer.resize(255);
					is.rdbuf()->pubsetbuf(&buffer[0], buffer.size());

					std::streamsize bytes_in = is.read(&buffer[0], buffer.size()).gcount();
					std::vector<boost::asio::const_buffer> content_data;

					while (bytes_in > 0)
					{
						std::stringstream ss;

						ss << std::hex << bytes_in;
						ss << misc_strings::crlf;
						ss << buffer;
						ss << misc_strings::crlf;

						me->write_buffer.emplace_back(ss.str());

						me->do_chunked_write(false);

						bytes_in = is.read(&buffer[0], buffer.size()).gcount();
					}

					std::stringstream ss;
					ss.clear();
					ss << std::hex << 0;
					ss << misc_strings::crlf;
					ss << misc_strings::crlf;
					me->write_buffer.emplace_back(ss.str());

					me->do_chunked_write(true);

				}));

			}
			else
			{

				std::array<char, 8192> buffer;

				std::ifstream is(reply_.document_path().c_str(), std::ios::in | std::ios::binary);

				is.rdbuf()->pubsetbuf(&buffer[0], buffer.size());

				if (!is)
				{
					reply_ = http::reply::stock_reply(http::reply::not_found, request_.version());
				}

				/*
				std::for_each(data.begin(), data.end(), [&](boost::asio::const_buffer& b) {
					std::cout << boost::asio::buffer_cast<const char*>(b);
				});*/


				std::stringstream ss;

				while (int bytes_in = is.read(&buffer[0], buffer.size()).gcount() > 0)
				{
					ss << &buffer[0];
				}

				reply_.content.assign(std::move(ss.str()));
				reply_.headers.emplace_back(http::header("Content-Length", std::to_string(reply_.content.size())));

				std::vector<boost::asio::const_buffer> data = std::move(reply_.to_buffers());

				boost::asio::async_write(socket_, data, write_strand_.wrap([this, me = shared_from_this()](boost::system::error_code ec, std::size_t)
				{
					if (ec != boost::asio::error::operation_aborted)
					{
						me->do_write_done(ec);
					}
				}));
			}
		}

		void do_write_done(boost::system::error_code const & error)
		{
			if (!error)
			{
				if (reply_.keep_alive() && session.keepalive_count > 0)
				{
						session.keepalive_count--;
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
		}

	private:
		boost::asio::io_service& service_;
		http::session<boost::asio::ip::tcp::socket> session;
		boost::asio::ip::tcp::socket socket_;
		int keep_alive_count;
		int keepalive_timeout;

		boost::asio::io_service::strand write_strand_;
		boost::asio::streambuf in_packet_;

		/// The handler used to process the incoming request.
		http::request_handler<boost::asio::ip::tcp::socket> request_handler_;

		/// Buffer for incoming data.
		std::array<char, 8192> buffer_;

		std::deque<std::string> write_buffer;

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



			auto http_handler = std::make_shared<http::client_connection_handler>(io_service, keep_alive_count, keepalive_timeout);
			auto https_handler = std::make_shared<http::ssl_client_connection_handler>(io_service, ssl_context, keep_alive_count, keepalive_timeout);

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
				std::cout << "accepted a non-ssl-connection from: " << http_handler->socket().remote_endpoint().address().to_string() << "\n";
				this->handle_new_connection(http_handler, error);
			});

			ssl_acceptor_.async_accept(https_handler->socket(), [this, https_handler](auto error)
			{
				std::cout << "accepted a ssl-connection from: " << https_handler->socket().remote_endpoint().address().to_string() << "\n";
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

			auto new_handler = std::make_shared<http::client_connection_handler>(io_service, keep_alive_count, keep_alive_count);

			acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error)
			{
				this->handle_new_connection(new_handler, error);
			});
		}

		void handle_new_https_connection(shared_https_client_connection_handler_t handler, const boost::system::error_code error)
		{
			if (error) { return; }

			handler->start();

			auto new_handler = std::make_shared<http::ssl_client_connection_handler>(io_service, ssl_context, keep_alive_count, keep_alive_count);

			ssl_acceptor_.async_accept(new_handler->socket(), [this, new_handler](auto error)
			{
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

}


int main(int argc, char* argv[])
{

	http::server<http::client_connection_handler, http::ssl_client_connection_handler> server(
		"C:\\Development Libraries\\ssl.crt", 
		"C:\\Development Libraries\\ssl.key");

	server.start_server();

	return 0;
}


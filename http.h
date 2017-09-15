#pragma once
#include <sstream>
#include <string>

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>

#include <deque>
#include <thread>
#include <vector>

#include <ctime>

#include <map>

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

namespace http
{

namespace util
{
	inline bool case_insensitive_equal(const std::string& str1, const std::string& str2) noexcept
	{
		return str1.size() == str2.size() && std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) { return tolower(a) == tolower(b); });
	}

	template <typename block_container_t = std::array<char, 1024>>
	bool read_from_disk(const std::string& file_path, const std::function<bool(block_container_t, size_t)>& read)
	{

		block_container_t buffer;
		std::ifstream is(file_path.c_str(), std::ios::in | std::ios::binary);

		is.seekg(0, std::ifstream::ios_base::beg);
		is.rdbuf()->pubsetbuf(buffer.data(), buffer.size());

		std::streamsize bytes_in = is.read(buffer.data(), buffer.size()).gcount();

		bool result = false;

		while (bytes_in > 0)
		{

			if (!read(buffer, bytes_in)) break;

			bytes_in = is.read(buffer.data(), buffer.size()).gcount();
		}

		return result;
	}

} // namespace util

namespace status_strings
{
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
	} // namespace http_11
} // namespace status_strings

namespace misc_strings
{

	const char name_value_separator[] = { ':', ' ' };
	const char crlf[] = { '\r', '\n' };

} // namespace misc_strings

namespace stock_replies
{

	const char ok[] = "";
	const char created[]
		= "<html>"
		  "<head><title>Created</title></head>"
		  "<body><h1>201 Created</h1></body>"
		  "</html>";
	const char accepted[]
		= "<html>"
		  "<head><title>Accepted</title></head>"
		  "<body><h1>202 Accepted</h1></body>"
		  "</html>";
	const char no_content[]
		= "<html>"
		  "<head><title>No Content</title></head>"
		  "<body><h1>204 Content</h1></body>"
		  "</html>";
	const char multiple_choices[]
		= "<html>"
		  "<head><title>Multiple Choices</title></head>"
		  "<body><h1>300 Multiple Choices</h1></body>"
		  "</html>";
	const char moved_permanently[]
		= "<html>"
		  "<head><title>Moved Permanently</title></head>"
		  "<body><h1>301 Moved Permanently</h1></body>"
		  "</html>";
	const char moved_temporarily[]
		= "<html>"
		  "<head><title>Moved Temporarily</title></head>"
		  "<body><h1>302 Moved Temporarily</h1></body>"
		  "</html>";
	const char not_modified[]
		= "<html>"
		  "<head><title>Not Modified</title></head>"
		  "<body><h1>304 Not Modified</h1></body>"
		  "</html>";
	const char bad_request[]
		= "<html>"
		  "<head><title>Bad Request</title></head>"
		  "<body><h1>400 Bad Request</h1></body>"
		  "</html>";
	const char unauthorized[]
		= "<html>"
		  "<head><title>Unauthorized</title></head>"
		  "<body><h1>401 Unauthorized</h1></body>"
		  "</html>";
	const char forbidden[]
		= "<html>"
		  "<head><title>Forbidden</title></head>"
		  "<body><h1>403 Forbidden</h1></body>"
		  "</html>";
	const char not_found[]
		= "<html>"
		  "<head><title>Not Found</title></head>"
		  "<body><h1>404 Not Found</h1></body>"
		  "</html>";
	const char internal_server_error[]
		= "<html>"
		  "<head><title>Internal Server Error</title></head>"
		  "<body><h1>500 Internal Server Error</h1></body>"
		  "</html>";
	const char not_implemented[]
		= "<html>"
		  "<head><title>Not Implemented</title></head>"
		  "<body><h1>501 Not Implemented</h1></body>"
		  "</html>";
	const char bad_gateway[]
		= "<html>"
		  "<head><title>Bad Gateway</title></head>"
		  "<body><h1>502 Bad Gateway</h1></body>"
		  "</html>";
	const char service_unavailable[]
		= "<html>"
		  "<head><title>Service Unavailable</title></head>"
		  "<body><h1>503 Service Unavailable</h1></body>"
		  "</html>";

} // namespace stock_replies

class header
{
public:
	header() = default;

	header(const std::string&& name, const std::string&& value = "")
		: name(std::move(name))
		, value(std::move(value)){};

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

	std::string method;
	std::string uri;
	int http_version_major;
	int http_version_minor;

	std::vector<http::header> headers;
};

class request_parser
{
public:
	request_parser()
		: state_(method_start){};

	void reset() { state_ = method_start; };

	enum result_type
	{
		good,
		bad,
		indeterminate
	};

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
	static bool is_char(int c) { return c >= 0 && c <= 127; }

	/// Check if a byte is an HTTP control character.
	static bool is_ctl(int c) { return (c >= 0 && c <= 31) || (c == 127); }
	/// Check if a byte is defined as an HTTP tspecial character.
	static bool is_tspecial(int c)
	{
		switch (c)
		{
		case '(':
		case ')':
		case '<':
		case '>':
		case '@':
		case ',':
		case ';':
		case ':':
		case '\\':
		case '"':
		case '/':
		case '[':
		case ']':
		case '?':
		case '=':
		case '{':
		case '}':
		case ' ':
		case '\t':
			return true;
		default:
			return false;
		}
	}

	/// Check if a byte is a digit.
	static bool is_digit(int c) { return c >= '0' && c <= '9'; }

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
	reply()
		: document_path_{ "" }
		, keep_alive_{ false }
		, chunked_encoding_{ false } {};

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

	std::string& document_path() noexcept { return document_path_; }

	bool& keep_alive() { return keep_alive_; }

	bool& chunked_encoding() { return chunked_encoding_; }

	std::string headers_to_string()
	{
		std::string result;
		std::stringstream ss;

		ss << http::reply::to_buffer(this->status);

		for (std::size_t i = 0; i < headers.size(); ++i)
		{
			http::header& h = headers[i];
			ss << h.name;
			ss << misc_strings::name_value_separator;
			ss << h.value;
			ss << misc_strings::crlf;
		}
		ss << misc_strings::crlf;

		return result = ss.str();
	};

	std::string content_to_string()
	{
		std::string result;
		std::stringstream ss;

		ss << content;

		return result = ss.str();
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
	bool chunked_encoding_;
	bool keep_alive_;
	std::string document_path_;

	static std::string to_string(http::reply::status_type status)
	{
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
	}

	static const std::string to_buffer(http::reply::status_type status)
	{
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
	}
};

namespace mime_types
{
	struct mapping
	{
		const char* extension;
		const char* mime_type;
	}

	mappings[]
		= { { "ico", "image/x-icon" }, { "gif", "image/gif" },   { "htm", "text/html" }, { "html", "text/html" },
			{ "jpg", "image/jpeg" },   { "jpeg", "image/jpeg" }, { "png", "image/png" } };

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

namespace api
{
	class router
	{
	public:
		router(){};

		void add_route(const char* api_route, const char* http_method, std::function<bool(const char* method, class session& session)> api_method)
		{
			std::string key{ http_method };

			key += "_";
			key += api_route;

			api_router_table.insert(std::make_pair(key.c_str(), api_method));
		}

		bool call(const char* api_route, const char* http_method, class session& session)
		{
			std::string key{ http_method };

			key += "_";
			key += api_route;

			auto result = api_router_table[api_route](http_method, session);

			return result;
		}

	protected:
		std::map<const char*, std::function<bool(const char* method, class session& session)>> api_router_table;
	};

} // namespace api

class session_handler
{
public:
	session_handler(const session_handler&) = delete;
	session_handler& operator=(const session_handler&) = delete;

	/// Construct with a directory containing files to be served.
	explicit session_handler(const std::string& doc_root, http::api::router& router)
		: doc_root_{ doc_root }
		, router_(router)
	{
	}

	const std::string date_header_value() const
	{
		std::string returnvalue;

		/// The value to use to format an HTTP date into RFC1123 format.
		static const char DATE_FORMAT[] = { "%a, %d %b %Y %H:%M:%S GMT" };

		char buffer[30];

		time_t now;
		tm tm;

		time(&now);

		::localtime_s(&tm, &now);

		std::strftime(buffer, 30, DATE_FORMAT, &tm);

		returnvalue = buffer;

		return returnvalue;
	}

	/// Handle a request and produce a reply.

	template <typename InputIterator> std::tuple<request_parser::result_type, InputIterator> parse_request(InputIterator begin, InputIterator end)
	{
		return request_parser_.parse(request_, begin, end);
	}

	/// Handle a request and produce a reply.
	void handle_request()
	{
		// Decode url to path.
		std::string request_path;

		if (!url_decode(request_.uri, request_path))
		{
			reply_ = http::reply::stock_reply(http::reply::bad_request);
			return;
		}

		// Request path must be absolute and not contain "..".
		if (request_path.empty() || request_path[0] != '/' || request_path.find("..") != std::string::npos)
		{
			reply_ = http::reply::stock_reply(http::reply::bad_request);
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

		reply_.document_path() = doc_root_ + request_path;

		// Fill out the reply to be sent to the client.
		reply_.status = http::reply::ok;

		for (auto& request_header : request_.headers)
		{
			if (http::util::case_insensitive_equal(request_header.name, "Content-Encoding")
				&& http::util::case_insensitive_equal(request_header.name, "chunked"))
				reply_.chunked_encoding() = true;

			if (http::util::case_insensitive_equal(request_header.value, "Keep-Alive")) reply_.keep_alive() = true;
		}

		reply_.headers.emplace_back(http::header("Server", "NeoLM / 0.01 (Windows)"));
		reply_.headers.emplace_back(http::header("Date", date_header_value()));
		reply_.headers.emplace_back(http::header("Content-Type", mime_types::extension_to_type(extension)));

		if (reply_.chunked_encoding())
		{
			reply_.headers.emplace_back(http::header("Transfer-Encoding", "chunked"));
		}
		else
		{
			size_t bytes_total = fs::file_size(reply_.document_path());
			reply_.headers.emplace_back(http::header("Content-Length", std::to_string(bytes_total)));
		}

		if (reply_.keep_alive() == true)
		{
			reply_.headers.emplace_back(http::header("Connection", "Keep-Alive"));
			reply_.headers.emplace_back(
				http::header("Keep-Alive", std::string("timeout=") + std::to_string(keepalive_max_) + std::string(" max=") + std::to_string(keepalive_count_)));
		}
		else
		{
			reply_.headers.emplace_back(http::header("Connection", "close"));
		}
	}

	int& keepalive_count() { return keepalive_count_; };
	int& keepalive_max() { return keepalive_max_; };

	request_parser& request_parser() { return request_parser_; };
	reply& reply() { return reply_; };
	request& request() { return request_; };

	void reset()
	{
		request_parser_.reset();
		request_.reset();
		reply_.reset();
	}

private:
	/// The directory containing the files to be served.
	std::string doc_root_;

	http::request request_;
	http::reply reply_;
	http::request_parser request_parser_;

	http::api::router& router_;
	int keepalive_count_;
	int keepalive_max_;

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

} // namespace http

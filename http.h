#pragma once

#define __STDC_WANT_LIB_EXT1__ 1
#include <sstream>
#include <string>
#include <time.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>

#include <deque>
#include <thread>
#include <vector>

#include <ctime>

#include <map>
#include <type_traits>
#include <algorithm>

#include "http_message.h"

// #include <experimental/filesystem>
// namespace fs = std::experimental::filesystem;

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
				req.method().push_back(input);
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
				req.method().push_back(input);
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
				req.uri().push_back(input);
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
				req.version_ = 0;
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
				req.version_ = (10 * (input - '0'));
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
				req.version_ = (10 * (input - '0'));
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case http_version_minor_start:
			if (is_digit(input))
			{
				req.version_ = req.version() + (input - '0');
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
				req.version_ = req.version() + (input - '0');
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
			else if (!req.fields().empty() && (input == ' ' || input == '\t'))
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
				req.fields().push_back(http::field());
				req.fields().back().name.push_back(input);
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
				req.fields().back().value.push_back(input);
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
				req.fields().back().name.push_back(input);
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
				req.fields().back().value.push_back(input);
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

	static std::string extension_to_type(const std::string& extension)
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

class session_handler;

namespace api
{
	template <class function_t = std::function<bool(http::session_handler& session)>> class router
	{
	public:
		router() {};

		void add_route(const std::string& http_uri, function_t api_method)
		{
			std::string key{ http_uri };
			api_router_table.insert(std::make_pair(key.c_str(), api_method));
		}

		bool call(http::session_handler& session)
		{
			std::string key{ session._request().uri() };

			auto i = api_router_table.find(key);

			if (i != api_router_table.end())
				return api_router_table[key](session);
			else
				return false;
		}

	protected:
		std::map<const std::string, function_t> api_router_table;
	};

} // namespace api



class session_handler
{

public:
	session_handler(const session_handler&) = delete;
	session_handler& operator=(const session_handler&) = delete;

	/// Construct with a directory containing files to be served.
	explicit session_handler(const std::string& doc_root, class http::api::router<>& router)
		: doc_root_{ doc_root }
		, router_(router)
	{
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

		if (!url_decode(request_.uri(), request_path))
		{
			reply_.stock_reply(http::reply::bad_request);
			return;
		}

		// Request path must be absolute and not contain "..".
		if (request_path.empty() || request_path[0] != '/' || request_path.find("..") != std::string::npos)
		{
			reply_.stock_reply(http::reply::bad_request);
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

		// Fill out the reply to be sent to the client.
		reply_.stock_reply(http::reply::ok);


/*		for (auto& request_header : request_.fields())
		{
			if (http::util::case_insensitive_equal(request_header.name, "Content-Encoding")
				&& http::util::case_insensitive_equal(request_header.name, "chunked"))
				reply_.chunked_encoding() = true;

			if (http::util::case_insensitive_equal(request_header.value, "Keep-Alive")) reply_.keep_alive() = true;
		}*/


		if (request_["Content-Encoding"] == "chunked")
		{
			reply_.set("Transfer-Encoding", "chunked");
		}

		if (this->router_.call(*this))
		{
			reply_.set("Content-Length", std::to_string(reply_.body_.length()));
		}
		else
		{
			// not routed to an api. proceed as normal HTTP file request.
			// NDJ: from here...
			//reply_.uri() = doc_root_ + request_path;
			//reply_.

			size_t bytes_total = 0; // TODO fs::file_size(reply_.document_path());
			reply_.set("Content-Length", std::to_string(bytes_total));
		}

		if (request_["Connection"] == "keep-alive") // || Version == 11)
		{
			reply_.set("Connection", "Keep-Alive");
			reply_.set("Keep-Alive", std::string("timeout=") + std::to_string(keepalive_max_) + std::string(" max=") + std::to_string(keepalive_count_));
		}
		else
		{
			reply_.set("Connection", "close");
		}
	}

	int& keepalive_count() { return keepalive_count_; };
	int& keepalive_max() { return keepalive_max_; };

	//using request = http::message<true>;
	//using reply = http::message<false>;

	http::request_parser& request_parser() { return request_parser_; };
	http::reply& _reply() { return reply_; };
	http::request& _request() { return request_; };

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
	http::api::router<>& router_;

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

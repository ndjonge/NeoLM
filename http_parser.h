#pragma once

#define __STDC_WANT_LIB_EXT1__ 1
#include <string>

#include <deque>
#include <vector>
#include <algorithm>
#include <map>

#include "http_api_router.h"
#include "http_message.h"

#if defined(_USE_CPP17_STD_FILESYSTEM)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#include "filesystem.h"
namespace fs = filesystem;
#endif

namespace http
{

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

	template <typename InputIterator> std::tuple<result_type, InputIterator> parse(http::request_message& req, InputIterator begin, InputIterator end)
	{
		std::stringstream trace;

		while (begin != end)
		{
			result_type result = consume(req, *begin++);

			if (result == good || result == bad)
			{
				return std::make_tuple(result, begin);
			}
		}

		return std::make_tuple(indeterminate, begin);
	}

private:
	result_type consume(http::request_message& req, char input)
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
				state_ = target;
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
		case target:
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
				req.target().push_back(input);
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
			else if (!req.fields_empty() && (input == ' ' || input == '\t'))
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
				auto i = req.new_field();
				i->name.push_back(input);
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
				req.last_new_field()->value.push_back(input);
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
				req.last_new_field()->name.push_back(input);
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
				req.last_new_field()->value.push_back(input);
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
			if (input == '\n') return (input == '\n') ? good : bad;
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
		target,
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
		expecting_newline_3,
		body_start,
		body_end
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
		= { { "ico", "image/x-icon" }, { "gif", "image/gif" }, { "htm", "text/html" }, { "html", "text/html" }, { "jpg", "image/jpeg" }, { "jpeg", "image/jpeg" }, { "png", "image/png" } };

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

class session_handler
{

public:
	session_handler(const session_handler&) = default;
	session_handler& operator=(const session_handler&) = default;

	explicit session_handler(class http::api::router<>& router)
		: router_(router)
		, keepalive_count_(30)
		, keepalive_max_(20)
	{
	}

	template <typename InputIterator> std::tuple<request_parser::result_type, InputIterator> parse_request(InputIterator begin, InputIterator end) { return request_parser_.parse(request_, begin, end); }

	void handle_request()
	{
		std::string request_path;

		if (!url_decode(request_.target(), request_path))
		{
			response_.stock_reply(http::status::bad_request);
			return;
		}

		if (request_path.empty() || request_path[0] != '/' || request_path.find("..") != std::string::npos)
		{
			response_.stock_reply(http::status::bad_request);
			return;
		}

		if (request_path[request_path.size() - 1] == '/')
		{
			request_path += "index.html";
		}

		std::size_t last_slash_pos = request_path.find_last_of("/");
		std::size_t last_dot_pos = request_path.find_last_of(".");
		std::string extension;

		if (last_dot_pos != std::string::npos && last_dot_pos > last_slash_pos)
		{
			extension = request_path.substr(last_dot_pos + 1);
		}

		request_.target() = request_path;

		response_.stock_reply(http::status::ok);

		if (this->router_.call(*this))
		{
			// route has a valid response (dynamic or static content)
			if (request_.chunked()) response_.chunked(true);

			if (!response_.body().empty())
				response_.content_length(response_.body().length());
			else
			{
				response_.content_length(fs::file_size(request_.target()));
			}

			if (request_.keep_alive() && this->keepalive_count() > 0)
			{
				response_.keep_alive(true, this->keepalive_max(), this->keepalive_count());
			}
			else
			{
				response_.keep_alive(false);
			}
		}
		else
		{
			// route has a invalid response
			response_.set("Connection", "close");
		}
	}

	int& keepalive_count() { return keepalive_count_; };
	int& keepalive_max() { return keepalive_max_; };

	http::request_parser& request_parser() { return request_parser_; };
	http::response_message& response() { return response_; };
	http::request_message& request() { return request_; };

	void reset()
	{
		request_parser_.reset();
		request_.reset();
		response_.reset();
	}

private:
	http::request_message request_;
	http::response_message response_;
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

namespace util
{
	template <typename block_container_t = std::array<char, 1024>> bool read_from_disk(const std::string& file_path, const std::function<bool(block_container_t, size_t)>& read)
	{
		block_container_t buffer;
		std::ifstream is(file_path.c_str(), std::ios::in | std::ios::binary);

		is.seekg(0, std::ifstream::ios_base::beg);
		is.rdbuf()->pubsetbuf(buffer.data(), buffer.size());

		std::streamsize bytes_in = is.read(buffer.data(), buffer.size()).gcount();

		bool result = false;

		while (bytes_in > 0)
		{
			// printf("bytes_in %d\n", bytes_in);
			if (!read(buffer, bytes_in)) break;

			bytes_in = is.read(buffer.data(), buffer.size()).gcount();
		}

		return result;
	}

} // namespace util

} // namespace http

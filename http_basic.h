/*
TODO: insert copyrights and MIT license.
*/

#pragma once

#include <cstdint>
#include <sys/stat.h>

#include <cstddef>
#include <cstring>

#include <algorithm>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#if defined(_USE_CPP17_STD_FILESYSTEM)
#include <experimental/filesystem>
#endif

namespace filesystem
{
inline std::uintmax_t file_size(const std::string& path)
{
	struct stat t;

	int ret = stat(path.c_str(), &t);

	if (ret != 0)
		return t.st_size;
	else
		return 0;
}
} // namespace filesystem

#if defined(_USE_CPP17_STD_FILESYSTEM)
namespace fs = std::experimental::filesystem;
#else
namespace fs = filesystem;
#endif


namespace http
{
class request_parser;
class session_handler;

namespace util
{
inline bool case_insensitive_equal(const std::string& str1, const std::string& str2) noexcept
{
	return str1.size() == str2.size() && std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) { return tolower(a) == tolower(b); });
}


namespace split_opt
{
  enum empties_t { empties_ok, no_empties };
};

template <typename T>
T& split(T& result, const typename T::value_type& s, const typename T::value_type& delimiters, split_opt::empties_t empties = split_opt::empties_ok )
{
  result.clear();
  size_t current;
  size_t next = -1;
  do
  {
    if (empties == split_opt::no_empties)
    {
      next = s.find_first_not_of( delimiters, next + 1 );
      if (next == T::value_type::npos) break;
      next -= 1;
    }
    current = next + 1;
    next = s.find_first_of( delimiters, current );
    result.push_back( s.substr( current, next - current +1) );
  }
  while (next != T::value_type::npos);
  return result;
}
} // namespace util

namespace status
{
enum status_t
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
};

inline const char* to_string(status_t s)
{
	switch (s)
	{
	case http::status::ok:
		return "HTTP/1.1 200 OK\r\n";
	case http::status::created:
		return "HTTP/1.1 202 Accepted\r\n";
	case http::status::accepted:
		return "HTTP/1.1 204 No Content\r\n";
	case http::status::no_content:
		return "HTTP/1.1 204 No Content\r\n";
	case http::status::multiple_choices:
		return "HTTP/1.1 300 Multiple Choices\r\n";
	case http::status::moved_permanently:
		return "HTTP/1.1 301 Moved Permanently\r\n";
	case http::status::moved_temporarily:
		return "HTTP/1.1 302 Moved Temporarily\r\n";
	case http::status::not_modified:
		return "HTTP/1.1 304 Not Modified\r\n";
	case http::status::bad_request:
		return "HTTP/1.1 400 Bad Request\r\n";
	case http::status::unauthorized:
		return "HTTP/1.1 401 Unauthorized\r\n";
	case http::status::forbidden:
		return "HTTP/1.1 403 Forbidden\r\n";
	case http::status::not_found:
		return "HTTP/1.1 404 Not Found\r\n";
	case http::status::internal_server_error:
		return "HTTP/1.1 500 Internal Server Error\r\n";
	case http::status::not_implemented:
		return "HTTP/1.1 501 Not Implemented\r\n";
	case http::status::bad_gateway:
		return "HTTP/1.1 502 Bad Gateway\r\n";
	case http::status::service_unavailable:
		return "HTTP/1.1 503 Service Unavailable\r\n";
	default:
		return "";
	}
}
} // namespace status

namespace misc_strings
{
const char name_value_separator[] = { ':', ' ' };
const char crlf[] = { '\r', '\n' };
} // namespace misc_strings

class field
{
public:
	field() = default;

	field(const std::string& name, const std::string& value = "")
		: name(name)
		, value(value){};

	std::string name;
	std::string value;
};

class fields
{

public:
	using iterator = std::vector<http::field>::iterator;
	using value_type = http::field;

protected:
	std::vector<fields::value_type> fields_;

public:
	fields() = default;

	fields(std::initializer_list<fields::value_type> init_list)
		: fields_(init_list){};

	fields(const http::fields& f)
		: fields_(f.fields_){};

	inline bool fields_empty() const { return this->fields_.empty(); };

	inline void set(const std::string& name, const std::string& value)
	{
		http::field field_(name, value);

		fields_.emplace_back(std::move(field_));
	}

	inline std::vector<fields::value_type>::reverse_iterator new_field()
	{
		fields_.push_back(field());
		return fields_.rbegin();
	}

	inline std::vector<fields::value_type>::reverse_iterator last_new_field() { return fields_.rbegin(); }

	inline const std::string& operator[](std::string name) const
	{
		static const std::string not_found = "";

		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) {
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
		{
			return not_found;
		}
		else
			return i->value;
	}

	inline std::string& operator[](const std::string& name)
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) {
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i == std::end(fields_))
		{
			fields_.emplace_back(http::field(name, ""));
			return fields_.back().value;
		}
		else
			return i->value;
	}
};

using configuration = http::fields;

enum message_specializations
{
	request_specialization,
	response_specialization
};

template <message_specializations> class header;

template <> class header<request_specialization> : public fields
{
using query_params=http::fields;

public:
	std::string method_;
	std::string target_;
	std::string body_;
	query_params params_;


	unsigned int version_;

	std::string& method() { return method_; }

	std::string& target() { return target_; }

	unsigned int& version() { return version_; }

	query_params& query() { return params_; };

	void reset()
	{
		this->method_.clear();
		this->target_.clear();
		this->body_.clear();
		this->fields_.clear();
	}
};

template <> class header<response_specialization> : public fields
{
public:
	std::string reason_;
	http::status::status_t status_;
	unsigned int version_ = 11;

	unsigned int& version() noexcept { return version_; }

	void version(unsigned int value) noexcept { version_ = value; }

	void reset() { this->fields_.clear(); }

	std::string header_to_string() const
	{
		std::stringstream ss;

		ss << status::to_string(status_);

		for (auto&& field : fields_)
		{
			ss << field.name << ":";
			ss << field.value << "\r\n";
		}

		ss << "\r\n";

		return ss.str();
	}
};

using request_header = header<request_specialization>;
using response_header = header<response_specialization>;

namespace mime_types
{
struct mapping
{
	const char* extension;
	const char* mime_type;
}

const mappings[]
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

template <message_specializations specialization> class message : public header<specialization>
{
private:
	std::string body_;

public:
	message() = default;
	message(const message& ) = default;

	std::string& body() { return body_; }

	const std::string& body() const { return body_; }

	bool chunked() const { return (http::fields::operator[]("Transfer-Encoding") == "chunked"); }

	void chunked(bool value)
	{
		if (value)
			http::fields::operator[]("Transfer-Encoding") = "chunked";
		else
			http::fields::operator[]("Transfer-Encoding") = "none";
	}

	bool has_content_lenght() const
	{
		if (http::fields::operator[]("Content-Length").empty())
			return false;
		else
			return true;
	}

	void content_length(uint64_t const& length) { http::fields::operator[]("Content-Length") = std::to_string(length); }

	uint64_t content_length() const { return std::stoul(http::fields::operator[]("Content-Length")); }

	bool keep_alive() const
	{
		if (http::util::case_insensitive_equal(http::fields::operator[]("Connection"), "Keep-Alive"))
			return true;
		else
			return false;
	}

	void keep_alive(bool value, int timeout = 0, int count = 0)
	{
		if (value && count > 0)
		{
			fields::set("Connection", "keep-alive");
			fields::set("Keep-Alive", "timeout=" + std::to_string(timeout) + ", max=" + std::to_string(count));
		}
		else
		{
			fields::set("Connection", "close");
		}
	}

	/// Get a stock reply.
	void stock_reply(http::status::status_t status, const std::string& extension = "text/plain")
	{
		http::header<specialization>::status_ = status;
		if (status != http::status::ok)
		{
			body_ = std::to_string(status);
		}

		fields::set("Server", "NeoLM / 0.01 (Windows)");
		fields::set("Content-Type", mime_types::extension_to_type(extension));
	}

	static std::string to_string(const http::message<specialization>& message)
	{
		std::string ret = message.header_to_string();
		ret += message.body();

		return ret;
	}
};

template <message_specializations specialization> std::string to_string(const http::message<specialization>& message) { return http::message<specialization>::to_string(message); }

using request_message = http::message<request_specialization>;
using response_message = http::message<response_specialization>;

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

class session_handler
{

public:
	using result_type = http::request_parser::result_type;

	session_handler(const session_handler&) = default;
	session_handler& operator=(const session_handler&) = default;

	explicit session_handler()
		: keepalive_count_(30)
		, keepalive_max_(20)
	{
	}

	template <typename InputIterator> std::tuple<request_parser::result_type, InputIterator> parse_request(InputIterator begin, InputIterator end) { return request_parser_.parse(request_, begin, end); }

	template <typename router_t> void handle_request(router_t& router_)
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

		std::size_t query_pos = request_path.find_last_of("?");

		if (query_pos != std::string::npos)
		{
			std::vector<std::string> tokens;

			http::util::split(tokens, request_path.substr(query_pos+1), "&");

			for (auto& token : tokens)
			{
				std::vector<std::string> name_value;
				
				http::util::split(name_value, token, "=");

				request_.query().set(name_value[0], name_value[1]);
			}



		}

		request_.target() = request_path;

		response_.stock_reply(http::status::ok);

		if (router_.call(*this))
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
				response_.keep_alive(true, this->keepalive_max(), this->keepalive_count()--);
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
	// http::api::router<>& router_;

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

namespace api
{

class params
{
public:
	inline bool insert(const std::string& name, const std::string& value)
	{
		auto ret = parameters.emplace(std::make_pair(name, value));
		return ret.second;
	}

	inline const std::string& get(const std::string& name) const
	{
		auto it = parameters.find(name);
		static std::string no_ret;

		if (it != parameters.end()) // if found
			return it->second;

		return no_ret;
	}

private:
	std::map<std::string, std::string> parameters;
}; // < class Params

using session_handler_type = http::session_handler;
using function_type = std::function<bool(session_handler_type& session, const http::api::params& params)>;

template <class function_t = function_type> class route
{
public:
	route(const std::string& path, function_t endpoint)
		: path_(path)
		, endpoint_(endpoint)
	{
	};

	std::string path_;
	function_t endpoint_;

	static bool match(const std::string& route, const std::string& url, params& params)
	{

		// route: /route/:param1/subroute/:param2/subroute
		// url:   /route/parameter

		if (url == route)
		{
			return true;
		}

		std::vector<std::string> tokens;
		size_t offset = 0;
		size_t token = 0;
		bool ret = false;


		// token = /-----

		size_t b = route.find_first_of("/");
		size_t e = route.find_first_of("/", b+1);

		for (token = 0; b != std::string::npos; token++ )
		{
			std::string current_token = route.substr(b, e - b);
			tokens.emplace_back(std::move(current_token));

			if (e==std::string::npos)
				break;

			b = route.find_first_of("/", e);
			e = route.find_first_of("/", b+1);
		}

		b = url.find_first_of("/");
		e = url.find_first_of("/", b+1);


		bool match = false;

		for (token = 0; ((b != std::string::npos) && (token < tokens.size())); token++)
		{
			std::string current_token = url.substr(b, e - b);

			if (tokens[token].size() > 2 && tokens[token][1] == ':')
			{
				params.insert(tokens[token].substr(2), current_token.substr(1));
			}
			else if(tokens[token] != current_token) 
			{
				match = false; 
				break;
			}
			else if (tokens.size()-1 == token)
			{
				//still matches, this is the last token 
				match = true;
			}

			b = url.find_first_of("/", e);
			e = url.find_first_of("/", b+1);

			if ((b == std::string::npos) && (tokens.size()-1 == token))
			{
				match = true; 
				break;
			}
		}




		return match;
	}

};

template <typename function_t = function_type> class router
{
public:
	router()
		: doc_root_("/var/www"){};

	router(const std::string& doc_root)
		: doc_root_(doc_root){};

	void on_get(const std::string& route, function_t api_method) { api_router_table["GET"].emplace_back(api::route<>(route, api_method)); };
	void on_post(const std::string& route, function_t api_method) { api_router_table["POST"].emplace_back(api::route<>(route, api_method)); };
	void on_head(const std::string& route, function_t api_method) { api_router_table["HEAD"].emplace_back(api::route<>(route, api_method)); };
	void on_put(const std::string& route, function_t api_method) { api_router_table["PUT"].emplace_back(api::route<>(route, api_method)); };
	void on_update(const std::string& route, function_t api_method) { api_router_table["UPDATE"].emplace_back(api::route<>(route, api_method)); };
	void on_delete(const std::string& route, function_t api_method) { api_router_table["DELETE"].emplace_back(api::route<>(route, api_method)); };
	void on_patch(const std::string& route, function_t api_method) { api_router_table["PATCH"].emplace_back(api::route<>(route, api_method)); };
	void on_option(const std::string& route, function_t api_method) { api_router_table["OPTION"].emplace_back(api::route<>(route, api_method)); };

	bool call(session_handler_type& session)
	{
		auto routes = api_router_table[session.request().method()];

		if (routes.empty())
		{
			return false;
		}

		for (auto& route : routes)
		{
			params params_;

			if (api::route<>::match(route.path_, session.request().target(), params_))
			{
				return route.endpoint_(session, params_);
			}
		}
		return false;
	}

protected:
	std::string doc_root_;

	std::map<const std::string, std::vector<api::route<>>> api_router_table;
};
} // namespace api

namespace basic
{

class session_data
{
public:
	session_data(){};

	void store_request_data(const char* data, size_t size) { data_request_.insert(std::end(data_request_), &data[0], &data[0] + size); }

	void store_response_data(const std::string& response_string) { data_response_.insert(std::end(data_response_), response_string.begin(), response_string.end()); }

	std::vector<char>& request_data() { return data_request_; }
	std::vector<char>& response_data() { return data_response_; }

	void reset()
	{
		data_request_.clear();
		data_response_.clear();
	}

private:
	std::vector<char> data_request_;
	std::vector<char> data_response_;
};

class server
{
public:
	server(std::initializer_list<http::configuration::value_type> init_list)
		: router_("")
		, configuration_(init_list){};

	server(const http::configuration& configuration)
		: router_("")
		, configuration_(configuration){};

	server(const server&) = default;

	session_data* open_session()
	{
		session_datas_.push_back(new session_data);

		return session_datas_.back();
	};

	void close_session(session_data* session) { session_datas_.erase(std::find(std::begin(session_datas_), std::end(session_datas_), session)); };

	http::session_handler::result_type parse_session_data(session_data* session)
	{
		http::session_handler::result_type result;

		std::tie(result, std::ignore) = session_handler_.parse_request(std::begin(session->request_data()), std::end(session->request_data()));

		return result;
	}

	void reset_session(session_data* session)
	{
		session_handler_.reset();
		session->reset();
	}

	http::response_message& handle_session(session_data* session)
	{
		session_handler_.handle_request(router_);

		return session_handler_.response();
	}

protected:
	std::deque<session_data*> session_datas_;
	http::session_handler session_handler_;

	http::api::router<> router_;
	http::configuration configuration_;
};

} // namespace basic

} // namespace http

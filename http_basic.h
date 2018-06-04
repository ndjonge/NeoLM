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
#include <array>
#include <mutex>
#include <future>
#include <deque>
#include <thread>




#if defined(_USE_CPP17_STD_FILESYSTEM)
#include <experimental/filesystem>
#endif

#if defined(WIN32)
#include <Ws2tcpip.h>
#include <winsock2.h>
#endif

#include "network.h"


namespace filesystem
{
inline std::uintmax_t file_size(const std::string& path)
{
	struct stat t;

	int ret = stat(path.c_str(), &t);

	if (ret == 0)
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
  T::size_type next = T::value_type::npos;
  auto current = next;

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
    result.push_back( s.substr( current, next - current) );
  }
  while (next != T::value_type::npos);
  return result;
}

bool read_from_disk(const std::string& file_path, const std::function<bool(std::array<char, 8192>&, size_t)>& read)
{
    std::array<char, 8192> buffer;
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

namespace status
{
enum status_t
{
	not_set = 0,
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
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) { return f.name == name; });

		if (i!= std::end(fields_))
		{
			i->value = value;
		}
		else
		{
			http::field field_(name, value);
			fields_.emplace_back(std::move(field_));
		}
	}

	inline std::vector<fields::value_type>::reverse_iterator new_field()
	{
		fields_.push_back(field());
		return fields_.rbegin();
	}

	template <typename T> typename std::enable_if<std::is_same<T, bool>::value, bool>::type get(const std::string& name, const T value = T())
	{
		T returnvalue = value;

		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) {
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i!=std::end(fields_))
			returnvalue = i->value == "true";

		return static_cast<T>(returnvalue);
	}

	template <typename T> typename std::enable_if<std::is_integral<T>::value && !std::is_same<T, bool>::value, T>::type get(const std::string& name, const T value = T())
	{
		T returnvalue = value;

		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) {
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i!=std::end(fields_))
			returnvalue = std::stoi(i->value);

		return static_cast<T>(returnvalue);
	}

	template <typename T> typename std::enable_if<std::is_same<T, std::string>::value, std::string>::type get(const std::string& name, const T& value = T())
	{
		T returnvalue = value;

		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) {
			if (http::util::case_insensitive_equal(f.name, name))
				return true;
			else
				return false;
		});

		if (i!=std::end(fields_))
			returnvalue = i->value;

		return returnvalue;
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
friend class http::session_handler;
friend class http::request_parser;

private:
	std::string method_;
	std::string url_requested_;
	std::string target_;
	query_params params_;
	unsigned int version_nr_;


public:
	const std::string& method() const { return method_; }
	const std::string& target() const { return target_; }
	const std::string& url_requested() const { return url_requested_; }
	const unsigned int& version_nr() const { return version_nr_; }
	const std::string version() const { return std::string("HTTP ") + (version_nr_ == 10 ? "1.0" : "1.1"); }
	void target(const std::string& target) { target_ = target; }

	query_params& query() { return params_; };

	void reset()
	{
		this->version_nr_ = 0;
		this->method_.clear();
		this->target_.clear();
		this->url_requested_.clear();

		this->fields_.clear();
	}

	std::string header_to_string() const
	{
		std::stringstream ss;

		ss << method_ << " " << target_ << "\n";
		
		for (auto&& field : fields_)
		{
			ss << field.name << ": ";
			ss << field.value << "\r\n";
		}

		ss << "\r\n";

		return ss.str();
	}
};

template <> class header<response_specialization> : public fields
{
private:
	std::string reason_;
	http::status::status_t status_;
	unsigned int version_ = 11;

public:
	const unsigned int& version() const noexcept { return version_; }
	void version(unsigned int value) noexcept { version_ = value; }
	void status(http::status::status_t status) { status_ = status; }
	http::status::status_t status() const { return status_; }

	void reset() { 
		this->fields_.clear(); 
		version_ = 0;
	}

	std::string header_to_string() const
	{
		std::stringstream ss;

		ss << status::to_string(status_);

		for (auto&& field : fields_)
		{
			ss << field.name << ": ";
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
	= { { "json", "application/json" }, { "ico", "image/x-icon" }, { "gif", "image/gif" }, { "htm", "text/html" }, { "html", "text/html" }, { "jpg", "image/jpeg" }, { "jpeg", "image/jpeg" }, { "png", "image/png" } };

static std::string extension_to_type(const std::string& extension)
{
	if (extension.find_first_of("/") != std::string::npos)
		return extension;
	else
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

	void reset()
	{
		header<specialization>::reset();
		this->body_.clear();
	}

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

	void type(const std::string& content_type)
	{
		http::fields::operator[]("Content-Type") = mime_types::extension_to_type(content_type);
	}

	void result(http::status::status_t status)
	{
		http::header<specialization>::status(status);

		if (http::header<specialization>::status() != http::status::ok)
		{
			body_ += "status: " + std::to_string(http::header<specialization>::status());
		}
	}

	void content_length(uint64_t const& length) { http::fields::operator[]("Content-Length") = std::to_string(length); }

	uint64_t content_length() const { 
		auto content_length_ = http::fields::operator[]("Content-Length");

		if (content_length_.empty()) 
			return 0;
		else
			return std::stoul(content_length_); 
	}

	bool keep_alive() const
	{
		if (http::util::case_insensitive_equal(http::fields::operator[]("Connection"), "Keep-Alive"))
			return true;
		else
			return false;
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

	void reset() 
	{ 
		state_ = method_start; 
	};

	enum result_type
	{
		good,
		bad,
		indeterminate
	};

	template <typename InputIterator> std::tuple<result_type, InputIterator> parse(http::request_message& req, InputIterator begin, InputIterator end)
	{
		while (begin != end)
		{
			result_type result = consume(req, *begin++);

			if (result == good )
			{
				state_ = method_start; 
				return std::make_tuple(result, begin);
			}
			else if (result == bad)
			{
				state_ = method_start; 
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
				req.method_.push_back(input);
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
				req.method_.push_back(input);
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
				req.target_.push_back(input);
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
				req.version_nr_ = 0;
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
				req.version_nr_ = (10 * (input - '0'));
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
				req.version_nr_ = (10 * (input - '0'));
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case http_version_minor_start:
			if (is_digit(input))
			{
				req.version_nr_ = req.version_nr_ + (input - '0');
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
				req.version_nr_ = req.version_nr_ + (input - '0');
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

	session_handler(http::configuration& configuration)
		: configuration_(configuration)
		, keepalive_count_(configuration.get<int>("keepalive_count", 10))
		, keepalive_max_(configuration.get<int>("keepalive_timeout", 5))
	{
	}

	template <typename InputIterator> std::tuple<request_parser::result_type, InputIterator> parse_request(InputIterator begin, InputIterator end) { return request_parser_.parse(request_, begin, end); }

	template <typename router_t> void handle_request(router_t& router_)
	{
		std::string request_path;
		response_.type("text");
		response_.result(http::status::ok);
		response_.set("Server", configuration_.get<std::string>("server", "a http server 0.0"));


		if (!url_decode(request_.target(), request_path))
		{
			response_.result(http::status::bad_request);
			return;
		}

		if (request_path.empty() || request_path[0] != '/' || request_path.find("..") != std::string::npos)
		{
			response_.result(http::status::bad_request);
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

		std::size_t query_pos = request_path.find_first_of("?#");

		if (query_pos != std::string::npos)
		{
			std::vector<std::string> tokens;

			http::util::split(tokens, request_path.substr(query_pos+1), "&");

			request_path = request_path.substr(0, query_pos);
			for (auto& token : tokens)
			{
				std::vector<std::string> name_value;
				
				http::util::split(name_value, token, "=");

				request_.query().set(name_value[0], name_value[1]);
			}
		}

		request_.url_requested_ = request_.target_;
		request_.target_ = request_path;


		if (router_.call_middleware(*this))
		{
		}
		else
		{
			response_.result(http::status::bad_request);
		}

		if (response_.body().empty())
		{
			if (router_.call_route(*this))
			{
				// Route has a valid handler, response body is set.
				// Check bodys size and set headers.
				response_.content_length(response_.body().length());

			}
			else if (router_.serve_static_content(*this))
			{
				// Static content route.
				// Check filesize and set headers.
				auto content_size = fs::file_size(request_.target());

				if (content_size == 0)
				{ 
					response_.result(http::status::not_found);
					response_.content_length(response_.body().length());
				}
				else
				{
					response_.type(extension);
					response_.content_length(content_size);
				}
			}
		}
		else 
		{
			response_.content_length(response_.body().length());
		}

		// set connection headers in the response.
		if (request_.keep_alive() || (request_.version_nr() == 11 && (http::util::case_insensitive_equal(request_["Connection"], "close")==false))  && 

			(this->keepalive_count()-1 > 0 && (response_.status() == http::status::ok)))
		{
			keepalive_count(keepalive_count() - 1);
			response_["Connection"] = "Keep-Alive";
			response_["Keep-Alive"] = 
				std::string("timeout=") + std::to_string(keepalive_max()) 
				+ ", max=" + 
				std::to_string(keepalive_count());	
		}
		else
		{
			response_["Connection"] = "close";
		}

	}

	void keepalive_count(const int& keepalive_count) 
	{ 
		keepalive_count_ = keepalive_count; 
	};
	int keepalive_count() const 
	{ 
		return keepalive_count_; 
	};

	void keepalive_max(const int& keepalive_max) { keepalive_max_ = keepalive_max; };
	int keepalive_max() const { return keepalive_max_; };


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
	http::configuration& configuration_;

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

using route_function_t = std::function<void(session_handler_type& session, const http::api::params& params)>;
using middleware_function_t = std::function<void(session_handler_type& session, const http::api::params& params)>;

template <typename R = route_function_t> class route
{
public:
	route(const std::string& path, R endpoint)
		: path_(path)
		, endpoint_(endpoint)
	{
	};

	std::string path_;
	R endpoint_;

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

template <typename M = middleware_function_t> class middelware
{
public:
	middelware(const std::string& path, M endpoint)
		: path_(path)
		, endpoint_(endpoint)
	{
	};

	std::string path_;
	M endpoint_;

	static bool match(const std::string& route, const std::string& url, params& params)
	{
		// route: /route/:param1/subroute/:param2/subroute
		// url:   /route/parameter

		if (url.find(route) == 0) // url starts with route
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


template <typename R = route_function_t, typename M = middleware_function_t> class router
{
public:
	router()
		: doc_root_("/var/www"){};

	router(const std::string& doc_root)
		: doc_root_(doc_root){};

	void use(const std::string& path) { static_content_routes.emplace_back(path); }

	void on_http_method(const std::string& route, const std::string& http_method, R api_method) { api_router_table[http_method].emplace_back(route, api_method); }
	void on_get(const std::string& route, R api_method) { api_router_table["GET"].emplace_back(route, api_method); }
	void on_post(const std::string& route, R api_method) { api_router_table["POST"].emplace_back(route, api_method); }
	void on_head(const std::string& route, R api_method) { api_router_table["HEAD"].emplace_back(route, api_method); }
	void on_put(const std::string& route, R api_method) { api_router_table["PUT"].emplace_back(route, api_method); }
	void on_update(const std::string& route, R api_method) { api_router_table["UPDATE"].emplace_back(route, api_method); }
	void on_delete(const std::string& route, R api_method) { api_router_table["DELETE"].emplace_back(route, api_method); }
	void on_patch(const std::string& route, R api_method) { api_router_table["PATCH"].emplace_back(route, api_method); }
	void on_option(const std::string& route, R api_method) { api_router_table["OPTION"].emplace_back(route, api_method); }

	void use(const std::string& route, middleware_function_t middleware_function) { api_middleware_table.emplace_back(route, middleware_function); };

	bool serve_static_content(session_handler_type& session)
	{
		//auto static_path = std::find(std::begin(this->static_content_routes), std::end(this->static_content_routes), session.request().target());
		for (auto static_route : static_content_routes)
		{
			if (session.request().target().find(static_route) == 0)
			{
				auto file_path = doc_root_ + session.request().target();
				session.request().target(file_path);

				return true;
			}
		}
		return false;
	}

	bool call_middleware(session_handler_type& session)
	{
		auto result = true;
		for (auto& middleware : api_middleware_table)
		{
			params params_;

			if (api::middelware<>::match(middleware.path_, session.request().target(), params_))
			{
				result = true;
				middleware.endpoint_(session, params_);
			}
		}

		return result;
	}

	bool call_route(session_handler_type& session)
	{
		auto result = false;
		auto routes = api_router_table[session.request().method()];

		if (!routes.empty())
		{
			for (auto& route : routes)
			{
				params params_;

				if (api::route<>::match(route.path_, session.request().target(), params_))
				{
					route.endpoint_(session, params_);
					return true;
				}
			}
		}

		return false;
	}

protected:
	std::string doc_root_;
	std::vector<std::string> static_content_routes;
	std::map<const std::string, std::vector<api::route<route_function_t>>> api_router_table;
	std::vector<api::middelware<middleware_function_t>> api_middleware_table;
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
	server(http::configuration& configuration)
		: router_(configuration.get<std::string>("doc_root", "/var/www"))
		, configuration_(configuration)
	{};

	server(const server&) = default;

	session_data* open_session()
	{
		session_datas_.push_back(new session_data);

		return session_datas_.back();
	};

	void close_session(session_data* session) { session_datas_.erase(std::find(std::begin(session_datas_), std::end(session_datas_), session)); };


protected:
	std::deque<session_data*> session_datas_;
	http::api::router<> router_;
	http::configuration& configuration_;
};

namespace threaded
{

class server : public http::basic::server
{
	using socket_t = SOCKET;

public:
	server(http::configuration& configuration)
		: http::basic::server{ configuration }
		, thread_count_(configuration.get<int>("thread_count", 5))
		, listen_port_(configuration.get<int>("listen_port_", atoi(getenv("HTTP_PORT"))))
		, connection_timeout_(configuration.get<int>("keepalive_timeout", 4))
	{
	}

	server(const server&) = default;

	virtual void start_server()
	{
		network::init();
		network::ssl::init();


		std::thread http_connection_thread([this]() { http_listener_handler(); });
		// al_so_create(&sync_, AL_SYNC_TYPE_SEMAPHORE|AL_SYNC_LOCKED, FALSE);
		// al_so_add_to_ipcwait(sync_, callback, sync_);

		http_connection_thread.detach();

		//std::thread https_connection_thread([this]() { https_listener_handler(); });
		//https_connection_thread.detach();
	}

	void https_listener_handler()
	{
		try
		{
			network::tcp::v6 endpoint_http(listen_port_+1);

			network::tcp::acceptor acceptor_https{};

			acceptor_https.open(endpoint_http.protocol());

			acceptor_https.bind(endpoint_http);

			acceptor_https.listen();

			network::ssl::context ssl_context(network::ssl::context::tlsv12);

			ssl_context.use_certificate_chain_file(configuration_.get<std::string>("ssl_certificate", std::string("")).c_str());
			ssl_context.use_private_key_file(configuration_.get<std::string>("ssl_certificate_key", std::string("")).c_str());

			network::ssl::stream<network::tcp::socket> https_socket(ssl_context);

			int connections_accepted = 0;

			while (1)
			{
				acceptor_https.accept(https_socket.lowest_layer());
				https_socket.handshake(network::ssl::stream_base::server);

				DWORD timeout_value = static_cast<DWORD>(connection_timeout_) * 1000;
				int ret = ::setsockopt(https_socket.lowest_layer(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout_value), sizeof(timeout_value));

				BOOL tcp_nodelay = 1;
				ret = ::setsockopt(https_socket.lowest_layer(), IPPROTO_TCP, TCP_NODELAY, (char*)&tcp_nodelay, sizeof(tcp_nodelay));

				server_status().connections_accepted(server_status().connections_accepted() + 1);
				server_status().connections_current(server_status().connections_current() + 1);

				std::thread connection_thread([new_connection_handler = std::make_shared<connection_handler<network::ssl::stream<network::tcp::socket>>>(*this, https_socket, connection_timeout_)]() { new_connection_handler->proceed(); });
				connection_thread.detach();
			}
		}
		catch (...)
		{
			// TODO
		}
	}

	void http_listener_handler()
	{
		try
		{
			network::tcp::v6 endpoint_http(listen_port_);

			network::tcp::acceptor acceptor_http{};

			acceptor_http.open(endpoint_http.protocol());

			acceptor_http.bind(endpoint_http);

			acceptor_http.listen();

			network::tcp::socket http_socket;



			/*
			int reuseaddr = 1;
			int ret = ::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuseaddr, sizeof(reuseaddr));

			int ipv6only = 0;
			ret = ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only));
			*/

			int connections_accepted = 0;

			while (1)
			{
				acceptor_http.accept(http_socket);

				DWORD timeout_value = static_cast<DWORD>(connection_timeout_) * 1000;
				int ret = ::setsockopt(http_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout_value), sizeof(timeout_value));

				BOOL tcp_nodelay = 1;
				ret = ::setsockopt(http_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&tcp_nodelay, sizeof(tcp_nodelay));

				server_status().connections_accepted(server_status().connections_accepted() + 1);
				server_status().connections_current(server_status().connections_current() + 1);

				std::thread connection_thread([new_connection_handler = std::make_shared<connection_handler<network::tcp::socket>>(*this, http_socket, connection_timeout_)]() { new_connection_handler->proceed(); });
				connection_thread.detach();
			}
		}
		catch (...)
		{
			// TODO
		}
	}

	class server_info
	{
	private:
		size_t connections_accepted_;
		size_t connections_current_;
		std::vector<std::string> access_log_;
		std::mutex mutex_;

	public:
		server_info()
			: connections_accepted_(0)
			, connections_current_(0){};

		size_t connections_accepted()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return connections_accepted_;
		}

		void connections_accepted(size_t nr)
		{
			std::lock_guard<std::mutex> g(mutex_);
			connections_accepted_ = nr;
		}

		const size_t connections_current()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return connections_current_;
		}

		void connections_current(size_t nr)
		{
			std::lock_guard<std::mutex> g(mutex_);
			connections_current_ = nr;
		}

		static std::string log_entry() {}

		void log_access(http::session_handler& session)
		{
			std::lock_guard<std::mutex> g(mutex_);

			std::stringstream s;

			s << "\"" << session.request()["Remote_Addr"] << "\"";

			s << " - \"" << session.request().method() << " " << session.request().url_requested() << " " << session.request().version() << "\"";
			s << " - " << session.response().status() << " - " << session.response().content_length() << " - " << session.request().content_length();;
			s << " - \"" << session.request()["User-Agent"] << "\"\n";

			access_log_.emplace_back(s.str());

			if (access_log_.size() >= 32) access_log_.erase(access_log_.begin());
		}

		std::string log_access_to_string()
		{
			std::stringstream s;
			std::lock_guard<std::mutex> g(mutex_);

			for (auto& access_log_entry : access_log_)
				s << access_log_entry;

			return s.str();
		}

		std::string to_string()
		{
			std::stringstream s;

			s << "connections_accepted: " << connections_accepted_ << "\n";
			s << "connections_current: " << connections_current_ << "\n";
			s << "access_log:\n";
			s << log_access_to_string();

			return s.str();
		}
	};

	template<class S>
	class connection_handler
	{
	public:
		connection_handler(http::basic::threaded::server& server, S client_socket, int connection_timeout)
			: server_(server)
			, client_socket_(client_socket)
			, session_handler_(server.configuration_)
			, connection_timeout_(connection_timeout)
		{
		}

		~connection_handler()
		{
			// printf("connection close: %lld\n", client_socket_);
			network::shutdown(client_socket_, SD_SEND);
			network::closesocket(client_socket_);
			server_.server_status().connections_current(server_.server_status().connections_current() - 1);
		}

		void proceed()
		{
			std::array<char, 4096> buffer;
			http::basic::session_data connection_data;
			int ret = 0;



			while (true)
			{
				int ret = network::read(client_socket_, network::buffer(buffer.data(), buffer.size()));

				if (ret == 0)
				{
					break;
				}
				if (ret < 0)
				{
					break;
				}

				// store_request_data(buffer, ret);

				http::session_handler::result_type parse_result;
				std::array<char, 4096>::iterator c = std::begin(buffer);

				auto& response = session_handler_.response();
				auto& request = session_handler_.request();

				std::tie(parse_result, c) = session_handler_.parse_request(c, std::end(buffer));

				if ((parse_result == http::request_parser::result_type::good) && (request.has_content_lenght()))
				{
					auto x = c - std::begin(buffer);

					//request.body().reserve((ret - x));
					request.body().assign(buffer.data() + x, (ret - x));

					if (request.content_length() > std::uint64_t(ret - x))
					{
						while (true)
						{
							parse_result = http::request_parser::result_type::bad;

							int ret = network::read(client_socket_, network::buffer(buffer.data(), buffer.size()));

							if (ret == 0)
							{
								break;
							}
							if (ret < 0)
							{
								break;
							}

							request.body().append(buffer.data(), buffer.data()+ret);
							
							if (request.content_length() == request.body().length())
							{
								parse_result = http::request_parser::result_type::good;
								break;
							}
							else if (request.content_length() < request.body().length())
							{
								parse_result = http::request_parser::result_type::bad;
								break;
							}
							else
								continue;
						}
					}						
				}

				if ((parse_result == http::request_parser::result_type::good) || (parse_result == http::request_parser::result_type::bad))
				{

					request_data().clear();
					response_data().clear();

					if (parse_result == http::request_parser::result_type::good)
					{
						session_handler_.request()["Remote_Addr"] = network::get_client_info(client_socket_);
						session_handler_.handle_request(server_.router_);
						server_.server_status().log_access(session_handler_);
					}
					else
					{
						session_handler_.response().result(http::status::bad_request);
					}

					if (response.body().empty())
					{
						std::array<char, 1024 * 32> file_buffer;

						{
							std::string headers = response.header_to_string();



							ret = network::write(client_socket_, network::buffer(&headers[0], headers.length()) );

							std::ifstream is(session_handler_.request().target(), std::ios::in | std::ios::binary);

							is.seekg(0, std::ifstream::ios_base::beg);
							is.rdbuf()->pubsetbuf(file_buffer.data(), file_buffer.size());

							std::streamsize bytes_in = is.read(file_buffer.data(), file_buffer.size()).gcount();

							while (bytes_in > 0 && ret != -1)
							{
								ret = network::write(client_socket_, network::buffer(&file_buffer[0], bytes_in) );

								bytes_in = is.read(file_buffer.data(), file_buffer.size()).gcount();
							}
						}
					}
					else
					{
						connection_data.store_response_data(http::to_string(response));
						ret = network::write(client_socket_, network::buffer(&(connection_data.response_data()[0]), static_cast<int>(connection_data.response_data().size())));
					}

					if (response.keep_alive() == true)
					{
						connection_data.reset();
						session_handler_.reset();
					}
					else
					{
						return;
					}
				}
				else
				{
					// TODO send http error
					connection_data.reset();
					session_handler_.reset();
					return;
				}
			}
		}

	protected:
		http::basic::threaded::server& server_;
		S client_socket_;
		http::session_handler session_handler_;
		int connection_timeout_;

		std::vector<char> data_request_;
		std::vector<char> data_response_;

		void store_request_data(const std::array<char, 4096>& data, size_t size)
		{
			data_request_.resize(data_request_.size() + size);

			std::copy(std::begin(data), std::begin(data) + size, std::rbegin(data_request_));
		}
		void store_response_data(const std::string& response_string)
		{
			data_response_.resize(response_string.size());
			data_response_.insert(std::end(data_response_), response_string.begin(), response_string.end());
		}

		std::vector<char>& request_data() { return data_request_; }
		std::vector<char>& response_data() { return data_response_; }

		void reset_session()
		{
			session_handler_.reset();
			data_request_.clear();
			data_response_.clear();
		}
	};

	server_info& server_status() { return server_info_; }
protected:
	server_info server_info_;
private:
	int thread_count_;
	int listen_port_;
	int connection_timeout_;
};

} // namespace threaded

} // namespace basic


} // namespace http

/*
Copyright (c) <2018> <ndejonge@gmail.com>

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include <cstdint>
#include <sys/stat.h>

#include <cstddef>
#include <cstring>

#include <algorithm>
#include <array>
#include <deque>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <queue>
#include <ratio>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <zlib.h>

#if defined(_USE_CPP17_STD_FILESYSTEM)
#include <experimental/filesystem>
#endif

#include "http_network.h"

// using boost::hash_combine
template <class T> inline void hash_combine(std::size_t& seed, T const& v) { seed ^= std::hash<T>()(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2); }

namespace std
{
template <typename T> struct hash<vector<T>>
{
	using argument_type = std::vector<T>;
	using result_type = std::size_t;
	result_type operator()(argument_type const& in) const
	{
		size_t size = in.size();
		size_t seed = 0;
		for (size_t i = 0; i < size; i++)
			// Combine the hash of the current vector with the hashes of the previous ones
			hash_combine(seed, in[i]);
		return seed;
	}
};

template <typename F, typename S> struct hash<pair<F, S>>
{
	using argument_type = pair<F, S>;
	using result_type = std::size_t;

	result_type operator()(argument_type const& in) const
	{
		size_t seed = 0;

		hash_combine(seed, in.first);
		hash_combine(seed, in.second);

		return seed;
	}
};
} // namespace std

namespace filesystem
{
inline std::uintmax_t file_size(const std::string& path)
{
	struct stat t
	{
	};

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

namespace gzip
{

class compressor
{
	std::size_t max_{ 0 };
	int level_;

public:
	compressor(int level = Z_DEFAULT_COMPRESSION) noexcept
		: level_(level)
	{
	}

	template <typename InputType> void compress(InputType& output, const char* data, std::size_t size) const
	{
		z_stream deflate_s{};
		deflate_s.zalloc = nullptr;
		deflate_s.zfree = nullptr;
		deflate_s.opaque = nullptr;
		deflate_s.avail_in = 0;
		deflate_s.next_in = nullptr;

		constexpr int window_bits = 15 + 16;
		constexpr int mem_level = 8;

		if (deflateInit2(&deflate_s, level_, Z_DEFLATED, window_bits, mem_level, Z_DEFAULT_STRATEGY) != Z_OK)
		{
			throw std::runtime_error("deflate init failed");
		}

		deflate_s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data)); // NOLINT
		deflate_s.avail_in = static_cast<unsigned int>(size);

		std::size_t size_compressed = 0;
		do
		{
			size_t increase = size / 2 + 1024;
			if (output.size() < (size_compressed + increase))
			{
				output.resize(size_compressed + increase);
			}

			deflate_s.avail_out = static_cast<unsigned int>(increase);
			deflate_s.next_out = reinterpret_cast<Bytef*>((&output[0] + size_compressed)); // NOLINT
			deflate(&deflate_s, Z_FINISH);
			size_compressed += (increase - deflate_s.avail_out);
		} while (deflate_s.avail_out == 0);

		deflateEnd(&deflate_s);
		output.resize(size_compressed);
	}
};

inline std::string compress(const char* data, std::size_t size, int level = Z_DEFAULT_COMPRESSION)
{
	compressor comp(level);
	std::string output;
	comp.compress(output, data, size);
	return output;
}

class decompressor
{
public:
	decompressor() noexcept = default;

	template <typename OutputType> void decompress(OutputType& output, const char* data, std::size_t size) const
	{
		z_stream inflate_s{};

		inflate_s.zalloc = nullptr;
		inflate_s.zfree = nullptr;
		inflate_s.opaque = nullptr;
		inflate_s.avail_in = 0;
		inflate_s.next_in = nullptr;

		constexpr int window_bits = 15 + 32;

		if (inflateInit2(&inflate_s, window_bits) != Z_OK)
		{
			throw std::runtime_error("inflate init failed");
		}

		inflate_s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data)); // NOLINT

		inflateEnd(&inflate_s);

		inflate_s.avail_in = static_cast<unsigned int>(size);
		std::size_t size_uncompressed = 0;
		do
		{
			std::size_t resize_to = size_uncompressed + 2 * size;
			inflateEnd(&inflate_s);
			output.resize(resize_to);
			inflate_s.avail_out = static_cast<unsigned int>(2 * size);
			inflate_s.next_out = reinterpret_cast<Bytef*>(&output[0] + size_uncompressed); // NOLINT
			int ret = inflate(&inflate_s, Z_FINISH);
			if (ret != Z_STREAM_END && ret != Z_OK && ret != Z_BUF_ERROR)
			{
				std::string error_msg = inflate_s.msg;
				inflateEnd(&inflate_s);
				throw std::runtime_error(error_msg);
			}

			size_uncompressed += (2 * size - inflate_s.avail_out);
		} while (inflate_s.avail_out == 0);
		inflateEnd(&inflate_s);
		output.resize(size_uncompressed);
	}
};

inline std::string decompress(const char* data, std::size_t size)
{
	decompressor decomp;
	std::string output;
	decomp.decompress(output, data, size);
	return output;
}
} // namespace gzip

namespace http
{
class request_parser;
class response_parser;
class session_handler;

namespace util
{
inline bool case_insensitive_equal(const std::string& str1, const std::string& str2) noexcept
{
	return str1.size() == str2.size() && std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) { return tolower(a) == tolower(b); });
}

namespace split_opt
{
enum empties_t
{
	empties_ok,
	no_empties
};
};

template <typename T> T& split_(T& result, const typename T::value_type& s, const typename T::value_type& delimiters, split_opt::empties_t empties = split_opt::empties_ok)
{
	result.clear();
	typename T::size_type next = T::value_type::npos;
	auto current = next;

	do
	{
		if (empties == split_opt::no_empties)
		{
			next = s.find_first_not_of(delimiters, next + 1);
			if (next == T::value_type::npos) break;
			next -= 1;
		}
		current = next + 1;
		next = s.find_first_of(delimiters, current);
		result.push_back(s.substr(current, next - current));
	} while (next != T::value_type::npos);
	return result;
}

inline std::vector<std::string> split(const std::string& str, const std::string& delimiters)
{
	std::vector<std::string> output;

	output.reserve(str.size() / 2);

	auto first = str.cbegin();

	while (first != str.cend())
	{
		const auto second = std::find_first_of(first, str.cend(), delimiters.cbegin(), delimiters.cend());

		if (first != second) output.emplace_back(first, second);

		if (second == str.cend()) break;

		first = std::next(second);
	}

	return output;
}

inline bool read_from_disk(const std::string& file_path, const std::function<bool(std::array<char, 4096>&, size_t)>& read)
{
	std::array<char, 4096> buffer{};
	std::ifstream is(file_path.c_str(), std::ios::in | std::ios::binary);

	is.seekg(0, std::ifstream::ios_base::beg);
	is.rdbuf()->pubsetbuf(buffer.data(), buffer.size());

	std::streamsize bytes_in = is.read(buffer.data(), buffer.size()).gcount();

	bool result = false;

	while (bytes_in > 0)
	{

		if (!read(buffer, static_cast<size_t>(bytes_in))) break;

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
	method_not_allowed = 405,
	conflict = 409,
	internal_server_error = 500,
	not_implemented = 501,
	bad_gateway = 502,
	service_unavailable = 503
};

inline status_t to_status(std::uint16_t status_nr) { return static_cast<status_t>(status_nr); }

inline const char* to_string(status_t s)
{
	switch (s)
	{
	case http::status::ok:
		return "HTTP/1.1 200 OK\r\n";
	case http::status::created:
		return "HTTP/1.1 201 Created\r\n";
	case http::status::accepted:
		return "HTTP/1.1 202 Accepted\r\n";
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
	case http::status::method_not_allowed:
		return "HTTP/1.1 405 Method Not Allowed\r\n";
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

namespace router_result
{

enum router_result_type
{
	no_route,
	no_method,
	match_found
};

}

class field
{
public:
	field() = default;

	field(std::string name, std::string value = "")
		: name(std::move(name))
		, value(std::move(value)){};

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

	fields(const http::fields& f) = default;
	fields(http::fields&& f) = default;

	fields& operator=(const http::fields&) = default;
	fields& operator=(http::fields&&) = default;

	~fields() = default;

	inline std::string to_string() const noexcept
	{
		std::stringstream ss;
		for (auto&& field : fields_)
		{
			ss << field.name << ": " << field.value << "\r\n";
		}

		return ss.str();
	}

	inline bool fields_empty() const { return this->fields_.empty(); };

	inline std::vector<fields::value_type>::reverse_iterator new_field()
	{
		fields_.emplace_back(field());
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

		if (i != std::end(fields_)) returnvalue = i->value == "true";

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

		if (i != std::end(fields_)) returnvalue = std::stoi(i->value);

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

		if (i != std::end(fields_)) returnvalue = i->value;

		return returnvalue;
	}

	inline std::vector<fields::value_type>::reverse_iterator last_new_field() { return fields_.rbegin(); }

	inline const std::string& get(const char* name) const
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

	inline void set(const std::string& name, const std::string& value)
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field& f) { return http::util::case_insensitive_equal(f.name, name); });

		if (i != std::end(fields_))
		{
			i->value = value;
		}
		else
		{
			http::field field_(name, value);
			fields_.emplace_back(std::move(field_));
		}
	}

	inline size_t size() const noexcept { return fields_.size(); }

	const http::field& operator[](size_t index) const noexcept { return fields_[index]; }
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
	using query_params = http::fields;
	friend class http::session_handler;
	friend class http::request_parser;

protected:
	std::string method_;
	std::string url_requested_;
	std::string target_;
	query_params params_;
	unsigned int version_nr_ = 11;

public:
	header() = default;
	const std::string& method() const { return method_; }
	const std::string& target() const { return target_; }
	const std::string& url_requested() const { return url_requested_; }
	const unsigned int& version_nr() const { return version_nr_; }
	const std::string version() const
	{
		std::string ret = "HTTP 1.0";

		if (version_nr_ == 10) ret = "HTTP 1.0";

		return ret;
	}
	void target(const std::string& target) { target_ = target; }

	query_params& query() { return params_; };

	void headers_reset()
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

		ss << method_ << " " << target_ << " HTTP/";

		if (version_nr() == 11)
			ss << "1.1\r\n";
		else
			ss << "1.0\r\n";

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
	http::status::status_t status_ = http::status::bad_request;
	unsigned int status_nr_ = 400;
	unsigned int version_nr_ = 11;

	friend class http::response_parser;

public:
	header() = default;
	const unsigned int& version_nr() const noexcept { return version_nr_; }
	void version(unsigned int value) noexcept { version_nr_ = value; }
	void status(http::status::status_t status) { status_ = status; }
	http::status::status_t status() const { return status_; }

	const std::string version() const
	{
		std::string ret = "HTTP 1.1";

		if (version_nr_ == 10) ret = "HTTP 1.0";

		return ret;
	}

	void headers_reset()
	{
		this->fields_.clear();
		version_nr_ = 0;
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
} const mappings[] = { { "json", "application/json" }, { "text", "text/plain" }, { "ico", "image/x-icon" }, { "gif", "image/gif" }, { "htm", "text/html" },
					   { "html", "text/html" },		   { "jpg", "image/jpeg" },  { "jpeg", "image/jpeg" },  { "png", "image/png" }, { nullptr, nullptr } };

static std::string extension_to_type(const std::string& extension)
{
	if (extension.find_first_of('/') != std::string::npos)
		return extension;
	else
	{
		for (const auto& m : mappings) // NOLINT: trust me i now what i am doing...
		{
			if (m.extension == extension)
			{
				return m.mime_type;
			}
		}
	}
	return "application/octet-stream";
}
} // namespace mime_types

template <message_specializations specialization> class message : public header<specialization>
{
	// friend response_parser;
	// friend request_parser;

private:
	std::string body_;

public:
	message() = default;
	~message() = default;

	message(const message&) = default;
	message(message&&) = default;

	message& operator=(const message&) = default;
	message& operator=(message&&) = default;

	// TODO use enableif....
	message(const std::string& method, const std::string& target, const int version_nr = 11)
	{
		header<specialization>::version_nr_ = version_nr;
		header<specialization>::method_ = method;
		header<specialization>::target_ = target;
	}

	std::string target() const { return header<specialization>::target_; }

	void target(const std::string& target) { header<specialization>::target_ = target; }

	const std::vector<http::field>& headers() { return header<specialization>::fields_; }

	void reset()
	{
		header<specialization>::headers_reset();
		this->body_.clear();
	}

	std::string& body() { return body_; }

	const std::string& body() const { return body_; }

	bool chunked() const { return (http::fields::get("Transfer-Encoding") == "chunked"); }

	void chunked(bool value)
	{
		if (value)
			http::fields::set("Transfer-Encoding", "chunked");
		else
			http::fields::set("Transfer-Encoding", "none");
	}

	bool has_content_lenght() const
	{
		if (http::fields::get("Content-Length").empty())
			return false;
		else
			return true;
	}

	void type(const std::string& content_type) { http::fields::set("Content-Type", mime_types::extension_to_type(content_type)); }

	void result(http::status::status_t status)
	{
		http::header<specialization>::status(status);

		if (http::header<specialization>::status() != http::status::ok)
		{
			body_ += "status: " + std::to_string(http::header<specialization>::status());
		}
	}

	void content_length(uint64_t const& length) { http::fields::set("Content-Length", std::to_string(length)); }

	uint64_t content_length() const
	{
		auto content_length_ = http::fields::get("Content-Length");

		if (content_length_.empty())
			return 0;
		else
			return std::stoul(content_length_);
	}

	bool http_version11() const { return http::header<request_specialization>::version_nr() == 11; }

	bool connection_close() const
	{
		if (http::util::case_insensitive_equal(http::fields::get("Connection"), "close"))
			return true;
		else
			return false;
	}

	bool connection_keep_alive() const
	{
		if (http::util::case_insensitive_equal(http::fields::get("Connection"), "Keep-Alive"))
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
	request_parser() noexcept = default;

	void reset() { state_ = method_start; };

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

			if (result == good)
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
	} state_
		= { method_start };

public:
	static std::string url_decode(const std::string& in)
	{
		std::string ret;
		ret.reserve(in.size());

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
						ret += static_cast<char>(value);
						i += 2;
					}
					else
					{
						return "";
					}
				}
				else
				{
					return "";
				}
			}
			else if (in[i] == '+')
			{
				ret += ' ';
			}
			else
			{
				ret += in[i];
			}
		}
		return ret;
	}

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

class response_parser
{
public:
	response_parser() noexcept
		: state_(http_version_h){};

	void reset() { state_ = http_version_h; };

	enum result_type
	{
		good,
		bad,
		indeterminate
	};

	template <typename InputIterator> std::tuple<result_type, InputIterator> parse(http::response_message& req, InputIterator begin, InputIterator end)
	{
		auto data_size = end - begin;

		while (begin != end)
		{
			result_type result = consume(req, *begin++);

			if (result == good)
			{
				state_ = http_version_h;

				std::copy(begin, end, std::back_inserter(req.body()));

				return std::make_tuple(result, begin);
			}
			else if (result == bad)
			{
				state_ = http_version_h;
				return std::make_tuple(result, begin);
			}
		}

		return std::make_tuple(indeterminate, begin);
	}

private:
	result_type consume(http::response_message& res, char input)
	{
		switch (state_)
		{
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
				res.version_nr_ = 0;
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
				res.version_nr_ = (10 * (input - '0'));
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
				res.version_nr_ = (10 * (input - '0'));
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case http_version_minor_start:
			if (is_digit(input))
			{
				res.version_nr_ = res.version_nr_ + (input - '0');
				state_ = http_version_minor;
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case http_version_minor:
			if (input == ' ')
			{
				state_ = space_before_status_code;
				return indeterminate;
			}
			else if (is_digit(input))
			{
				res.version_nr_ = res.version_nr_ + (input - '0');
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case space_before_status_code:
			if (is_digit(input))
			{
				res.status_nr_ = (100 * (input - '0'));

				state_ = status_code_1;
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case status_code_1:
			if (is_digit(input))
			{
				res.status_nr_ += (10 * (input - '0'));

				state_ = status_code_2;
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case status_code_2:
			if (is_digit(input))
			{
				res.status_nr_ += (1 * (input - '0'));

				res.status_ = http::status::to_status(res.status_nr_);
				state_ = status_code_3;
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case status_code_3:
			if (input == ' ')
			{
				state_ = space_after_status_code;
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case space_after_status_code:
			if (is_char(input) && !is_ctl(input) && !is_tspecial(input))
			{
				state_ = status_phrase;
				res.reason_.push_back(input);
				return indeterminate;
			}
			else
			{
				return bad;
			}
		case status_phrase:
			if (input == '\r')
			{
				state_ = expecting_newline_1;
				return indeterminate;
			}
			else if (is_ctl(input) || is_tspecial(input))
			{
				return bad;
			}
			else
			{
				res.reason_.push_back(input);
				return indeterminate;
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
			else if (!res.fields_empty() && (input == ' ' || input == '\t'))
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
				auto i = res.new_field();
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
				res.last_new_field()->value.push_back(input);
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
				res.last_new_field()->name.push_back(input);
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
				res.last_new_field()->value.push_back(input);
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
		space_before_status_code,
		status_code_1,
		status_code_2,
		status_code_3,
		space_after_status_code,
		status_phrase,
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
	} state_
		= { method_start };

public:
	static std::string url_decode(const std::string& in)
	{
		std::string ret;
		ret.reserve(in.size());

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
						ret += static_cast<char>(value);
						i += 2;
					}
					else
					{
						return "";
					}
				}
				else
				{
					return "";
				}
			}
			else if (in[i] == '+')
			{
				ret += ' ';
			}
			else
			{
				ret += in[i];
			}
		}
		return ret;
	}

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

class session_handler
{

public:
	using result_type = http::request_parser::result_type;

	session_handler() = delete;
	session_handler(const session_handler&) = default;
	session_handler(session_handler&&) = default;
	session_handler& operator=(const session_handler&) = default;
	session_handler& operator=(session_handler&&) = default;

	~session_handler() = default;

	session_handler(http::configuration& configuration)
		: configuration_(configuration)
		, keepalive_count_(configuration.get<int>("keepalive_count", 10))
		, keepalive_max_(configuration.get<int>("keepalive_timeout", 5))
		, t0_(std::chrono::steady_clock::now())
	{
	}

	template <typename InputIterator> std::tuple<request_parser::result_type, InputIterator> parse_request(InputIterator begin, InputIterator end)
	{
		return request_parser_.parse(request_, begin, end);
	}

	//	template <typename InputIterator> std::tuple<response_parser::result_type, InputIterator> parse_response(InputIterator begin, InputIterator end) { return
	// response_parser_.parse(response_, begin, end); }

	class url
	{
	public:
		url(std::string protocol, std::string hostname, std::string port, std::string target)
			: protocol_(std::move(protocol))
			, hostname_(std::move(hostname))
			, port_(std::move(port))
			, target_(std::move(target))
		{
		}

		url(const std::string& url)
		{
			// protocol://host:port/target
			// http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html

			auto p1 = url.find_first_of(':');

			protocol_ = url.substr(0, p1);

			auto p2 = url.find_first_of('/', p1 + 3);

			hostname_ = url.substr(p1 + 3, p2 - (p1 + 3));

			auto p3 = hostname_.find_last_of(':');

			if (p3 != std::string::npos)
			{
				port_ = hostname_.substr(p3 + 1);
				hostname_ = hostname_.substr(0, p3);
			}
			else
			{
				port_ = "80";
			}

			target_ = url.substr(p2);
		}

		const std::string& protocol() const noexcept { return protocol_; };
		const std::string& hostname() const noexcept { return hostname_; };
		const std::string& port() const noexcept { return port_; };
		const std::string& target() const noexcept { return target_; };

	private:
		std::string protocol_;
		std::string hostname_;
		std::string port_;
		std::string target_;
	};

	http::response_message get(const std::string& url_string, const http::response_header& headers = {})
	{
		http::response_message message;

		http::session_handler::url u{ url_string };

		http::request_message request{ "GET", u.target() };

		// request.headers_set(headers);

		request.set("Host", u.hostname() + ":" + u.port());

		network::tcp::resolver resolver;
		auto& results = resolver.resolve(u.hostname(), u.port());

		network::tcp::socket s;

		auto ec = network::connect(s, results);

		if (ec == network::error::success)
		{
			using data_store_buffer_t = std::array<char, 64>;
			data_store_buffer_t buffer{};
			auto c = std::begin(buffer);

			auto request_result_size = network::write(s, http::to_string(request));
			http::response_parser p;
			http::response_parser::result_type parse_result;

			if (request_result_size != -1)
			{
				do
				{
					auto response_result_size = network::read(s, network::buffer(buffer.data(), buffer.size()));

					if (response_result_size != -1)
					{
						std::tie(parse_result, c) = p.parse(message, buffer.begin(), buffer.begin() + response_result_size);

						if (parse_result == http::response_parser::result_type::good && message.content_length() > message.body().size())
						{
							message.body().reserve(message.content_length());

							do
							{
								auto response_result_size_body = network::read(s, network::buffer(buffer.data(), buffer.size()));
								if (response_result_size_body != -1)
								{
									message.body().append(buffer.begin(), buffer.end());
								}
								else
								{
									message = http::response_message();
									return message;
								}

							} while (response_result_size != -1 && message.body().size() < message.content_length());
						}
					}
				} while (parse_result == http::response_parser::result_type::indeterminate);
			}
		}
		return message;
	}

	template <typename router_t> void handle_request(router_t& router_)
	{
		std::string request_path;

		response_.type("text");
		response_.result(http::status::ok);
		response_.set("Server", configuration_.get<std::string>("server", "http/server/0"));
		response_.set("Host", configuration_.get<std::string>("host", "localhost:" + configuration_.get<std::string>("http_listen_port", "3000")));

		if (!http::request_parser::url_decode(request_.target(), request_path))
		{
			response_.result(http::status::bad_request);
			return;
		}

		if (request_path.empty() || request_path[0] != '/' || request_path.find("..") != std::string::npos)
		{
			response_.result(http::status::bad_request);
			return;
		}

		std::size_t last_slash_pos = request_path.find_last_of('/');
		std::size_t last_dot_pos = request_path.find_last_of('.');
		std::string extension;

		if (last_dot_pos != std::string::npos && last_dot_pos > last_slash_pos)
		{
			extension = request_path.substr(last_dot_pos + 1);
		}

		std::size_t query_pos = request_path.find_first_of("?#");

		if (query_pos != std::string::npos)
		{
			std::vector<std::string> tokens = http::util::split(request_path.substr(query_pos + 1), "&");

			request_path = request_path.substr(0, query_pos);
			for (auto& token : tokens)
			{
				std::vector<std::string> name_value = http::util::split(token, "=");

				std::string name_decoded = http::request_parser::url_decode(name_value[0]);
				std::string value_decoded = (name_value.size() == 2) ? http::request_parser::url_decode(name_value[1]) : "";

				request_.query().set(name_decoded, value_decoded);
			}
		}

		if (request_.get("Content-Encoding") == "gzip")
		{
			request_.body() = gzip::decompress(request_.body().c_str(), request_.content_length());
		}

		// std::string url_1 = url_requested.substr(0, request_.find_first_of('?'));

		request_.url_requested_ = request_.target_; //.substr(0, request_.target_.find_first_of('?'));
		request_.target_ = request_path;

		bool continue_with_routing = router_.call_middleware(*this);

		if (continue_with_routing)
		{
			t0_ = std::chrono::steady_clock::now();
			t1_ = t0_;

			switch (router_.call_route(*this))
			{
			case http::router_result::match_found:
			{
				// Route has a valid handler, response body is set.
				// Check bodys size and set headers.
				response_.content_length(response_.body().length());

				break;
			}
			case http::router_result::no_method:
			{
				response_.result(http::status::method_not_allowed);
				response_.content_length(response_.body().length());
				break;
			}
			case http::router_result::no_route:
			{
				auto static_result = router_.serve_static_content(*this);

				if (static_result)
				{
					if (request_path[request_path.size() - 1] == '/')
					{
						request_path = request_.target() + "index.html";
						request_.target(request_path);
						extension = "html";
					}

					// Static content route.
					// Check filesize and set headers.

					auto content_size = fs::file_size(request_.target());

					if (content_size == 0) // TODO: empty  files are ok?
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
				else
				{
					response_.result(http::status::not_found);
					response_.content_length(response_.body().length());
				}
				break;
			}
			}
		}
		else
		{
			response_.content_length(response_.body().length());
		}

		// set connection headers in the response.request_
		// && (response_.status() == http::status::ok || response_.status() == http::status::created)
		// && (response_.status() == http::status::ok || response_.status() == http::status::created)
		if ((request_.http_version11() == true && keepalive_count() > 1 && request_.connection_close() == false)
			|| (request_.http_version11() == false && request_.connection_keep_alive() && keepalive_count() > 1 && request_.connection_close() == false))
		{
			keepalive_count_decr();
			response_.set("Connection", "Keep-Alive");
			// response_.set("Keep-Alive", std::string("timeout=") + std::to_string(keepalive_max()) + ", max=" +std::to_string(keepalive_count()));
		}
		else
		{
			response_.set("Connection", "close");
		}
	}

	void keepalive_count_decr() { --keepalive_count_; };
	int keepalive_count() const { return keepalive_count_; };

	void keepalive_max(const int& keepalive_max) { keepalive_max_ = keepalive_max; };
	int keepalive_max() const { return keepalive_max_; };

	http::request_parser& request_parser() { return request_parser_; };
	http::response_message& response() { return response_; };
	http::request_message& request() { return request_; };

	void reset()
	{
		t0_ = std::chrono::steady_clock::now();

		request_parser_.reset();
		request_.reset();
		response_.reset();
	}

	std::chrono::steady_clock::time_point t0() const noexcept { return t0_; };
	std::chrono::steady_clock::time_point t1() const noexcept { return t1_; };

private:
	http::request_message request_;
	http::response_message response_;
	http::request_parser request_parser_;
	http::configuration& configuration_;

	int keepalive_count_;
	int keepalive_max_;

	std::chrono::steady_clock::time_point t0_;
	std::chrono::steady_clock::time_point t1_;
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
		static std::string no_ret = "";

		if (it != parameters.end()) // if found
			return it->second;

		return no_ret;
	}

private:
	std::map<std::string, std::string> parameters;
}; // < class Params

using session_handler_type = http::session_handler;

using route_function_t = std::function<void(session_handler_type& session, const http::api::params& params)>;
using middleware_function_t = std::function<bool(session_handler_type& session, const http::api::params& params)>;

template <typename R = route_function_t> class route
{
public:
	route(const std::string& method, const std::string& route, const R& endpoint)
		: method_(method)
		, route_(route)
		, endpoint_(endpoint)
	{
		size_t b = route_.find_first_of('/');
		size_t e = route_.find_first_of('/', b + 1);
		size_t token = 0;

		for (token = 0; b != std::string::npos; token++)
		{
			std::string current_token = route.substr(b, e - b);
			tokens_.emplace_back(std::move(current_token));

			if (e == std::string::npos) break;

			b = route_.find_first_of('/', e);
			e = route_.find_first_of('/', b + 1);
		}
	};

	struct route_metrics
	{
		route_metrics() = default;
		route_metrics(const route_metrics& r)
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
		}

		route_metrics& operator=(const route_metrics& r)
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
		}

		route_metrics(route_metrics&& r)
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
		}

		route_metrics& operator=(route_metrics&& r)
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
		}

		std::atomic<std::chrono::high_resolution_clock::duration> request_latency_{};
		std::atomic<std::chrono::high_resolution_clock::duration> processing_duration_{};

		std::atomic<std::int64_t> hit_count_{ 0 };

		std::string to_string()
		{
			std::stringstream s;

			s << request_latency_.load().count() << "ms, " << processing_duration_.load().count() << "ms, " << hit_count_ << "x";

			return s.str();
		};
	};

	std::string method_;
	std::string route_;
	R endpoint_;
	std::vector<std::string> tokens_;
	route_metrics metrics_;

	void update_metrics(std::chrono::high_resolution_clock::duration request_duration, std::chrono::high_resolution_clock::duration new_processing_duration_)
	{
		metrics_.request_latency_.store(request_duration);
		metrics_.processing_duration_.store(new_processing_duration_);
		metrics_.hit_count_++;
	}

	route_metrics& metrics() { return metrics_; }

	router_result::router_result_type match(const std::string& method, const std::string& url, params& params) const
	{
		// route: /route/:param1/subroute/:param2/subroute
		// url:   /route/parameter

		if (url == route_)
		{
			if (method == method_)
				return router_result::match_found;
			else
				return router_result::no_method;
		}

		// std::vector<std::string> tokens;

		// token = /-----

		auto b = url.find_first_of('/');
		auto e = url.find_first_of('/', b + 1);
		size_t token = 0;
		bool match = false;

		for (token = 0; ((b != std::string::npos) && (token < tokens_.size())); token++)
		{
			// std::string current_token = url.substr(b, e - b);

			if (tokens_[token].size() > 2 && (tokens_[token][1] == ':' || tokens_[token][1] == '{'))
			{
				std::string value = url.substr(b + 1, e - b - 1);

				http::request_parser::url_decode(url.substr(b + 1, e - b - 1), value);

				if (tokens_[token][1] == ':')
				{
					params.insert(tokens_[token].substr(2, tokens_[token].size() - 2), value);
				}
				else
				{
					params.insert(tokens_[token].substr(2, tokens_[token].size() - 3), value);
				}
			}
			else if (tokens_[token] != url.substr(b, e - b))
			{
				match = false;
				break;
			}
			/*			else if (tokens_.size() - 1 == token)
						{
							// still matches, this is the last token
							match = true;
						}*/

			b = url.find_first_of('/', e);
			e = url.find_first_of('/', b + 1);

			if ((b == std::string::npos) && (tokens_.size() - 1 == token))
			{
				match = true;
				break;
			}
			else if (b == std::string::npos)
			{
				match = false;
				break;
			}
		}

		if (match && method_ == method)
			return router_result::match_found;
		else if (match)
			return router_result::no_method;
		else
			return router_result::no_route;
	}
};

template <typename M = middleware_function_t> class middelware
{
public:
	middelware(const std::string& route, M endpoint)
		: route_(route)
		, endpoint_(endpoint)
	{
		size_t token = 0;

		// token = /-----

		size_t b = route.find_first_of('/');
		size_t e = route.find_first_of('/', b + 1);

		for (token = 0; b != std::string::npos; token++)
		{
			std::string current_token = route.substr(b, e - b);
			tokens_.emplace_back(std::move(current_token));

			if (e == std::string::npos) break;

			b = route.find_first_of('/', e);
			e = route.find_first_of('/', b + 1);
		}
	};

	std::string route_;
	M endpoint_;
	std::vector<std::string> tokens_;

	bool match(const std::string& url_requested, params& params) const
	{
		// route: /route/:param1/subroute/:param2/subroute
		// url:   /route/parameter

		std::string url = url_requested.substr(0, url_requested.find_first_of('?'));

		if (url.find(route_) == 0) // url starts with route
		{
			return true;
		}

		size_t token = 0;

		// token = /-----
		auto b = url.find_first_of('/');
		auto e = url.find_first_of('/', b + 1);

		bool match = false;

		for (token = 0; ((b != std::string::npos) && (token < tokens_.size())); token++)
		{
			// std::string current_token = url.substr(b, e - b);

			if (tokens_[token].size() > 2 && (tokens_[token][1] == ':' || tokens_[token][1] == '{'))
			{
				if (tokens_[token][1] == ':')
				{
					params.insert(tokens_[token].substr(2, tokens_[token].size() - 2), url.substr(b + 1, e - b - 1));
				}
				else
				{
					params.insert(tokens_[token].substr(2, tokens_[token].size() - 3), url.substr(b + 1, e - b - 1));
				}
			}
			else if (tokens_[token] != url.substr(b, e - b))
			{
				match = false;
				break;
			}

			b = url.find_first_of('/', e);
			e = url.find_first_of('/', b + 1);

			if ((b == std::string::npos) && (tokens_.size() - 1 == token))
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

	std::string to_string()
	{
		std::stringstream s;

		for (auto& route : route_registry_)
		{
			s << R"(")" << route.route_ << R"(",)" << route.method_ << ", " << route.metrics().to_string() << "\n";
		}

		return s.str();
	}

	void use(const std::string& path) { static_content_routes.emplace_back(path); }

	void on_http_method(const std::string& route, const std::string& http_method, R api_method) { route_registry_.emplace_back(http_method, route, api_method); }

	void on_busy(std::function<bool()> on_busy_callback) { on_busy_ = on_busy_callback; }

	void on_idle(std::function<bool()> on_idle_callback) { on_idle_ = on_idle_callback; }

	void on_get(const std::string& route, R api_method) { route_registry_.emplace_back("GET", route, api_method); }

	void on_post(const std::string& route, R api_method) { route_registry_.emplace_back("POST", route, api_method); }

	void on_head(const std::string& route, R api_method) { route_registry_.emplace_back("HEAD", route, api_method); }

	void on_put(const std::string& route, R api_method) { route_registry_.emplace_back("PUT", route, api_method); }

	void on_update(const std::string& route, R api_method) { route_registry_.emplace_back("UPDATE", route, api_method); }

	void on_delete(const std::string& route, R api_method) { route_registry_.emplace_back("DELETE", route, api_method); }

	void on_patch(const std::string& route, R api_method) { route_registry_.emplace_back("PATCH", route, api_method); }

	void on_option(const std::string& route, R api_method) { route_registry_.emplace_back("OPTION", route, api_method); }

	void use(const std::string route, middleware_function_t middleware_function) { api_middleware_table.emplace_back(route, middleware_function); };

	bool serve_static_content(session_handler_type& session)
	{
		// auto static_path = std::find(std::begin(this->static_content_routes), std::end(this->static_content_routes),
		// session.request().target());
		for (auto& static_route : static_content_routes)
		{
			std::string url = session.request().url_requested().substr(0, session.request().url_requested().find_first_of('?'));

			if (url.find(static_route) == 0)
			{
				auto file_path = doc_root_ + session.request().target();
				session.request().target(file_path);

				return true;
			}
		}
		return false;
	}

	bool call_middleware(session_handler_type& session) const
	{
		auto result = true;
		for (auto& middleware : api_middleware_table)
		{
			params params_;

			if (middleware.match(session.request().target(), params_))
			{
				if ((result = middleware.endpoint_(session, params_)) == false) break;
			}
		}

		return result;
	}

	http::router_result::router_result_type call_route(session_handler_type& session)
	{
		// std::cout << session.request().target() << "\n";

		auto best_result = http::router_result::router_result_type::no_route;

		if (!route_registry_.empty())
		{
			std::string url = session.request().url_requested().substr(0, session.request().url_requested().find_first_of('?'));

			for (auto& route : route_registry_)
			{
				params params_;

				auto result = route.match(session.request().method(), url, params_);

				if (result == router_result::router_result_type::match_found)
				{
					auto t0 = std::chrono::steady_clock::now();

					route.endpoint_(session, params_);
					auto t1 = std::chrono::steady_clock::now();

					route.update_metrics(std::chrono::duration<std::int64_t, std::nano>(t0 - session.t0()), std::chrono::duration<std::int64_t, std::nano>(t1 - t0));
					return result;
				}
				else if (result == router_result::router_result_type::no_method)
				{
					best_result = result;
				}
			}
		}

		return best_result;
	}

	bool call_on_busy()
	{
		if (on_busy_)
			return on_busy_();
		else
			return false;
	}

	bool call_on_idle()
	{
		if (on_idle_)
			return on_idle_();
		else
			return true;
	}

protected:
	std::function<bool()> on_busy_;
	std::function<bool()> on_idle_;
	std::vector<api::route<route_function_t>> route_registry_;
	std::string doc_root_;
	std::vector<std::string> static_content_routes;
	std::vector<api::middelware<middleware_function_t>> api_middleware_table;
};
} // namespace api

namespace basic
{

class server
{
public:
	server(http::configuration& configuration)
		: router_(configuration.get<std::string>("doc_root", "/var/www"))
		, configuration_(configuration){};

	server(const server&) = delete;
	server(server&&) = delete;

	server& operator=(server&&) = delete;
	server& operator=(const server&) = delete;

	~server() = default;

	// std::atomic<bool>& active() { return active_; }

	virtual void start_server() { active_ = true; }

	class server_manager
	{
	private:
		std::string server_information_;
		std::string router_information_;

		size_t requests_handled_{ 0 };
		size_t requests_handled_prev_{ 0 };
		size_t requests_per_second_{ 0 };

		size_t connections_accepted_{ 0 };
		size_t connections_accepted_prev_{ 0 };
		size_t connections_accepted_per_second_{ 0 };

		size_t connections_current_{ 0 };
		size_t connections_highest_{ 0 };

		size_t health_checks_received_consecutive_{ 0 };

		bool is_idle_{ false };
		bool is_busy_{ false };

		std::chrono::steady_clock::time_point t0_;
		std::chrono::steady_clock::time_point idle_t0_;

		std::vector<std::string> access_log_;
		std::mutex mutex_;

	public:
		server_manager() noexcept
			: server_information_("")
			, router_information_("")
			, t0_(std::chrono::steady_clock::now())
			, idle_t0_()
		{
			access_log_.reserve(32);
		};

		void update_stats()
		{
			std::lock_guard<std::mutex> g(mutex_);
			std::chrono::steady_clock::time_point t1_ = std::chrono::steady_clock::now();
			std::chrono::duration<std::int64_t, std::nano> duration(t1_ - t0_);

			requests_per_second_ = ((requests_handled_ - requests_handled_prev_) * 100000000000) / duration.count();
			connections_accepted_per_second_ = ((connections_accepted_ - connections_accepted_prev_) * 100000000000) / duration.count();

			t0_ = std::chrono::steady_clock::now();

			requests_handled_prev_ = requests_handled_;
			connections_accepted_prev_ = connections_accepted_;
		}

		void idle(bool value)
		{
			std::lock_guard<std::mutex> g(mutex_);

			if (!is_idle_ && value == true)
				idle_t0_ = std::chrono::steady_clock::now();
			else if (is_idle_ && value == false)
				idle_t0_ = {};

			is_idle_ = value;
			is_busy_ = false;
		}

		std::int64_t idle_duration()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return is_idle_ ? std::chrono::nanoseconds(std::chrono::steady_clock::now() - idle_t0_).count() / 1000000000 : 0;
		}

		bool is_idle()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return is_idle_;
		}

		void busy(bool value)
		{
			std::lock_guard<std::mutex> g(mutex_);
			is_busy_ = value;
			is_idle_ = false;
		}

		bool is_busy()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return is_busy_;
		}

		size_t requests_handled()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return requests_handled_;
		}

		void requests_handled(size_t nr)
		{
			std::lock_guard<std::mutex> g(mutex_);
			requests_handled_ = nr;
		}

		size_t connections_accepted()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return connections_accepted_;
		}

		void connections_accepted_increase()
		{
			std::lock_guard<std::mutex> g(mutex_);
			connections_accepted_++;
		}

		void connections_accepted_decrease()
		{
			std::lock_guard<std::mutex> g(mutex_);
			connections_accepted_--;
		}

		size_t connections_current()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return connections_current_;
		}

		void connections_current_increase()
		{
			std::lock_guard<std::mutex> g(mutex_);
			connections_current_++;
			if (connections_current_ > connections_highest_) connections_highest_ = connections_current_;
		}

		void connections_current_decrease()
		{
			std::lock_guard<std::mutex> g(mutex_);
			connections_current_--;
		}

		size_t connections_highest()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return connections_highest_;
		}

		void health_checks_received_increase()
		{
			std::lock_guard<std::mutex> g(mutex_);
			health_checks_received_consecutive_++;
		}

		size_t health_checks_received_consecutive()
		{
			std::lock_guard<std::mutex> g(mutex_);
			return health_checks_received_consecutive_;
		}

		void health_checks_received_consecutive_increase()
		{
			std::lock_guard<std::mutex> g(mutex_);
			health_checks_received_consecutive_++;
		}

		void health_checks_received_consecutive_reset()
		{
			std::lock_guard<std::mutex> g(mutex_);
			health_checks_received_consecutive_ = 0;
		}

		void log_access(http::session_handler& session)
		{
			std::stringstream s;
			std::lock_guard<std::mutex> g(mutex_);

			s << R"(")" << session.request().get("Remote_Addr") << R"(")"
			  << R"( - ")" << session.request().method() << " " << session.request().url_requested() << " " << session.request().version() << R"(")"
			  << " - " << session.response().status() << " - " << session.response().content_length() << " - " << session.request().content_length() << R"( - ")"
			  << session.request().get("User-Agent") << "\"\n";

			access_log_.emplace_back(s.str());

			if (access_log_.size() >= 32) access_log_.erase(access_log_.begin());
		}

		void server_information(std::string info)
		{
			std::lock_guard<std::mutex> g(mutex_);
			server_information_ = std::move(info);
		}

		void router_information(std::string info)
		{
			std::lock_guard<std::mutex> g(mutex_);
			router_information_ = std::move(info);
		}

		std::string to_string()
		{
			std::lock_guard<std::mutex> g(mutex_);

			std::stringstream s;

			s << "Server Configuration:\n" << server_information_ << "\n";

			s << "\nStatistics:\n";
			s << "connections_accepted: " << connections_accepted_ << "\n";
			s << "connections_highest: " << connections_highest_ << "\n";
			s << "connections_current: " << connections_current_ << "\n";
			s << "requests_handled: " << requests_handled_ << "\n";
			s << "health_checks_received_consecutive: " << health_checks_received_consecutive_ << "\n";
			s << "busy: " << is_busy_ << "\n";
			s << "idle: " << is_idle_ << "\n";
			s << "requests_per_second: " << requests_per_second_ / 100.0 << "\n";
			s << "connections_accepted_per_second: " << connections_accepted_per_second_ / 100.0 << "\n";

			s << "\nEndPoints:\n" << router_information_ << "\n";

			s << "\nAccess Log:\n";

			for (auto& access_log_entry : access_log_)
				s << access_log_entry;

			return s.str();
		}
	};

	server_manager& manager() { return manager_; }

protected:
	server_manager manager_;
	http::api::router<> router_;
	http::configuration& configuration_;
	std::atomic<bool> active_{ true };
}; // namespace basic

namespace threaded
{

class server : public http::basic::server
{
	using socket_t = SOCKET;

public:
	server(http::configuration& configuration)
		: http::basic::server{ configuration }
		, thread_count_(configuration.get<int>("thread_count", 5))
		, http_listen_port_begin_(configuration.get<int>("http_listen_port_begin", (std::getenv("PORT_NUMBER") ? std::atoi(getenv("PORT_NUMBER")) : 3000)))
		, http_listen_port_end_(configuration.get<int>("http_listen_port_end", http_listen_port_begin_))
		, http_listen_port_(0)
		, endpoint_http_(http_listen_port_begin_)
		, https_listen_port_begin_(configuration.get<int>("https_listen_port_begin", (std::getenv("PORT_NUMBER") ? std::atoi(getenv("PORT_NUMBER")) : 2000)))
		, https_listen_port_end_(configuration.get<int>("https_listen_port_end", http_listen_port_begin_))
		, https_listen_port_(0)
		, endpoint_https_(https_listen_port_begin_)
		, connection_timeout_(configuration.get<int>("keepalive_timeout", 4))
		, gzip_min_length_(configuration.get<size_t>("gzip_min_length", 1024 * 10))
		, http_connection_thread_([this]() { http_listener_handler(); })
		, https_connection_thread_([this]() { https_listener_handler(); })
		, http_connection_queue_thread_([this]() { http_connection_queue_handler(); })
		, https_connection_queue_thread_([this]() { https_connection_queue_handler(); })
	{
	}

	~server()
	{
		http_connection_thread_.join();
		https_connection_thread_.join();
		http_connection_queue_thread_.join();
		https_connection_queue_thread_.join();
	}

	server() = delete;
	server(server&&) = delete;
	server(const server&) = delete;

	server& operator=(const server&) = delete;
	server& operator=(const server&&) = delete;

	void start_server() override
	{
		manager_.server_information(http::basic::server::configuration_.to_string());
		manager_.router_information(http::basic::server::router_.to_string());

		http::basic::server::start_server();
	}

	virtual void deactivate()
	{
		http::basic::server::active_ = false;
		// std::cout << "\ndeactivated!\n";
	}

	void http_connection_queue_handler()
	{
		while (active_ == true)
		{
			std::unique_lock<std::mutex> m(http_connection_queue_mutex_);

			http_connection_queue_has_connection_.wait_for(m, std::chrono::seconds(1));

			// std::cout << "http_connection_queue_:" << std::to_string(http_connection_queue_.size()) << "\n";

			if (http_connection_queue_.empty())
			{
				std::this_thread::yield();

				manager_.update_stats();

				if (manager_.connections_current() == 0)
				{
					if (router_.call_on_idle())
					{
						manager_.idle(true);
					}
				}
			}
			else
			{
				manager_.idle(false);

				if (manager_.connections_current() >= 4)
				{
					manager_.busy(router_.call_on_busy());
				}
				else
				{
					manager_.busy(false);
				}

				while (!http_connection_queue_.empty())
				{

					// network::timeout(http_socket, connection_timeout_);
					// network::tcp_nodelay(http_socket, 1);

					std::thread connection_thread(
						[
                            new_connection_handler = std::make_shared<connection_handler<network::tcp::socket>>(
							    *this, 
                                std::move(http_connection_queue_.front()), 
                                connection_timeout_, 
                                gzip_min_length_
                            )
                        ]() { new_connection_handler->proceed(); }
                    );
					connection_thread.detach();

					http_connection_queue_.pop();

					manager_.connections_accepted_increase();
					manager_.connections_current_increase();
				}
			}
		}
		// std::cout << "http_connection_queue_::end1\n";
	}

	void https_connection_queue_handler()
	{
		while (active_ == true)
		{
			std::unique_lock<std::mutex> m(https_connection_queue_mutex_);

			https_connection_queue_has_connection_.wait_for(m, std::chrono::seconds(1));

			// std::cout << "https_connection_queue_:" << std::to_string(https_connection_queue_.size()) << "\n";
			if (https_connection_queue_.empty())
			{
				std::this_thread::yield();

				manager_.update_stats();

				/*	if (manager_.connections_current() == 0)
					{
						if (router_.call_on_idle())
						{
							manager_.idle(true);
						}
					}*/
			}
			else
			{
				manager_.idle(false);

				if (manager_.connections_current() >= 4)
				{
					manager_.busy(router_.call_on_busy());
				}
				else
				{
					manager_.busy(false);
				}

				while (!https_connection_queue_.empty())
				{
					// network::timeout(http_socket, connection_timeout_);
					// network::tcp_nodelay(http_socket, 1);

					std::thread connection_thread(
						[new_connection_handler = std::make_shared<connection_handler<network::ssl::stream<network::tcp::socket>>>(
							 *this, std::move(https_connection_queue_.front()), connection_timeout_, gzip_min_length_)]() { new_connection_handler->proceed(); });
					connection_thread.detach();
					https_connection_queue_.pop();

					manager_.connections_accepted_increase();
					manager_.connections_current_increase();
				}
			}
		}
		// std::cout << "https_connection_queue_::end2\n";
	}

	void https_listener_handler()
	{

		try
		{
			// network::tcp::v6 endpoint_https(https_listen_port_begin_);

			network::tcp::acceptor acceptor_https{};

			acceptor_https.open(endpoint_https_.protocol());

			network::ipv6only(endpoint_https_.socket(), 0);

			network::use_portsharding(endpoint_https_.socket(), 1);

			// network::no_linger(endpoint_http.socket(), 1);

			network::error_code ec = network::error::success;

			for (https_listen_port_ = https_listen_port_begin_; https_listen_port_ <= https_listen_port_end_;)
			{
				acceptor_https.bind(endpoint_https_, ec);
				// std::cout << "binding https to: " << std::to_string(https_listen_port_) << "\n";

				if (ec == network::error::success)
				{
					// this->configuration_.set("https_listen_port", std::to_string(https_listen_port_));

					break;
				}
				else if (ec == network::error::address_in_use)
				{
					https_listen_port_++;
					endpoint_https_.port(https_listen_port_);
				}
			}

			if (ec)
			{
				throw std::runtime_error(
					std::string("cannot bind/listen to port in range: [ " + std::to_string(https_listen_port_begin_) + ":" + std::to_string(https_listen_port_end_) + " ]"));
				exit(-1);
			}

			network::ssl::context ssl_context(network::ssl::context::tlsv12);

			ssl_context.use_certificate_chain_file(configuration_.get<std::string>("ssl_certificate", std::string("")).c_str());
			ssl_context.use_private_key_file(configuration_.get<std::string>("ssl_certificate_key", std::string("")).c_str());

			acceptor_https.listen();

			while (active_ == true)
			{
				network::ssl::stream<network::tcp::socket> https_socket(ssl_context);
				ec = network::error::success;
				acceptor_https.accept(https_socket.lowest_layer(), ec, 5);

				if (ec == network::error::interrupted) break;
				if (ec == network::error::operation_would_block) continue;

				network::timeout(https_socket.lowest_layer(), connection_timeout_);
				https_socket.handshake(network::ssl::stream_base::server);

				if (https_socket.lowest_layer().lowest_layer() > 0)
				{
					std::unique_lock<std::mutex> m(https_connection_queue_mutex_);
					https_connection_queue_.push(std::move(https_socket));
					https_connection_queue_has_connection_.notify_one();
				}
			}
			// std::cout << "https_listener_handler_::end1\n";
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
			// network::tcp::v6 endpoint_http(http_listen_port_begin_);

			network::tcp::acceptor acceptor_http{};

			acceptor_http.open(endpoint_http_.protocol());

			if (http_listen_port_begin_ == http_listen_port_end_)
				network::reuse_address(endpoint_http_.socket(), 1);
			else
				network::reuse_address(endpoint_http_.socket(), 0);

			network::ipv6only(endpoint_http_.socket(), 0);

			network::use_portsharding(endpoint_http_.socket(), 1);

			// network::no_linger(endpoint_http.socket(), 1);

			network::error_code ec = network::error::success;

			for (http_listen_port_ = http_listen_port_begin_; http_listen_port_ <= http_listen_port_end_;)
			{
				acceptor_http.bind(endpoint_http_, ec);

				// network::no_linger(endpoint_http.socket(), 1);

				if (ec == network::error::success)
				{
					// std::scoped_lock<std::mutex> g(configuration_mutex_);
					// this->configuration_.set("http_listen_port", std::to_string(http_listen_port_));

					break;
				}
				else if (ec == network::error::address_in_use)
				{
					http_listen_port_++;
					endpoint_http_.port(http_listen_port_);
				}
			}

			if (ec)
			{
				throw std::runtime_error(
					std::string("cannot bind/listen to port in range: [ " + std::to_string(http_listen_port_begin_) + ":" + std::to_string(http_listen_port_end_) + " ]"));
				exit(-1);
			}

			acceptor_http.listen();

			while (active_ == true)
			{
				network::tcp::socket http_socket{ 0 };
				ec = network::error::success;

				acceptor_http.accept(http_socket, ec, 5);

				if (ec == network::error::interrupted) break;
				if (ec == network::error::operation_would_block) continue;

				if (http_socket.lowest_layer() > 0)
				{
					std::unique_lock<std::mutex> m(http_connection_queue_mutex_);
					http_connection_queue_.push(std::move(http_socket));
					http_connection_queue_has_connection_.notify_one();
				}
			}
			// std::cout << "https_listener_handler_::end2\n";
		}
		catch (...)
		{
			// TODO
		}
	}

	template <class S> class connection_handler
	{
	public:
		connection_handler(http::basic::threaded::server& server, S&& client_socket, int connection_timeout, size_t gzip_min_length)
			: server_(server)
			, client_socket_(std::move(client_socket))
			, session_handler_(server.configuration_)
			, connection_timeout_(connection_timeout)
			, gzip_min_length_(gzip_min_length)
			, bytes_received_(0)
			, bytes_send_(0)

		{
			/*			std::string port = std::to_string(server_.http_listen_port_);
						std::string msg = port + " open connection\n";

						std::cout << msg;*/
		}

		~connection_handler()
		{
			/*			std::string port = std::to_string(server_.http_listen_port_);
						std::string msg = port + " close connection after: " + std::to_string(bytes_received_) + " bytes, keepalive-count: " +
			   std::to_string(session_handler_.keepalive_count()) + "\n";

						std::cout << msg;*/

			network::shutdown(client_socket_, network::shutdown_send);
			network::closesocket(client_socket_);
			server_.manager().connections_current_decrease();
		}

		connection_handler(const connection_handler&) = delete;
		connection_handler(connection_handler&&) = delete;

		connection_handler& operator=(connection_handler&) = delete;
		connection_handler& operator=(const connection_handler&&) = delete;

		void proceed()
		{
			using data_store_buffer_t = std::array<char, 1024 * 8>;
			data_store_buffer_t buffer{};
			auto c = std::begin(buffer);
			while (true)
			{
				size_t left_of_buffer_size = buffer.size() - (c - std::begin(buffer));

				int ret = network::read(client_socket_, network::buffer(&(*c), left_of_buffer_size));

				if (ret <= 0)
				{
					break;
				}

				bytes_received_ += ret;

				http::session_handler::result_type parse_result;

				auto& response = session_handler_.response();
				auto& request = session_handler_.request();

				std::tie(parse_result, c) = session_handler_.parse_request(c, c + ret);

				if ((parse_result == http::request_parser::result_type::good) && (request.has_content_lenght()))
				{
					auto x = c - std::begin(buffer);

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

							bytes_received_ += ret;

							request.body().append(buffer.data(), buffer.data() + ret);

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

					if (parse_result == http::request_parser::result_type::good)
					{
						session_handler_.request().set("Remote_Addr", session_handler_.request().get("X-Forwarded-For", network::get_client_info(client_socket_)));

						session_handler_.handle_request(server_.router_);

						// bool health_check_ok = (session_handler_.request().get("X-Health-Check") == "ok");

						// if (!health_check_ok)
						{
							server_.manager().requests_handled(server_.manager().requests_handled() + 1);
							server_.manager().log_access(session_handler_);
						}
					}
					else
					{
						session_handler_.response().result(http::status::bad_request);
					}

					if (response.body().empty())
					{
						std::array<char, 1024 * 8> file_buffer{};

						{
							std::string headers = response.header_to_string();

							ret = network::write(client_socket_, network::buffer(&headers[0], headers.length()));

							std::ifstream is(session_handler_.request().target(), std::ios::in | std::ios::binary);

							is.seekg(0, std::ifstream::ios_base::beg);
							is.rdbuf()->pubsetbuf(file_buffer.data(), file_buffer.size());

							std::streamsize bytes_in = is.read(file_buffer.data(), file_buffer.size()).gcount();

							while (bytes_in > 0 && ret != -1)
							{
								ret = network::write(client_socket_, network::buffer(&file_buffer[0], static_cast<size_t>(bytes_in)));

								bytes_in = is.read(file_buffer.data(), file_buffer.size()).gcount();
							}
						}
					}
					else
					{
						if ((gzip_min_length_ < response.body().size()) && (session_handler_.request().get("Accept-Encoding").find("gzip") != std::string::npos))
						{
							response.body() = gzip::compress(response.body().c_str(), response.body().size());
							response.set("Content-Encoding", "gzip");
							response.set("Content-Length", std::to_string(response.body().size()));
						}

						// connection_data.store_response_data(http::to_string(response));
						ret = network::write(client_socket_, http::to_string(response));
					}

					if (response.connection_keep_alive() == true)
					{
						session_handler_.reset();
						// std::fill(buffer.begin(), buffer.end(),0);
						c = buffer.begin();
					}
					else
					{
						return;
					}
				}
				else if (parse_result == http::request_parser::result_type::indeterminate)
				{
					continue;
				}
			}
		}

	protected:
		http::basic::threaded::server& server_;
		S client_socket_;
		http::session_handler session_handler_;
		int connection_timeout_;
		size_t gzip_min_length_;
		size_t bytes_received_;
		size_t bytes_send_;

		/*		std::vector<char> data_request_;
				std::vector<char> data_response_;

				std::vector<char>& request_data() { return data_request_; }
				std::vector<char>& response_data() { return data_response_; }*/

		void reset_session()
		{
			session_handler_.reset();
			// data_request_.clear();
			// data_response_.clear();
		}
	};

private:
	int thread_count_;
	int http_listen_port_begin_;
	int http_listen_port_end_;
	int http_listen_port_;

	network::tcp::v6 endpoint_http_;

	int https_listen_port_begin_;
	int https_listen_port_end_;
	int https_listen_port_;

	network::tcp::v6 endpoint_https_;

	int connection_timeout_;
	size_t gzip_min_length_;

	std::condition_variable http_connection_queue_has_connection_;
	std::condition_variable https_connection_queue_has_connection_;

	std::mutex http_connection_queue_mutex_;
	std::mutex https_connection_queue_mutex_;
	std::mutex configuration_mutex_;

	std::queue<network::tcp::socket> http_connection_queue_;
	std::queue<network::ssl::stream<network::tcp::socket>> https_connection_queue_;

	std::thread http_connection_thread_;
	std::thread https_connection_thread_;

	std::thread http_connection_queue_thread_;
	std::thread https_connection_queue_thread_;
};

} // namespace threaded

} // namespace basic

} // namespace http

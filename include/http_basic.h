#pragma once

#include <cstdint>
#include <sys/stat.h>

#include <cstddef>
#include <cstring>
#include <cstdlib>

#include <algorithm>
#include <array>
#include <cassert>
#include <deque>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip> // put_time
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <ratio>
#include <sstream>
#include <stack>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <zlib.h>

#if !defined(USE_VCPKG_INCLUDES)
#include "nlohmann_json.hpp"
#else
#include "nlohmann/json.hpp"
#endif

using json = nlohmann::json;

#if !defined(HTTP_DO_NOT_USE_CURL)
#define CURL_STATICLIB
#include <curl/curl.h>
#endif

#if defined(_WIN32) && !defined(gmtime_r)
#define gmtime_r(X, Y) gmtime_s(Y, X)
#endif

#include "http_network.h"

#if __cplusplus > 1201402L
#include <shared_mutex>
using std14 = std;
#else
namespace std14
{

class shared_mutex
{
	using mutex_type = std::mutex;
	using cond_type = std::condition_variable;
	using count_type = unsigned;

	mutex_type mut_;
	cond_type gate1_;
	cond_type gate2_;
	count_type state_;

	static const count_type write_entered_ = 1U << (sizeof(count_type) * CHAR_BIT - 1);
	static const count_type n_readers_ = ~write_entered_;

public:
	shared_mutex() : state_(0) {}
	~shared_mutex() { std::lock_guard<mutex_type> _(mut_); }

	shared_mutex(const shared_mutex&) = delete;
	shared_mutex& operator=(const shared_mutex&) = delete;

	void lock()
	{
		std::unique_lock<mutex_type> lk(mut_);
		while (state_ & write_entered_)
			gate1_.wait(lk);
		state_ |= write_entered_;
		while (state_ & n_readers_)
			gate2_.wait(lk);
	}

	bool try_lock()
	{
		std::unique_lock<mutex_type> lk(mut_);
		if (state_ == 0)
		{
			state_ = write_entered_;
			return true;
		}
		return false;
	}

	void unlock()
	{
		std::lock_guard<mutex_type> _(mut_);
		state_ = 0;
		gate1_.notify_all();
	}

	// Shared ownership

	void lock_shared()
	{
		std::unique_lock<mutex_type> lk(mut_);
		while ((state_ & write_entered_) || (state_ & n_readers_) == n_readers_)
			gate1_.wait(lk);
		count_type num_readers = (state_ & n_readers_) + 1;
		state_ &= ~n_readers_;
		state_ |= num_readers;
	}

	void unlock_shared()
	{
		std::lock_guard<mutex_type> _(mut_);
		count_type num_readers = (state_ & n_readers_) - 1;
		state_ &= ~n_readers_;
		state_ |= num_readers;
		if (state_ & write_entered_)
		{
			if (num_readers == 0) gate2_.notify_one();
		}
		else
		{
			if (num_readers == n_readers_ - 1) gate1_.notify_one();
		}
	}
};

template <class T> class shared_lock
{
public:
	shared_lock(T& shared_mutex) : shared_mutex_(shared_mutex) { shared_mutex_.lock_shared(); };
	~shared_lock() { shared_mutex_.unlock_shared(); };

private:
	shared_mutex& shared_mutex_;
};

} // namespace std14
#endif

namespace util
{
static int pid_fd = -1;

#if !defined(WIN32)
inline void daemonize(const std::string& workdir, const std::string& lock_file)
{
	pid_t pid = 0;
	int fd;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0)
	{
		exit(EXIT_SUCCESS);
	}

	/* On success: The child process becomes session leader */
	if (setsid() < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* Ignore signal sent from child to parent process */
	signal(SIGCHLD, SIG_IGN);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0)
	{
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0)
	{
		exit(EXIT_SUCCESS);
	}

	/* Set new file permissions */
	umask(0);

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir(workdir.data());

	/* Close all open file descriptors */
	for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
	{
		close(fd);
	}

	/* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
	stdin = fopen("/dev/null", "r");
	stdout = fopen("/dev/null", "w+");
	stderr = fopen("/dev/null", "w+");

	/* Try to write PID of daemon to lockfile */
	if (lock_file.empty() == false)
	{
		char str[256];
		pid_fd = open(lock_file.data(), O_RDWR | O_CREAT, 0640);
		if (pid_fd < 0)
		{
			/* Can't open lockfile */
			exit(EXIT_FAILURE);
		}
		if (lockf(pid_fd, F_TLOCK, 0) < 0)
		{
			/* Can't lock file */
			exit(EXIT_FAILURE);
		}
		/* Get current PID */
		sprintf(str, "%d\n", getpid());
		/* Write PID to lockfile */
		write(pid_fd, str, strlen(str));
	}
}
#else
inline void daemonize(const std::string&, const std::string&) { std::cout << "Not implemented yet\n"; }
#endif

inline std::string to_lower(std::string input)
{
	std::transform(
		input.begin(), input.end(), input.begin(), [](char c) { return static_cast<char>(std::tolower(c)); });

	return input;
}

inline std::string to_upper(std::string input)
{
	std::transform(
		input.begin(), input.end(), input.begin(), [](char c) { return static_cast<char>(std::toupper(c)); });

	return input;
}

// inline std::string escape_json(const std::string& s)
//{
//	std::ostringstream ss;
//
//	for (const auto& c : s)
//	{
//		switch (c)
//		{
//			case '"':
//				ss << "\\\"";
//				break;
//			case '\\':
//				ss << "\\\\";
//				break;
//			case '\b':
//				ss << "\\b";
//				break;
//			case '\f':
//				ss << "\\f";
//				break;
//			case '\n':
//				ss << "\\n";
//				break;
//			case '\r':
//				ss << "\\r";
//				break;
//			case '\t':
//				ss << "\\t";
//				break;
//			default:
//				if (static_cast<signed char>(c) >= 0x00 && static_cast<signed char>(c) <= 0x1f)
//				{
//					ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
//				}
//				else
//				{
//					ss << c;
//				}
//		}
//	}
//	return ss.str();
//}

namespace case_insensitive
{

template <typename T> struct equal_to
{
	bool operator()(const T& lhs, const T& rhs) const
	{
		return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin(), [](char a, char b) {
				   return ((a > 96) && (a < 123) ? a ^= 0x20 : a) == ((b > 96) && (b < 123) ? b ^= 0x20 : b);
			   });
	}
};

} // namespace case_insensitive

namespace case_sensitive
{
template <typename T> struct equal_to
{
	bool operator()(const T& lhs, const T& rhs) const { return lhs == rhs; }
};
} // namespace case_sensitive

inline std::string return_current_time_and_date()
{
	std::string result;
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	auto tmp_tm = std::tm{};
	(void)gmtime_r(&in_time_t, &tmp_tm);
	std::array<char, 32> tmp{ char{ 0 } };
	auto size = strftime(&tmp[0], sizeof(tmp), "%a, %d %b %Y %H:%M:%S GMT", &tmp_tm);
	assert(size <= tmp.size());
	result.assign(&tmp[0], size);

	return result;
}

namespace split_opt
{
enum empties_t
{
	empties_ok,
	no_empties
};
};

template <typename T>
T& split_(
	T& result,
	const typename T::value_type& s,
	const typename T::value_type& delimiters,
	split_opt::empties_t empties = split_opt::empties_ok)
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

enum split_options
{
	all_tokens,
	stop_on_first_delimiter_found
};

inline std::vector<std::string>
split(const std::string& str, const std::string& delimiters, split_options options = split_options::all_tokens)
{
	std::vector<std::string> output;

	// output.reserve(str.size() / 2);

	auto first = str.cbegin();

	while (first != str.cend())
	{
		const auto second = std::find_first_of(first, str.cend(), delimiters.cbegin(), delimiters.cend());

		if (first != second) output.emplace_back(first, second);

		if (options == stop_on_first_delimiter_found)
		{
			output.emplace_back(second + 1, str.cend());
			break;
		}

		if (second == str.cend()) break;

		first = std::next(second);
	}

	return output;
}

} // namespace util

namespace gzip
{

class compressor
{
	int level_;

public:
	compressor(int level = Z_DEFAULT_COMPRESSION) noexcept : level_(level) {}

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

	template <typename OutputType>
	bool decompress(OutputType& output, const char* data, std::size_t size, std::string& error_code) const
	{
		bool result = false;
		z_stream inflate_s{};

		inflate_s.zalloc = nullptr;
		inflate_s.zfree = nullptr;
		inflate_s.opaque = nullptr;
		inflate_s.avail_in = 0;
		inflate_s.next_in = nullptr;

		constexpr int window_bits = 15 + 32;

		if (inflateInit2(&inflate_s, window_bits) != Z_OK)
		{
			error_code = "inflate init failed";
			return result;
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
				error_code = "unkown";

				if (inflate_s.msg) error_code = inflate_s.msg;

				inflateEnd(&inflate_s);
				return result;
			}

			size_uncompressed += (2 * size - inflate_s.avail_out);
		} while (inflate_s.avail_out == 0);
		inflateEnd(&inflate_s);
		output.resize(size_uncompressed);
		result = true;
		error_code = "";
		return result;
	}
};

inline std::string decompress(const char* data, std::size_t size, std::string& error_code)
{
	decompressor decomp;
	std::string output;
	bool error = decomp.decompress(output, data, size, error_code);

	if (error) output = "";

	return output;
}
} // namespace gzip

namespace lgr
{

enum class level
{
	none = 0,
	error,
	warning,
	access_log,
	access_log_all,
	api,
	info,
	debug
};

namespace prefix
{
static const char none[] = "";
static const char error[] = "[err]: ";
static const char warning[] = "[war]: ";
static const char access_log[] = "[acc]: ";
static const char access_log_all[] = "[aca]: ";
static const char api[] = "[api]: ";
static const char info[] = "[inf]: ";
static const char debug[] = "[dbg]: ";
} // namespace prefix

inline std::size_t get_thread_id() noexcept
{
	// Generate an ID per thread using a "global" ID counter
	static std::atomic<std::size_t> thread_idx{ 0 };
	thread_local std::size_t id = thread_idx++;
	return id;
}

class logger
{
public:
	logger(
		const std::string& access_log_file,
		const std::string& access_log_level,
		const std::string& extended_log_file,
		const std::string& extended_log_level)
		: extended_log_ostream_(&std::cout), access_log_ostream_(&std::cout)
	{
		set_access_log_level(access_log_level);
		set_access_log_file(access_log_file);

		set_extended_log_level(extended_log_level);
		set_extended_log_file(extended_log_file);

		if (extended_log_level_ != level::none && extended_log_file_ != "console")
		{
			redirected_extended_log_ostream_.open(
				extended_log_file_, std::ofstream::app | std::ofstream::out | std::ofstream::binary);
			extended_log_ostream_ = &redirected_extended_log_ostream_;
		}

		if (access_log_level_ != level::none && access_log_file_ != "console")
		{
			redirected_access_log_ostream_.open(
				access_log_file_, std::ofstream::app | std::ofstream::out | std::ofstream::binary);
			access_log_ostream_ = &redirected_access_log_ostream_;
		}

		if (extended_log_level_ != level::none)
		{
			info("logger started\n");
		}
	}

	~logger()
	{
		if (extended_log_level_ != level::none)
		{
			info("logger stopped\n");
		}
	}

	level current_extended_log_level() const { return extended_log_level_.load(); }
	level current_access_log_level() const { return access_log_level_.load(); }

	const std::string current_extended_log_level_to_string() const
	{
		std::string ret;

		if (extended_log_level_ == level::access_log)
			ret += "access_log";
		else if (extended_log_level_ == level::access_log_all)
			ret += "access_log_all";
		else if (extended_log_level_ == level::error)
			ret += "error";
		else if (extended_log_level_ == level::warning)
			ret += "warning";
		else if (extended_log_level_ == level::api)
			ret += "api";
		else if (extended_log_level_ == level::info)
			ret += "info";
		else if (extended_log_level_ == level::debug)
			ret += "debug";
		else
			ret += "none";

		return ret;
	}

	const std::string current_access_log_level_to_string() const
	{
		std::string ret;

		if (access_log_level_ == level::access_log)
			ret += "access_log";
		else if (access_log_level_ == level::access_log_all)
			ret += "access_log_all";
		else if (access_log_level_ == level::error)
			ret += "error";
		else if (access_log_level_ == level::warning)
			ret += "warning";
		else if (access_log_level_ == level::api)
			ret += "api";
		else if (access_log_level_ == level::info)
			ret += "info";
		else if (access_log_level_ == level::debug)
			ret += "debug";
		else
			ret += "none";

		return ret;
	}

	void set_access_log_file(const std::string& file) { access_log_file_ = file; }

	void set_extended_log_file(const std::string& file) { extended_log_file_ = file; }

	void set_extended_log_level(level l) { extended_log_level_.store(l); }
	void set_access_log_level(level l) { access_log_level_.store(l); }

	void set_extended_log_level(const std::string& level)
	{
		if (level == "access_log")
			extended_log_level_ = level::access_log;
		else if (level == "access_log_all")
			extended_log_level_ = level::access_log_all;
		else if (level == "api")
			extended_log_level_ = level::api;
		else if (level == "warning")
			extended_log_level_ = level::warning;
		else if (level == "error")
			extended_log_level_ = level::error;
		else if (level == "info")
			extended_log_level_ = level::info;
		else if (level == "debug")
			extended_log_level_ = level::debug;
		else
			extended_log_level_ = level::none;
	}

	void set_access_log_level(const std::string& level)
	{
		if (level == "access_log")
			access_log_level_ = level::access_log;
		else if (level == "access_log_all")
			access_log_level_ = level::access_log_all;
		else if (level == "api")
			access_log_level_ = level::api;
		else if (level == "warning")
			access_log_level_ = level::warning;
		else if (level == "error")
			access_log_level_ = level::error;
		else if (level == "info")
			access_log_level_ = level::info;
		else if (level == "debug")
			access_log_level_ = level::debug;
		else
			access_log_level_ = level::none;
	}

	template <const char* P, typename... A> static const std::string format(const std::string& msg)
	{
		return msg.c_str();
	}

	template <const char* P, typename... A> static const std::string format(const char* msg)
	{
		auto now = std::chrono::system_clock::now();
		auto in_time_t = std::chrono::system_clock::to_time_t(now);
		auto msec = static_cast<int>(
			std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000);
		auto tmp_tm = std::tm{};
		(void)gmtime_r(&in_time_t, &tmp_tm);

		std::string buffer(size_t{ 255 }, char{ 0 });
		std::array<char, 64> tmp{ char{ 0 } };

		auto offset = strftime(&tmp[0], sizeof(tmp), "%FT%T", &tmp_tm);
		snprintf(&tmp[offset], tmp.size() - offset, ".%03dZ T%03zu %s ", msec, get_thread_id() % 1000, P);
		buffer.assign(&tmp[0]);
		buffer.append(msg);

		return buffer;
	} // namespace util

	template <const char* P, typename... A> static const std::string format(const char* format, const A&... args)
	{
		class argument
		{
		public:
			enum class type
			{
				size_t_,
				int_,
				string_,
				double_
			};
			type value_;
			union
			{
				size_t size_t_value_;
				std::int64_t int_value_;
				double dbl_value_;
				struct
				{
					const char* string_value_;
					size_t string_size_;
				} string_v_;
			} u;

		public:
			argument(size_t value) : value_(type::size_t_) { u.size_t_value_ = value; }
			argument(int value) : value_(type::int_) { u.int_value_ = value; }
			argument(std::int64_t value) : value_(type::int_) { u.int_value_ = value; }
			argument(double value) : value_(type::double_) { u.dbl_value_ = value; }
			argument(const char* value) : value_(type::string_)
			{
				u.string_v_.string_value_ = value;
				u.string_v_.string_size_ = std::strlen(value);
			}
			argument(const std::string& value) : value_(type::string_)
			{
				u.string_v_.string_value_ = value.data();
				u.string_v_.string_size_ = value.size();
			}
		};

		enum class format_state
		{
			start,
			type,
			literal,
			end
		};

		argument argument_array[] = { args... };
		size_t argument_index = 0;
		size_t arguments_count = std::extent<decltype(argument_array)>::value;
		format_state expect = format_state::literal;

		auto now = std::chrono::system_clock::now();
		auto in_time_t = std::chrono::system_clock::to_time_t(now);
		auto msec = static_cast<int>(
			std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000);
		auto tmp_tm = std::tm{};
		(void)gmtime_r(&in_time_t, &tmp_tm);

		std::string buffer(size_t{ 255 }, char{ 0 });
		std::array<char, 64> tmp{ char{ 0 } };

		auto offset = strftime(&tmp[0], sizeof(tmp), "%FT%T", &tmp_tm);
		snprintf(&tmp[offset], tmp.size() - offset, ".%03dZ T%03zu %s ", msec, get_thread_id() % 1000, P);
		buffer.assign(&tmp[0]);

		for (; *format; format++)
		{
			switch (*format)
			{
				default:
					expect = format_state::literal;
					buffer.append(size_t{ 1 }, *format);
					break;
				case '{':
					if (expect == format_state::type)
					{
						expect = format_state::literal;
						buffer.append(size_t{ 1 }, *format);
					}
					else
						expect = format_state::type;
					break;
				case '}':
					if (expect == format_state::end)
						expect = format_state::literal;
					else
					{
						expect = format_state::end;
						buffer.append(size_t{ 1 }, *format);
					}
					break;
				case 's':
					if (expect == format_state::type
						&& argument_array[argument_index].value_ == argument::type::string_)
					{
						buffer.append(
							argument_array[argument_index].u.string_v_.string_value_,
							argument_array[argument_index].u.string_v_.string_size_);

						argument_index++;
						expect = format_state::end;
					}
					else
					{
						buffer.append(size_t{ 1 }, *format);
					}
					break;
				case 'u':
					if (expect == format_state::type
						&& argument_array[argument_index].value_ == argument::type::size_t_)
					{
						auto s = snprintf(&tmp[0], tmp.size(), "%zu", argument_array[argument_index++].u.size_t_value_);
						buffer.append(&tmp[0], s);
						expect = format_state::end;
					}
					else
					{
						buffer.append(size_t{ 1 }, *format);
					}
					break;
				case 'd':
					if (expect == format_state::type && argument_array[argument_index].value_ == argument::type::int_)
					{
						auto s = snprintf(
							&tmp[0],
							tmp.size(),
							"%lld",
							static_cast<long long>(argument_array[argument_index++].u.int_value_));
						buffer.append(&tmp[0], s);
						expect = format_state::end;
					}
					else
					{
						buffer.append(size_t{ 1 }, *format);
					}
					break;
				case 'x':
					if (expect == format_state::type && argument_array[argument_index].value_ == argument::type::int_)
					{
						auto s = snprintf(
							&tmp[0],
							tmp.size(),
							"%llx",
							static_cast<long long>(argument_array[argument_index++].u.int_value_));
						buffer.append(&tmp[0], s);
						expect = format_state::end;
					}
					else
					{
						buffer.append(size_t{ 1 }, *format);
					}
					break;
				case 'X':
					if (expect == format_state::type && argument_array[argument_index].value_ == argument::type::int_)
					{
						auto s = snprintf(
							&tmp[0],
							tmp.size(),
							"%llX",
							static_cast<long long>(argument_array[argument_index++].u.int_value_));
						buffer.append(&tmp[0], s);
						expect = format_state::end;
					}
					else
					{
						buffer.append(size_t{ 1 }, *format);
					}
					break;
				case 'f':
					if (expect == format_state::type
						&& argument_array[argument_index].value_ == argument::type::double_)
					{
						buffer.append(std::to_string(argument_array[argument_index++].u.dbl_value_));
						expect = format_state::end;
					}
					else
					{
						buffer.append(size_t{ 1 }, *format);
					}
					break;
			}
		}

		if (argument_index != arguments_count)
		{
			throw std::runtime_error{ "wrong nr of arguments format: " + std::to_string(argument_index)
									  + std::string("arguments: " + std::to_string(arguments_count)) };
		}

		return buffer;
	}

	inline void log(const level l, const std::string& msg) const
	{
		if (extended_log_level_ >= l)
		{
			std::lock_guard<std::mutex> g{ lock_ };
			extended_log_ostream_->write(msg.data(), msg.size()).flush();
		}
		if (access_log_level_ >= l)
		{
			std::lock_guard<std::mutex> g{ lock_ };
			access_log_ostream_->write(msg.data(), msg.size()).flush();
		}
	}

	template <typename... A> void access_log(const char* format, const A&... args) const
	{
		log(level::access_log, logger::format<prefix::access_log, A...>(format, args...));
	}

	template <typename... A> void api(const char* format, const A&... args) const
	{
		log(level::api, logger::format<prefix::api, A...>(format, args...));
	}

	template <typename... A> void info(const char* format, const A&... args) const
	{
		log(level::info, logger::format<prefix::info, A...>(format, args...));
	}

	template <typename... A> void warning(const char* format, const A&... args) const
	{
		log(level::warning, logger::format<prefix::warning, A...>(format, args...));
	}

	template <typename... A> void error(const char* format, const A&... args) const
	{
		log(level::error, logger::format<prefix::error, A...>(format, args...));
	}

	template <typename... A> void debug(const char* format, const A&... args) const
	{
		log(level::debug, logger::format<prefix::debug, A...>(format, args...));
	}

	template <typename... A> void access_log(const std::string& msg) const
	{
		if (access_log_level_ >= level::access_log)
		{
			std::lock_guard<std::mutex> g{ lock_ };
			access_log_ostream_->write(msg.data(), msg.size()).flush();
		}
		if (extended_log_level_ >= level::access_log)
		{
			std::lock_guard<std::mutex> g{ lock_ };
			extended_log_ostream_->write(msg.data(), msg.size()).flush();
		}
	}

	template <typename... A> void access_log_all(const std::string& msg) const
	{
		if (access_log_level_ >= level::access_log_all)
		{
			std::lock_guard<std::mutex> g{ lock_ };
			access_log_ostream_->write(msg.data(), msg.size()).flush();
		}
		if (extended_log_level_ >= level::access_log_all)
		{
			std::lock_guard<std::mutex> g{ lock_ };
			extended_log_ostream_->write(msg.data(), msg.size()).flush();
		}
	}

	std::ostream& as_stream() { return *extended_log_ostream_; }
	const std::ostream& as_stream() const { return *extended_log_ostream_; }

private:
	mutable std::mutex lock_;
	std::ostream* extended_log_ostream_;
	std::ostream* access_log_ostream_;

	std::ofstream redirected_extended_log_ostream_;
	std::ofstream redirected_access_log_ostream_;

	std::atomic<level> extended_log_level_;
	std::atomic<level> access_log_level_;

	std::string extended_log_file_;
	std::string access_log_file_;
};

} // namespace lgr

namespace http
{
class request_parser;
class response_parser;
class session_handler;

namespace api
{
class routing;
class params;
} // namespace api

enum protocol
{
	http,
	https
};

inline std::string to_string(protocol protocol) noexcept
{
	switch (protocol)
	{
		case http:
			return "http";
		case https:
			return "https";
		default:
			return "http";
	}
}

namespace method
{

enum method_t
{
	unknown = 0,
	delete_,
	get,
	head,
	post,
	put,
	connect,
	options,
	trace,
	patch,
	purge,
	proxy_pass
};

inline method_t to_method(const std::string& v) noexcept
{
	if (v.size() < 2) return method::unknown;

	switch (v[0])
	{
		case 'C':
			if (v == "CONNECT") return http::method::connect;
			break;
		case 'D':
			if (v == "DELETE") return http::method::delete_;
			break;
		case 'G':
			if (v == "GET") return http::method::get;
			break;
		case 'H':
			if (v == "HEAD") return http::method::head;
			break;
		case 'O':
			if (v == "OPTIONS") return http::method::options;
			break;
		case 'P':
			if (v == "PUT") return http::method::put;
			if (v == "POST") return http::method::post;
			if (v == "PATCH") return http::method::patch;
			if (v == "PURGE") return http::method::purge;
			return method::unknown;
	}

	return method::unknown;
}

inline std::string to_string(method_t method) noexcept
{
	switch (method)
	{
		case method::delete_:
			return "DELETE";
		case method::get:
			return "GET";
		case method::head:
			return "HEAD";
		case method::post:
			return "POST";
		case method::put:
			return "PUT";
		case method::connect:
			return "CONNECT";
		case method::options:
			return "OPTIONS";
		case method::trace:
			return "TRACE";
		case method::patch:
			return "PATCH";
		case method::purge:
			return "PURGE";
		case method::proxy_pass:
			return "PROXY_PASS";
		default:
			return "ERROR";
	}
}

} // namespace method

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
	not_acceptable = 406,
	proxy_authentication_required = 407,
	request_timeout = 408,
	conflict = 409,
	gone = 410,
	length_required = 411,
	precondition_failed = 412,
	payload_too_large = 413,
	uri_too_long = 414,
	unsupported_media_type = 415,
	range_not_satisfiable = 416,
	expectation_failed = 417,
	misdirected_request = 421,
	unprocessable_entity = 422,
	locked = 423,
	failed_dependency = 424,
	upgrade_required = 426,
	precondition_required = 428,
	too_many_requests = 429,
	request_header_fields_too_large = 431,
	connection_closed_without_response = 444,
	unavailable_for_legal_reasons = 451,
	client_closed_request = 499,
	internal_server_error = 500,
	not_implemented = 501,
	bad_gateway = 502,
	service_unavailable = 503,
	gateway_timeout = 504,
	http_version_not_supported = 505,
	variant_also_negotiates = 506,
	insufficient_storage = 507,
	loop_detected = 508,
	not_extended = 510,
	network_authentication_required = 511,
	network_connect_timeout_error = 599
};

inline status_t to_status(std::uint32_t status_nr)
{
	if (status_nr >= 100 && status_nr <= 599)
		return static_cast<status_t>(status_nr);
	else
		return http::status::internal_server_error;
}

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
		case http::status::not_acceptable:
			return "HTTP/1.1 406 Method Not Acceptable\r\n";
		case http::status::proxy_authentication_required:
			return "HTTP/1.1 407 Proxy Authentication Required\r\n";
		case http::status::request_timeout:
			return "HTTP/1.1 408 Request Timeout\r\n";
		case http::status::conflict:
			return "HTTP/1.1 409 Conflict \r\n";
		case http::status::gone:
			return "HTTP/1.1 410 Gone \r\n";
		case http::status::length_required:
			return "HTTP/1.1 411 Length Required\r\n";
		case http::status::precondition_failed:
			return "HTTP/1.1 412 Precondition Failed\r\n";
		case http::status::payload_too_large:
			return "HTTP/1.1 413 Payload Too Large\r\n";
		case http::status::uri_too_long:
			return "HTTP/1.1 414 URI Too Long\r\n";
		case http::status::unsupported_media_type:
			return "HTTP/1.1 415 Unsupported Media Type\r\n";
		case http::status::range_not_satisfiable:
			return "HTTP/1.1 416 Range Not Satisfiable\r\n";
		case http::status::expectation_failed:
			return "HTTP/1.1 417 Expectation Failed\r\n";
		case http::status::misdirected_request:
			return "HTTP/1.1 418 I'm a teapot\r\n";
		case http::status::unprocessable_entity:
			return "HTTP/1.1 422 Unprocessable Entity\r\n";
		case http::status::locked:
			return "HTTP/1.1 423 Locked\r\n";
		case http::status::failed_dependency:
			return "HTTP/1.1 424 Failed Dependency\r\n";
		case http::status::upgrade_required:
			return "HTTP/1.1 426 Upgrade Required\r\n";
		case http::status::precondition_required:
			return "HTTP/1.1 428 Precondition Required\r\n";
		case http::status::too_many_requests:
			return "HTTP/1.1 429 Too Many Requests\r\n";
		case http::status::request_header_fields_too_large:
			return "HTTP/1.1 431 Request Header Fields Too Large\r\n";
		case http::status::connection_closed_without_response:
			return "HTTP/1.1 444 Connection Closed Without Response\r\n";
		case http::status::unavailable_for_legal_reasons:
			return "HTTP/1.1 451 Unavailable For Legal Reasons\r\n";
		case http::status::client_closed_request:
			return "HTTP/1.1 499 Client Closed Request\r\n";
		case http::status::internal_server_error:
			return "HTTP/1.1 500 Internal Server Error\r\n";
		case http::status::not_implemented:
			return "HTTP/1.1 501 Not Implemented\r\n";
		case http::status::bad_gateway:
			return "HTTP/1.1 502 Bad Gateway\r\n";
		case http::status::service_unavailable:
			return "HTTP/1.1 503 Service Unavailable\r\n";
		case http::status::gateway_timeout:
			return "HTTP/1.1 504 Gateway Timeout\r\n";
		case http::status::http_version_not_supported:
			return "HTTP/1.1 505 HTTP Version Not Supported\r\n";
		case http::status::variant_also_negotiates:
			return "HTTP/1.1 506 Variant Also Negotiates\r\n";
		case http::status::insufficient_storage:
			return "HTTP/1.1 507 Insufficient Storage\r\n";
		case http::status::loop_detected:
			return "HTTP/1.1 508 Loop Detected\r\n";
		case http::status::not_extended:
			return "HTTP/1.1 510 Not Extended\r\n";
		case http::status::network_authentication_required:
			return "HTTP/1.1 511 Network Authentication Required\r\n";
		case http::status::network_connect_timeout_error:
			return "HTTP/1.1 599 Network Authentication Required\r\n";
		default:
			return "HTTP/1.1 500 Internal Server Error\r\n";
	}
}

inline std::int32_t to_int(status_t s)
{
	switch (s)
	{
		case http::status::ok:
			return 200;
		case http::status::created:
			return 201;
		case http::status::accepted:
			return 202;
		case http::status::no_content:
			return 204;
		case http::status::multiple_choices:
			return 300;
		case http::status::moved_permanently:
			return 301;
		case http::status::moved_temporarily:
			return 302;
		case http::status::not_modified:
			return 304;
		case http::status::bad_request:
			return 400;
		case http::status::unauthorized:
			return 401;
		case http::status::forbidden:
			return 403;
		case http::status::not_found:
			return 404;
		case http::status::method_not_allowed:
			return 405;
		case http::status::proxy_authentication_required:
			return 407;
		case http::status::request_timeout:
			return 408;
		case http::status::conflict:
			return 409;
		case http::status::gone:
			return 410;
		case http::status::length_required:
			return 411;
		case http::status::precondition_failed:
			return 412;
		case http::status::payload_too_large:
			return 413;
		case http::status::uri_too_long:
			return 414;
		case http::status::unsupported_media_type:
			return 415;
		case http::status::range_not_satisfiable:
			return 416;
		case http::status::expectation_failed:
			return 417;
		case http::status::unprocessable_entity:
			return 422;
		case http::status::locked:
			return 423;
		case http::status::failed_dependency:
			return 424;
		case http::status::upgrade_required:
			return 426;
		case http::status::precondition_required:
			return 428;
		case http::status::too_many_requests:
			return 429;
		case http::status::request_header_fields_too_large:
			return 431;
		case http::status::connection_closed_without_response:
			return 444;
		case http::status::unavailable_for_legal_reasons:
			return 451;
		case http::status::client_closed_request:
			return 499;
		case http::status::internal_server_error:
			return 500;
		case http::status::not_implemented:
			return 501;
		case http::status::bad_gateway:
			return 502;
		case http::status::service_unavailable:
			return 503;
		case http::status::gateway_timeout:
			return 504;
		case http::status::http_version_not_supported:
			return 505;
		case http::status::variant_also_negotiates:
			return 506;
		case http::status::insufficient_storage:
			return 507;
		case http::status::loop_detected:
			return 503;
		case http::status::not_extended:
			return 510;
		case http::status::network_authentication_required:
			return 511;
		case http::status::network_connect_timeout_error:
			return 599;
		default:
			return static_cast<int32_t>(s);
	}
}
} // namespace status

namespace misc_strings
{
const char name_value_separator[] = { ':', ' ' };
const char crlf[] = { '\r', '\n' };
} // namespace misc_strings

class url
{
public:
	url(const std::string& url)
	{
		auto end_of_scheme = url.find_first_of(':');
		scheme_ = url.substr(0, end_of_scheme);

		auto start_of_host = end_of_scheme + 3;

		auto start_of_port = url.find_first_of(':', start_of_host);
		auto start_of_path = url.find_first_of('/', start_of_host);

		if (start_of_path == std::string::npos) start_of_path = url.size();

		if (start_of_port != std::string::npos)
		{
			port_ = url.substr(start_of_port + 1, start_of_path - (start_of_port + 1));
		}
		else
		{
			port_ = "80";
			start_of_port = start_of_path;
		}

		host_ = url.substr(start_of_host, start_of_port - start_of_host);
		target_ = url.substr(start_of_path);
	}

	const std::string& scheme() const { return scheme_; };
	const std::string& host() const { return host_; };
	const std::string& port() const { return port_; };
	const std::string& target() const { return target_; };

	std::string data() const { return std::string{ scheme_ + "://" + host_ + ":" + port_ + target_ }; }

	std::string base_url() const { return std::string{ scheme_ + "://" + host_ + ":" + port_ }; }

	static url make_url(const std::string& url) { return http::url{ url }; }

private:
	std::string scheme_;
	std::string host_;
	std::string port_;
	std::string target_;
};

template <typename T> class field
{
public:
	using value_type = T;

	field() = default;

	field(const char* name, T value = T{}) : name(name), value(std::move(value)){};
	field(std::string name, T value = T{}) noexcept : name(std::move(name)), value(std::move(value)){};
	field(std::string&& name, T&& value = T{}) noexcept : name(std::move(name)), value(std::move(value)){};

	std::string name;
	T value;
};

template <typename T, class C = std::equal_to<std::string>> class fields
{

public:
	using iterator = typename std::vector<http::field<T>>::iterator;
	using value_type = http::field<T>;
	using compare_field_name = C;

protected:
	std::vector<fields::value_type> fields_;

public:
	fields() = default;

	fields(std::initializer_list<fields::value_type> init_list) : fields_(init_list){};

	fields(const http::fields<T, C>& f) = default;
	fields(http::fields<T, C>&& f) noexcept = default;

	fields<T, C>& operator=(const http::fields<T, C>&) = default;
	fields<T, C>& operator=(http::fields<T, C>&&) noexcept = default;

	~fields() = default;

	inline std::string to_string() const noexcept
	{
		std::ostringstream ss;

		for (auto&& field : fields_)
		{
			ss << field.name << ": " << field.value << "\r\n";
		}

		return ss.str();
	}

	inline bool fields_empty() const { return this->fields_.empty(); };

	inline typename std::vector<fields::value_type>::reverse_iterator new_field()
	{
		fields_.emplace_back(field<T>{});
		return fields_.rbegin();
	}

	template <typename P>
	typename std::enable_if<std::is_same<P, bool>::value, bool>::type get(const std::string& name, const P value) const
	{
		P returnvalue = value;

		auto i = std::find_if(fields_.cbegin(), fields_.cend(), [name](const http::field<T>& f) {
			if (compare_field_name()(f.name, name))
				return true;
			else
				return false;
		});

		if (i != fields_.cend()) returnvalue = i->value == "true";

		return static_cast<P>(returnvalue);
	}

	template <typename P>
	typename std::enable_if<
		std::is_integral<P>::value && (!std::is_same<P, bool>::value && !std::is_same<T, std::string>::value),
		P>::type
	get(const std::string& name, const P value) const
	{
		P returnvalue = value;

		auto i = std::find_if(fields_.cbegin(), fields_.cend(), [name](const http::field<T>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != fields_.cend()) returnvalue = static_cast<P>(i->value);

		return static_cast<P>(returnvalue);
	}

	template <typename P>
	typename std::enable_if<
		std::is_integral<P>::value && (!std::is_same<P, bool>::value && std::is_same<T, std::string>::value),
		P>::type
	get(const std::string& name, const P value) const
	{
		P returnvalue = value;

		auto i = std::find_if(fields_.cbegin(), fields_.cend(), [name](const http::field<T>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != fields_.cend()) returnvalue = static_cast<P>(std::stoi(i->value));

		return static_cast<P>(returnvalue);
	}

	template <typename P>
	typename std::enable_if<
		std::is_integral<P>::value && (!std::is_same<P, bool>::value && !std::is_same<T, std::string>::value),
		P>::type
	get(const std::string& name) const
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<T>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != std::end(fields_))
			return static_cast<P>(i->value);
		else
			throw std::runtime_error{ std::string{ "get of field: '" } + name + "' failed because it was not found" };
	}

	template <typename P>
	typename std::enable_if<
		std::is_integral<P>::value && (!std::is_same<P, bool>::value && std::is_same<T, std::string>::value),
		P>::type
	get(const std::string& name) const
	{
		auto i = std::find_if(fields_.cbegin(), fields_.cend(), [name](const http::field<T>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != fields_.cend())
			return static_cast<P>(std::stoi(i->value));
		else
			throw std::runtime_error{ std::string{ "get of field: '" } + name + "' failed because it was not found" };
	}

	template <typename P>
	typename std::enable_if<std::is_same<P, std::string>::value, std::string>::type
	get(const std::string& name, const P& value) const
	{
		bool ignore_existance;
		return get(name, ignore_existance, value);
	}

	template <typename P>
	typename std::enable_if<std::is_same<P, std::string>::value, std::string>::type
	get(const std::string& name, bool& exists, const P& value = P()) const
	{
		P returnvalue = value;

		auto i = std::find_if(fields_.cbegin(), fields_.cend(), [name](const http::field<std::string>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != fields_.cend())
		{
			exists = true;
			returnvalue = i->value;
		}
		else
		{
			exists = false;
		}
		return returnvalue;
	}

	inline typename std::vector<fields::value_type>::reverse_iterator last_new_field() { return fields_.rbegin(); }

	inline const T get(const char* name) const
	{
		auto i = std::find_if(fields_.cbegin(), fields_.cend(), [name](const http::field<T>& f) {
			return (compare_field_name()(f.name, name));
		});

		if (i == fields_.cend())
		{
			throw std::runtime_error{ std::string{ "get of field: '" } + name + "' failed because it was not found" };
		}
		else
			return i->value;
	}

	inline bool has(const char* name) const
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<T>& f) {
			return (compare_field_name()(f.name, name));
		});

		return i != std::end(fields_);
	}

	inline void set(const std::string& name, const T& value)
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<T>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != std::end(fields_))
		{
			i->value = value;
		}
		else
		{
			http::field<T> field_(name, value);
			fields_.emplace_back(std::move(field_));
		}
	}

	inline void reset_if_exists(const std::string& name)
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<std::string>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != std::end(fields_))
		{
			fields_.erase(i);
		}
	}

	inline void reset(const std::string& name)
	{
		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<T>& f) {
			return compare_field_name()(f.name, name);
		});

		if (i != std::end(fields_))
		{
			fields_.erase(i);
		}
		else
			throw std::runtime_error{ std::string{ "reset of field: '" } + name + "' failed because it was not found" };
	}

	inline void clear() { fields_.clear(); }

	inline size_t size() const noexcept { return fields_.size(); }

	const std::vector<fields::value_type> as_vector() const { return fields_; }
	std::vector<fields::value_type> as_vector() { return fields_; }

	const value_type& operator[](size_t index) const noexcept { return fields_[index]; }
};

class configuration
{
public:
	using iterator = std::vector<http::field<std::string>>::iterator;
	using value_type = http::field<std::string>;

public:
	configuration() = default;

	configuration(std::initializer_list<configuration::value_type> init_list, const std::string& string_options = "")
		: fields_(init_list)
	{
		const auto& split_string_options = util::split(string_options, ",");

		for (const auto& string_option : split_string_options)
		{
			const auto& split_string_option{ util::split(
				string_option, ":", util::split_options::stop_on_first_delimiter_found) };
			if (split_string_option.size() == 2) set(split_string_option[0], split_string_option[1]);
		}
	};

	configuration(const http::configuration& c)
	{
		std::unique_lock<std14::shared_mutex> lock_guard(configuration_mutex_);
		fields_ = c.fields_;
	};

	configuration(http::configuration&& c) noexcept
	{
		std::unique_lock<std14::shared_mutex> lock_guard(configuration_mutex_);
		fields_ = c.fields_;
	};

	configuration& operator=(const http::configuration& c)
	{
		std::unique_lock<std14::shared_mutex> lock_guard(configuration_mutex_);
		fields_ = c.fields_;

		return *this;
	};

	configuration& operator=(http::configuration&& c) noexcept
	{
		std::unique_lock<std14::shared_mutex> lock_guard(configuration_mutex_);
		fields_ = c.fields_;
		return *this;
	};

	~configuration() = default;

	inline std::string to_string() const noexcept
	{
		std::ostringstream ss;

		std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

		for (auto&& field : fields_)
		{
			ss << field.name << ": " << field.value << "\r\n";
		}

		return ss.str();
	}

	json to_json() const noexcept
	{
		json configuration_json;
		std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

		configuration_json = json::object();

		for (auto field = fields_.cbegin(); field != fields_.cend(); ++field)
		{
			configuration_json[field->name] = field->value;
		}

		return configuration_json;
	}

	template <typename T>
	typename std::enable_if<std::is_same<T, bool>::value, bool>::type
	get(const std::string& name, const T default_value = T()) const
	{
		T return_value = default_value;
		bool default_used = false;

		{
			std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

			auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<std::string>& f) {
				return util::case_sensitive::equal_to<std::string>()(f.name, name);
			});

			if (i != std::end(fields_)) return_value = i->value == "true";
		}

		if (default_used) set(name, std::to_string(return_value));

		return static_cast<T>(return_value);
	}

	template <typename T>
	typename std::enable_if<std::is_integral<T>::value && !std::is_same<T, bool>::value, T>::type
	get(const std::string& name, const T default_value = T()) const
	{
		T return_value = default_value;
		bool default_used = false;
		{
			std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

			auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<std::string>& f) {
				return (util::case_sensitive::equal_to<std::string>()(f.name, name));
			});

			if (i != std::end(fields_))
				return_value = static_cast<T>(std::stoi(i->value));
			else
				default_used = true;
		}

		if (default_used) set(name, std::to_string(return_value));

		return static_cast<T>(return_value);
	}

	template <typename T>
	typename std::enable_if<std::is_same<T, std::string>::value, std::string>::type
	get(const std::string& name, const T& default_value = T()) const
	{
		T return_value = default_value;
		bool default_used = false;

		{
			std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

			auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const http::field<std::string>& f) {
				return (util::case_sensitive::equal_to<std::string>()(f.name, name));
			});

			if (i != std::end(fields_))
				return_value = i->value;
			else
				default_used = true;
		}

		if (default_used)
		{
			set(name, return_value);
		}
		return return_value;
	}

	inline const std::string get(const char* name) const
	{
		static const std::string not_found = "";
		std::string return_value = not_found;
		bool default_used = false;

		{
			std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

			auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const value_type& f) {
				return (util::case_insensitive::equal_to<std::string>()(f.name, name));
			});

			if (i == std::end(fields_))
			{
				default_used = true;
			}
			else
			{
				return_value = i->value;
			}
		}

		if (default_used)
		{
			set(name, return_value);
		}
		return return_value;
	}

	inline void set(const std::string& name, const std::string& value) const
	{
		std::unique_lock<std14::shared_mutex> lock_guard(configuration_mutex_);

		auto i = std::find_if(std::begin(fields_), std::end(fields_), [name](const value_type& f) {
			return util::case_sensitive::equal_to<std::string>()(f.name, name);
		});

		if (i != std::end(fields_))
		{
			i->value = value;
		}
		else
		{
			fields_.emplace_back(name, value);
		}
	}

	inline size_t size() const noexcept
	{
		std14::shared_lock<std14::shared_mutex> lock_guard(configuration_mutex_);
		return fields_.size();
	}

private:
	mutable std::vector<http::field<std::string>> fields_;
	mutable std14::shared_mutex configuration_mutex_;
};

enum message_specializations
{
	request_specialization,
	response_specialization
};

template <message_specializations> class header;

template <>
class header<request_specialization> : public fields<std::string, util::case_insensitive::equal_to<std::string>>
{
	using query_params = http::fields<std::string, util::case_sensitive::equal_to<std::string>>;
	friend class session_handler;
	friend class request_parser;

public:
	using fields_base = fields<std::string, util::case_insensitive::equal_to<std::string>>;

protected:
	http::method::method_t method_{ method::unknown };
	std::string url_requested_;
	std::string target_;
	query_params params_;
	unsigned int version_nr_ = 11;

public:
	header() = default;
	const http::method::method_t& method() const { return method_; }
	const std::string& target() const { return target_; }
	const std::string& url_requested() const { return url_requested_; }
	const unsigned int& version_nr() const { return version_nr_; }
	const std::string version() const
	{
		std::string ret = "HTTP/1.1";

		if (version_nr_ == 10) ret = "HTTP/1.0";

		return ret;
	}
	void target(const std::string& target) { target_ = target; }

	query_params& query() { return params_; };
	const query_params& query() const { return params_; };

	void clear()
	{
		this->version_nr_ = 0;
		this->method_ = http::method::unknown;
		this->target_.clear();
		this->url_requested_.clear();
		this->params_.clear();

		this->fields_.clear();
	}

	std::string header_to_string() const
	{
		std::ostringstream ss;

		if (version_nr() == 11)
			ss << http::method::to_string(method_) << " " << target_ << " HTTP/1.1\r\n";
		else
			ss << http::method::to_string(method_) << " " << target_ << " HTTP/1.0\r\n";

		for (auto&& field : fields_)
		{
			ss << field.name << ": ";
			ss << field.value << "\r\n";
		}

		ss << "\r\n";

		return ss.str();
	}

	std::string header_to_dbg_string() const
	{
		std::ostringstream ss;

		if (version_nr() == 11)
			ss << http::method::to_string(method_) << " " << target_ << " HTTP/1.1\n";
		else
			ss << http::method::to_string(method_) << " " << target_ << " HTTP/1.0\n";

		for (auto&& field : fields_)
		{
			ss << field.name << ": ";
			ss << field.value << "\n";
		}

		ss << "\n";

		return ss.str();
	}

	inline void merge_new_header()
	{
		auto special_merge_case = compare_field_name()(last_new_field()->name, "Set-Cookie")
								  || compare_field_name()(last_new_field()->name, "WWW-Authenticate")
								  || compare_field_name()(last_new_field()->name, "Proxy-Authenticate");

		auto merged_last_new_header = false;

		if (!special_merge_case && fields_.size() > 1)
			for (auto i = fields_.rbegin() + 1; i != fields_.rend(); ++i)
			{
				if (compare_field_name()(last_new_field()->name, i->name) == true)
				{
					if ((last_new_field()->value.empty() == false))
					{
						i->value.append(", ");
						i->value.append(last_new_field()->value);
					}
					merged_last_new_header = true;
				}
			}

		if (merged_last_new_header) fields_.pop_back();
	}
};

template <>
class header<response_specialization> : public fields<std::string, util::case_insensitive::equal_to<std::string>>
{
private:
	std::string reason_;
	http::status::status_t status_ = http::status::bad_request;
	unsigned int status_nr_ = 400;
	unsigned int version_nr_ = 11;

	friend class response_parser;

public:
	using fields_base = fields<std::string, util::case_insensitive::equal_to<std::string>>;

public:
	header() = default;
	const unsigned int& version_nr() const noexcept { return version_nr_; }
	void version(unsigned int value) noexcept { version_nr_ = value; }
	void status(http::status::status_t status) { status_ = status; }
	http::status::status_t status() const { return status_; }

	const std::string version() const
	{
		std::string ret = "HTTP/1.1";

		if (version_nr_ == 10) ret = "HTTP/1.0";

		return ret;
	}

	void clear()
	{
		this->fields_.clear();
		version_nr_ = 0;
		reason_.clear();
	}

	std::string header_to_string() const
	{
		std::ostringstream ss;

		ss << status::to_string(status_);

		for (auto&& field : fields_)
		{
			ss << field.name << ": ";
			ss << field.value << "\r\n";
		}

		ss << "\r\n";

		return ss.str();
	}

	std::string header_to_dbg_string() const
	{
		std::ostringstream ss;

		ss << status::to_string(status_);

		for (auto&& field : fields_)
		{
			ss << field.name << ": ";
			ss << field.value << "\n";
		}

		ss << "\n";

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
} const mappings[]
	= { { "json", "application/json" }, { "text", "text/plain" }, { "ico", "image/x-icon" }, { "gif", "image/gif" },
		{ "htm", "text/html" },			{ "html", "text/html" },  { "jpg", "image/jpeg" },	 { "jpeg", "image/jpeg" },
		{ "png", "image/png" },			{ nullptr, nullptr } };

static std::string extension_to_type(const std::string& extension)
{
	if (extension.find_first_of('/') != std::string::npos)
		return extension;
	else
	{
		for (const auto& m : mappings) // NOLINT: trust me i know what i am doing...
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

using headers = http::request_header::fields_base;

template <message_specializations specialization> class message : public header<specialization>
{
public:
	using attributes = http::fields<std::uintptr_t>;
	attributes attributes_;

	using headers_base = typename header<specialization>::fields_base;

private:
	std::string body_;
	const http::session_handler* session_handler_{ nullptr };

	std::uint64_t cached_content_length_{ static_cast<std::uint64_t>(-1) };

public:
	message() = default;
	~message() = default;

	message(const message&) = default;
	message(message&&) noexcept = default;

	message& operator=(const message&) = default;
	message& operator=(message&&) noexcept = default;

	message(const http::session_handler& session) : session_handler_(&session){};

	// TODO use enableif....
	message(
		const http::method::method_t method,
		const std::string& host,
		const std::string& target,
		const http::headers& headers,
		const std::string& body,
		const int version_nr = 11)
		: body_(body)
	{
		for (auto& h : headers.as_vector())
			header<specialization>::set(h.name, h.value);

		if (header<specialization>::has("Host") == false) header<specialization>::set("Host", host);

		header<specialization>::version_nr_ = version_nr;
		header<specialization>::method_ = method;
		header<specialization>::target_ = target;

		content_length(body.size());
	}

	const http::session_handler& session() const
	{
		if (session_handler_ == nullptr) throw std::runtime_error{ "session is not set for this message" };

		return *session_handler_;
	}

	template <typename T>
	typename std::enable_if<std::is_pointer<T>::value, T>::type
	get_attribute(const std::string& attribute_name, const T default_value) const
	{
		return reinterpret_cast<T>(
			attributes_.get(attribute_name.c_str(), reinterpret_cast<std::uintptr_t>(default_value)));
	}

	template <typename T>
	typename std::enable_if<std::is_pointer<T>::value, T>::type get_attribute(const std::string& attribute_name) const
	{
		return reinterpret_cast<T>(attributes_.get(attribute_name.c_str()));
	}

	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, T>::type get_attribute(const std::string& attribute_name) const
	{
		return static_cast<T>(attributes_.get(attribute_name.c_str()));
	}

	template <typename T>
	typename std::enable_if<std::is_integral<T>::value, T>::type
	get_attribute(const std::string& attribute_name, const T& default_value) const
	{
		return attributes_.get<T>(attribute_name.c_str(), default_value);
	}

	template <typename T>
	void set_attribute(
		const std::string& attribute_name, typename std::enable_if<std::is_pointer<T>::value, T>::type attribute_value)
	{
		attributes_.set(attribute_name, reinterpret_cast<attributes::value_type::value_type>(attribute_value));
	};

	template <typename T>
	void set_attribute(
		const std::string& attribute_name, typename std::enable_if<!std::is_pointer<T>::value, T>::type attribute_value)
	{
		attributes_.set(attribute_name, attribute_value);
	};

	// TODO use std::enable_if for better performance?
	template <typename T> std::vector<field<T>> attributes_as_vector() const
	{
		std::vector<field<T>> vec;

		for (const auto& attribute : attributes_.as_vector())
		{
			vec.emplace_back(attribute.name, get_attribute<T>(attribute.name));
		}

		return vec;
	}

	void reset_attribute(const std::string& attribute_name) { attributes_.reset(attribute_name); };

	std::string target() const { return header<specialization>::target_; }

	void target(const std::string& target) { header<specialization>::target_ = target; }

	const std::vector<http::field<std::string>>& headers() const { return header<specialization>::fields_; }
	std::vector<http::field<std::string>>& headers() { return header<specialization>::fields_; }

	void assign(
		http::status::status_t status,
		std::string&& body = std::string{},
		const std::string& content_type = std::string{ "text/plain" },
		const http::headers& headers = http::headers{})
	{
		http::header<specialization>::status(status);
		headers_base::set("Content-Type", mime_types::extension_to_type(content_type));
		body_ = std::move(body);

		for (auto& h : headers.as_vector())
			header<specialization>::set(h.name, h.value);

		content_length(body.size());
	}

	void reset()
	{
		header<specialization>::clear();
		attributes_.clear();
		body_.clear();
		cached_content_length_ = static_cast<std::uint64_t>(-1);
	}

	void reset(const std::string& name) { header<specialization>::reset(name); }

	std::string& body() { return body_; }

	const std::string& body() const { return body_; }

	bool chunked() const { return (headers_base::get("Transfer-Encoding", std::string{}) == "chunked"); }

	void chunked(bool value)
	{
		if (value)
			headers_base::set("Transfer-Encoding", "chunked");
		else
			headers_base::set("Transfer-Encoding", "none");
	}

	bool has_content_length() const
	{
		if (headers_base::get("Content-Length", std::string{}).empty())
			return false;
		else
			return true;
	}

	void type(const std::string& content_type)
	{
		headers_base::set("Content-Type", mime_types::extension_to_type(content_type));
	}

	void status(http::status::status_t status) { http::header<specialization>::status(status); }
	http::status::status_t status() const { return http::header<specialization>::status(); }

	void content_length(uint64_t const& length)
	{
		headers_base::set("Content-Length", std::to_string(length));
		cached_content_length_ = length;
	}

	static const std::uint64_t content_length_invalid = static_cast<std::uint64_t>(-1);

	std::uint64_t content_length()
	{
		if (cached_content_length_ != content_length_invalid)
			return cached_content_length_;
		else
		{
			auto content_length
				= http::header<request_specialization>::fields_base::get("Content-Length", std::string{ "" });

			if (content_length.empty())
				cached_content_length_ = 0;
			else
			{
				cached_content_length_ = content_length_invalid;

				try
				{
					if (content_length[0] != '-') cached_content_length_ = std::stoull(content_length);
				}
				catch (std::exception&)
				{
				}

				return cached_content_length_;
			}

			return cached_content_length_;
		}
	}

	bool http_version11() const { return http::header<request_specialization>::version_nr() == 11; }

	bool connection_close() const
	{
		if (util::case_insensitive::equal_to<std::string>()(headers_base::get("Connection", std::string{}), "close"))
			return true;
		else
			return false;
	}

	bool connection_keep_alive() const
	{
		if (util::case_insensitive::equal_to<std::string>()(
				headers_base::get("Connection", std::string{}), "Keep-Alive"))
			return true;
		else
			return false;
	}

	static std::string to_dbg_string(const http::message<specialization>& message)
	{
		std::string ret = message.header_to_dbg_string();
		ret += message.body();

		return ret;
	}

	static std::string to_string(const http::message<specialization>& message)
	{
		std::ostringstream ss;

		ss << message.header_to_string();
		ss << message.body();

		return ss.str();
	}
};

template <message_specializations specialization> std::string to_string(const http::message<specialization>& message)
{
	return http::message<specialization>::to_string(message);
}

template <message_specializations specialization>
std::string to_dbg_string(const http::message<specialization>& message)
{
	return http::message<specialization>::to_dbg_string(message);
}

using request_message = http::message<request_specialization>;
using response_message = http::message<response_specialization>;

class request_parser
{
public:
	request_parser() = default;

	void reset()
	{
		state_ = method_start;
		error_reason_ = "";
	};

	enum result_type
	{
		good,
		bad,
		indeterminate
	};

	const std::string& error_reason() const { return error_reason_; }

	template <typename InputIterator>
	std::tuple<result_type, InputIterator> parse(http::request_message& req, InputIterator begin, InputIterator end)
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
					storage.clear();
					storage.push_back(input);
					return indeterminate;
				}
			case method:
				if (input == ' ')
				{
					state_ = target;
					req.method_ = http::method::to_method(storage);
					return indeterminate;
				}
				else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
				{
					return bad;
				}
				else
				{
					storage.push_back(input);
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
				if (input == '\r') // end of headers, expecting \r\n
				{
					state_ = expecting_newline_3;
					return indeterminate;
				}
				else if (!req.fields_empty() && (input == ' ' || input == '\t')) // optional line folding
				{
					// RFC 7230: Either reject with 400, or replace obs-fold with one or more spaces.
					// We opt for reject.
					error_reason_ = "obsolete line folding is unacceptable";
					return bad;
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
			case header_name:
				if (input == ':')
				{
					state_ = opt_ws_before_header_value;
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
			case opt_ws_before_header_value: // Skip leading white space, see RFC 7230
											 // (https://tools.ietf.org/html/rfc7230#section-3.2).
				if (input == ' ' || input == '\t')
				{
					return indeterminate;
				}
				else
				{
					state_ = header_value;
					// intentional fallthrough to case header_value
				}
				// fallthrough
			case header_value: // warning: fallthrough from state opt_ws_before_header_value
				if (input == '\r') // optional line folding
				{
					state_ = opt_ws_after_header_value;
					// intentional fallthrough to case opt_ws_after_header_value
				}
				else if (input == '\t') // RFC 7230: field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
				{
					req.last_new_field()->value.push_back(input);
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
				// fallthrough
			case opt_ws_after_header_value: // warning: fallthrough from case header_value
				if (input == '\r') // optional line folding is handled by successive states expecting_newline_2,
								   // header_line_start, header_lws, header_value
				{
					state_ = expecting_newline_2;

					// Trailing whitespace is not part of the value, see RFC 7230
					// (https://tools.ietf.org/html/rfc7230#section-3.2). To allow whitespace within the value, we
					// accepted the trailing whitespace in state header_value. Strip here.

					auto& last_new_field_value = req.last_new_field()->value;

					auto last_non_whitespace = last_new_field_value.find_last_not_of(" \t");
					if (last_non_whitespace != std::string::npos)
					{
						if (last_non_whitespace != last_new_field_value.size())
						{
							last_new_field_value = last_new_field_value.substr(0, last_non_whitespace + 1);
						}
					}
					else
					{
						last_new_field_value = "";
					}
					req.merge_new_header();
					return indeterminate;
				}
				else if (input == ' ' || input == '\t')
				{
					return indeterminate;
				}
				else
				{
					return bad;
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
				// fallthrough
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
		opt_ws_before_header_value,
		opt_ws_after_header_value,
		header_value,
		expecting_newline_2,
		expecting_newline_3,
		body_start,
		body_end
	} state_
		= { method_start };

	std::string storage;
	std::string error_reason_; // can be used when parse fails.

public:
	enum class url_decode_options
	{
		path,
		query
	};

	static std::string url_decode(const std::string& in, url_decode_options options = url_decode_options::path)
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
			else if (options == url_decode_options::query && in[i] == '+')
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

	static bool
	url_decode(const std::string& in, std::string& out, url_decode_options options = url_decode_options::path)
	{
		out.clear();
		out.reserve(in.size());
		bool query_part = false;

		for (std::size_t i = 0; i < in.size(); ++i)
		{
			if (in[i] == '?' && options == url_decode_options::path)
			{
				query_part = true;
			}

			if (query_part)
			{
				out += in[i];
			}
			else if (in[i] == '%')
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
			else if (options == url_decode_options::query && in[i] == '+')
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
	response_parser() noexcept : state_(http_version_h){};

	void reset() { state_ = http_version_h; };

	enum result_type
	{
		good,
		bad,
		indeterminate
	};

	template <typename InputIterator>
	std::tuple<result_type, InputIterator> parse(http::response_message& req, InputIterator begin, InputIterator end)
	{
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
				else if (is_ctl(input) || (is_tspecial(input) && !(input == ' ')))
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
				if (input == '\r') // end of headers, expecting \r\n
				{
					state_ = expecting_newline_3;
					return indeterminate;
				}
				else if (!res.fields_empty() && (input == ' ' || input == '\t')) // optional line folding
				{
					// RFC 7230: Either reject with 400, or replace obs-fold with one or more spaces.
					// We opt for reject.
					// error_reason_ = "obsolete line folding is unacceptable";
					return bad;
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
			case header_name:
				if (input == ':')
				{
					state_ = opt_ws_before_header_value;
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
			case opt_ws_before_header_value: // Skip leading white space, see RFC 7230
											 // (https://tools.ietf.org/html/rfc7230#section-3.2).
				if (input == ' ' || input == '\t')
				{
					return indeterminate;
				}
				else
				{
					state_ = header_value;
					// intentional fallthrough to case header_value
				}
				// fallthrough
			case header_value: // warning: fallthrough from state opt_ws_before_header_value
				if (input == '\r') // optional line folding
				{
					state_ = opt_ws_after_header_value;
					// intentional fallthrough to case opt_ws_after_header_value
				}
				else if (input == '\t') // RFC 7230: field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
				{
					res.last_new_field()->value.push_back(input);
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
				// fallthrough
			case opt_ws_after_header_value: // warning: fallthrough from case header_value
				if (input == '\r') // optional line folding is handled by successive states expecting_newline_2,
								   // header_line_start, header_lws, header_value
				{
					state_ = expecting_newline_2;

					// Trailing whitespace is not part of the value, see RFC 7230
					// (https://tools.ietf.org/html/rfc7230#section-3.2). To allow whitespace within the value, we
					// accepted the trailing whitespace in state header_value. Strip here.

					auto& last_new_field_value = res.last_new_field()->value;

					auto last_non_whitespace = last_new_field_value.find_last_not_of(" \t");
					if (last_non_whitespace != std::string::npos)
					{
						if (last_non_whitespace != last_new_field_value.size())
						{
							last_new_field_value = last_new_field_value.substr(0, last_non_whitespace + 1);
						}
					}
					else
					{
						last_new_field_value = "";
					}
					return indeterminate;
				}
				else if (input == ' ' || input == '\t')
				{
					return indeterminate;
				}
				else
				{
					return bad;
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
					state_ = header_value; // line folding
					res.last_new_field()->value.push_back(input);
					return indeterminate;
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
		opt_ws_before_header_value,
		opt_ws_after_header_value,
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

class transfer_encoding_chunked_parser
{
public:
	std::string tmp_chunk_size_;
	size_t chunk_size_still_to_read_;

	enum state
	{
		chunk_header_size,
		chunk_header_end,
		chunk_data,
		chunk_trailer_cr,
		chunk_trailer_lf,
		chunk_0,
		chunk_0_trailer_cr,
		chunk_0_trailer_lf
	};

	void reset()
	{
		tmp_chunk_size_ = "";

		chunk_size_still_to_read_ = 0;
		;
		state_ = chunk_header_size;
	};

	enum result_type
	{
		good,
		bad,
		indeterminate
	};

	state state_{ chunk_header_size };

	template <typename InputIterator>
	std::tuple<result_type, InputIterator> parse(http::request_message& req, InputIterator begin, InputIterator end)
	{
		while (begin != end)
		{
			result_type result = consume(req, *begin++);

			if (result == good)
			{
				state_ = chunk_header_size;
				req.content_length(req.body().size());
				return std::make_tuple(result, begin);
			}
			else if (result == bad)
			{
				state_ = chunk_header_size;
				return std::make_tuple(result, begin);
			}
		}

		return std::make_tuple(indeterminate, begin);
	}

private:
	result_type consume(http::request_message& res, char input)
	{
		switch (state_)
		{
			case chunk_header_size:
				if (is_hex_digit(tolower(input)))
				{
					tmp_chunk_size_.push_back(input);
					return indeterminate;
				}
				else if (input == '\r')
				{
					state_ = chunk_header_end;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case chunk_header_end:
				if (input == '\n')
				{
					state_ = chunk_data;
					chunk_size_still_to_read_ = strtoull(tmp_chunk_size_.data(), NULL, 16);

					if (chunk_size_still_to_read_ == 0) state_ = chunk_0_trailer_cr;

					return indeterminate;
				}
				else
				{
					return bad;
				}
			case chunk_data:
				res.body().push_back(input);
				chunk_size_still_to_read_--;

				if (chunk_size_still_to_read_ > 0)
				{
					return indeterminate;
				}
				else if (chunk_size_still_to_read_ == 0)
				{
					state_ = chunk_trailer_cr;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case chunk_trailer_cr:
				if (input == '\r')
				{
					state_ = chunk_trailer_lf;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case chunk_trailer_lf:
				if (input == '\n')
				{
					state_ = chunk_header_size;
					chunk_size_still_to_read_ = 0;
					tmp_chunk_size_ = "";
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case chunk_0_trailer_cr:
				if (input == '\r')
				{
					state_ = chunk_0_trailer_lf;
					return indeterminate;
				}
				else
				{
					return bad;
				}
			case chunk_0_trailer_lf:
				if (input == '\n')
				{
					state_ = chunk_header_size;
					return good;
				}
				else
				{
					return bad;
				}
			default:
				return bad;
		}
	}

	/// Check if a byte is a digit.
	static bool is_hex_digit(int c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
};

namespace api
{
namespace router_match
{
enum route_context_type
{
	no_route,
	no_method,
	match_found
};
}
} // namespace api

class session_handler
{

public:
	using result_type = http::request_parser::result_type;

	session_handler() = delete;
	session_handler(const session_handler&) = default;
	session_handler(session_handler&&) = delete;
	session_handler& operator=(const session_handler&) = delete;
	session_handler& operator=(session_handler&&) = delete;

	~session_handler() = default;

	session_handler(
		const std::string& server_id,
		int keep_alive_count,
		int keep_alive_timeout,
		int gzip_min_size,
		http::protocol protocol)
		: server_id_(server_id)
		, protocol_(protocol)
		, keepalive_count_(keep_alive_count)
		, keepalive_max_(keep_alive_timeout)
		, gzip_min_size_(gzip_min_size)
		, is_client_allowed_(true)
		, t0_(std::chrono::steady_clock::now())
	{
	}

	template <typename InputIterator>
	std::tuple<request_parser::result_type, InputIterator> parse_request(InputIterator begin, InputIterator end)
	{
		return request_parser_.parse(request_, begin, end);
	}

	const std::string& parse_error_reason() const { return request_parser_.error_reason(); }

	template <typename router_t>
	void handle_response(
		typename router_t::request_result_type& route_result,
		http::status::status_t error_status = http::status::not_found)
	{
		response_.set("Server", server_id_);
		response_.set("Date", util::return_current_time_and_date());

		if (protocol_ == http::protocol::https)
			response_.set("Strict-Transport-Security", "max-age=315360000; includeSubdomains");

		if (response_.get("Content-Type", std::string{}).empty()) response_.type("text");

		switch (route_result.match_result())
		{
			case http::api::router_match::match_found:
			{
				// Route has a valid handler, response body is set.
				// Check bodys size and set headers.
				break;
			}
			case http::api::router_match::no_method:
			{
				response_.set("Allow", route_result.allowed_methods());
				response_.status(http::status::method_not_allowed);
				break;
			}
			case http::api::router_match::no_route:
			{
				response_.status(error_status);
				break;
			}
		}

		// TODO: Currently we use gzip encoding whenever the Accept-Encoding header contains the
		// word "gzip".
		// TODO: "Accept-Encoding: gzip;q=0" means *no* gzip
		// TODO: "Accept-Encoding: gzip;q=0.2, deflate;q=0.5" means preferably deflate, but gzip
		// is good

		if ((gzip_min_size_ < response_.body().size())
			&& (request().get("Accept-Encoding", std::string{}).find("gzip") != std::string::npos)
			&& (response().get<std::string>("Content-Encoding", "") != "gzip")) // e.g. proxied responses might already be zipped
		{
			response_.body() = gzip::compress(response_.body().c_str(), response_.body().size());
			response_.set("Content-Encoding", "gzip");
			response_.set("Content-Length", std::to_string(response_.body().size()));
		}

		if (request().method() == http::method::unknown)
		{
			// no request was parsed, close the connection.
			response().set("Connection", "Close");
		}

		if ((request_.http_version11() == true && keepalive_count() > 1 && request_.connection_close() == false
			 && response_.connection_close() == false)
			|| (request_.http_version11() == false && request_.connection_keep_alive() && keepalive_count() > 1
				&& request_.connection_close() == false))
		{
			keepalive_count_decr();
			response_.set("Connection", "Keep-Alive");
		}
		else
		{
			response_.set("Connection", "close");
		}

		if (response_.status() == http::status::no_content)
		{
			response_.body() = "";
			response_.reset_if_exists("Content-Type");
			response_.reset_if_exists("Content-Length");
		}
		else
		{
			response_.reset_if_exists("Transfer-Encoding");
			response_.content_length(response_.body().length());
		}
	}

	template <typename router_t> typename router_t::request_result_type handle_request(router_t& router_)
	{

		response_.status(http::status::not_found);

		std::string request_path;

		if (is_client_allowed() == false)
		{
			response_.assign(http::status::forbidden, "", "application/text");
			return typename router_t::request_result_type{};
		}

		if (!http::request_parser::url_decode(request_.target(), request_path))
		{
			response_.type("text");
			response_.status(http::status::bad_request);
			return typename router_t::request_result_type{};
		}

		if (request_path.empty() || request_path[0] != '/' || request_path.find("..") != std::string::npos)
		{
			response_.type("text");
			response_.status(http::status::bad_request);
			return typename router_t::request_result_type{};
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
			std::vector<std::string> tokens = util::split(request_path.substr(query_pos + 1), "&");

			request_path = request_path.substr(0, query_pos);
			for (auto& token : tokens)
			{
				std::vector<std::string> name_value = util::split(token, "=");

				std::string name_decoded
					= http::request_parser::url_decode(name_value[0], http::request_parser::url_decode_options::query);

				std::string value_decoded = (name_value.size() == 2) ? http::request_parser::url_decode(
												name_value[1], http::request_parser::url_decode_options::query)
																	 : "";

				request_.query().set(name_decoded, value_decoded);
			}
		}

		if (request_.get("Content-Encoding", std::string{}) == "gzip")
		{
			std::string error_code;

			request_.body() = gzip::decompress(request_.body().c_str(), request_.content_length(), error_code);

			if (error_code.empty() == false)
			{
				response_.type("text");
				response_.status(http::status::bad_request);
				return typename router_t::request_result_type{};
			}
		}

		request_.url_requested_ = request_.target_;
		request_.target_ = request_path;

		return router_.call_route(*this);
	}

	void keepalive_count_decr() { --keepalive_count_; };
	int keepalive_count() const { return keepalive_count_; };

	void keepalive_max(const int& keepalive_max) { keepalive_max_ = keepalive_max; };
	int keepalive_max() const { return keepalive_max_; };

	http::request_parser& request_parser() { return request_parser_; };

	http::response_message& response() { return response_; };
	http::request_message& request() { return request_; };

	const http::response_message& response() const { return response_; };
	const http::request_message& request() const { return request_; };

	const http::api::params& params() const { return *params_; };
	const http::api::routing& routing() const { return *routing_; };
	http::api::routing& routing() { return *routing_; };
	http::protocol protocol() const { return protocol_; };

	void reset()
	{
		t0_ = std::chrono::steady_clock::now();

		request_parser_.reset();
		request_.reset();
		response_.reset();
	}

	std::chrono::steady_clock::time_point& t0() noexcept { return t0_; };
	std::chrono::steady_clock::time_point& t1() noexcept { return t1_; };
	std::chrono::steady_clock::time_point& t2() noexcept { return t2_; };

public:
	void routing(http::api::routing& r) { routing_ = &r; }
	void params(http::api::params& p) { params_ = &p; }
	bool is_client_allowed() const { return is_client_allowed_; }
	void client_allowed(bool value) { is_client_allowed_ = value; };

private:
	http::request_message request_{ *this };
	http::response_message response_{ *this };
	http::request_parser request_parser_;
	std::string server_id_;
	http::api::routing* routing_{ nullptr };
	http::api::params* params_{ nullptr };
	http::protocol protocol_{ http::protocol::http };

	int keepalive_count_;
	int keepalive_max_;
	size_t gzip_min_size_;
	bool is_client_allowed_;

	std::chrono::steady_clock::time_point t0_;
	std::chrono::steady_clock::time_point t1_;
	std::chrono::steady_clock::time_point t2_;
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

	inline const std::string& get(const std::string& name, const std::string& default_value) const
	{
		auto it = parameters.find(name);

		if (it != parameters.end()) // if found
			return it->second;

		return default_value;
	}

	inline const std::string& get(const std::string& name) const noexcept(false)
	{
		auto it = parameters.find(name);

		if (it != parameters.end()) // if found
			return it->second;
		else
			throw std::runtime_error("route param: '" + name + "' does not exists");
	}

	inline bool empty() const noexcept { return parameters.empty(); };

	inline void reset() { parameters.clear(); }

	std::map<std::string, std::string>& as_container() { return parameters; }

	const std::map<std::string, std::string>& as_container() const { return parameters; }

private:
	std::map<std::string, std::string> parameters;
}; // < class Params

using session_handler_type = http::session_handler;

class middleware_lambda_context
{ // Context passed to every C++ middleware handler
public:
	virtual ~middleware_lambda_context() = default;
};

class routing
{
public:
	enum class outcome_status
	{ // http::api::outcome_status
		success,
		bad_function, // dll or function not found, wrong signature
		internal_error, // function failed
		process_terminated // (3gl) process terminated unexpectedly (crashed) during execution of handler
	};

	template <typename T> class outcome
	{ // http::api::outcome
	public:
		outcome() : value_(T()) {}
		explicit outcome(T x)
			: value_(x) {} // explicit, or else a conversion from bool to outcome may happen if T is integral.
		outcome(outcome_status status, std::string error) : status_{ status }, error_(std::move(error)) {}
		outcome_status status() const { return status_; }
		bool success() const { return status_ == outcome_status::success; }
		const std::string& error() const
		{
			assert(status_ != outcome_status::success);
			return error_;
		}
		const T& value() const
		{
			assert(status_ == outcome_status::success);
			return value_;
		}

	private:
		outcome_status status_{ outcome_status::success };
		std::string error_;
		T value_;
	};

	using endpoint_lambda = std::function<void(session_handler_type& session)>;
	using middleware_lambda
		= std::function<outcome<std::int64_t>(middleware_lambda_context& context, session_handler_type& session)>;
	using exception_lambda = std::function<void(session_handler_type& session, std::exception& e)>;
	using result = http::api::router_match::route_context_type;

	// using proxy_pass_lambda = std::function<void(http::session_handler&)>;
	// void proxy_pass_to(proxy_pass_lambda&& proxy_pass) { proxy_pass_ = proxy_pass; }

	struct metrics
	{
		friend class route_result;

		metrics() = default;
		metrics(const metrics& r) noexcept
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
			active_count_.store(r.active_count_);
			response_latency_.store(r.response_latency_);
		}

		metrics& operator=(const metrics& r) noexcept
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
			active_count_.store(r.active_count_);
			response_latency_.store(r.response_latency_);
			return *this;
		}

		metrics(metrics&& r) noexcept
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
			active_count_.store(r.active_count_);
			response_latency_.store(r.response_latency_);
		}

		metrics& operator=(metrics&& r) noexcept
		{
			request_latency_.store(r.request_latency_);
			processing_duration_.store(r.processing_duration_);
			hit_count_.store(r.hit_count_);
			active_count_.store(r.active_count_);
			return *this;
		}

		std::atomic<std::uint64_t> request_latency_{ 0 };
		std::atomic<std::uint64_t> processing_duration_{ 0 };
		std::atomic<std::uint64_t> hit_count_{ 0 };
		std::atomic<std::uint64_t> active_count_{ 0 };
		std::atomic<std::uint64_t> response_latency_{ 0 };

		void to_json(json& result)
		{
			result["request_latency"] = request_latency_.load();
			result["processing_duration"] = processing_duration_.load();
			result["response_latency"] = response_latency_.load();
			result["active_count"] = active_count_.load();
			result["hit_count"] = hit_count_.load();
		}

		std::string to_string()
		{
			std::ostringstream ss;

			ss << request_latency_.load() << "ms, " << processing_duration_.load() << "ms, " << response_latency_.load()
			   << "ms, " << active_count_ << "x, " << hit_count_ << "x";

			return ss.str();
		};

		std::string to_json_string()
		{
			std::ostringstream ss;

			ss << "{\"request_latency\" :" << request_latency_.load()
			   << ",\"processing_duration\":" << processing_duration_.load()
			   << ",\"response_latency\":" << response_latency_.load() << ",\"active_count\":" << active_count_
			   << ",\"hit_count\":" << hit_count_ << "}";

			return ss.str();
		};
	};

	class middleware
	{
		friend class route_part;

	public:
		middleware() = default;
		middleware(const middleware&) = default;

		middleware(std::string middleware_type, std::string middleware_attribute, middleware_lambda middleware_lambda_)
			: middleware_type(std::move(middleware_type))
			, middleware_lambda_(std::move(middleware_lambda_))
			, middleware_attribute_(std::move(middleware_attribute))
		{
		}

		const std::string& type() const { return middleware_type; };
		const middleware_lambda& middleware_labda() const { return middleware_lambda_; };
		const std::string& middleware_attribute() const { return middleware_attribute_; };

	private:
		std::string middleware_type;
		const middleware_lambda middleware_lambda_;
		std::string middleware_attribute_;
	};

	using middlewares = std::vector<std::pair<middleware, middleware>>;

	class route
	{
		friend class route_part;

	public:
		route() = default;
		route(const route& rhs) = delete;
		route& operator=(const route&) = delete;

		route(
			const endpoint_lambda& endpoint,
			const std::string& handler,
			const std::vector<std::string>& consumes,
			const std::vector<std::string>& produces)
			: endpoint_(endpoint), produces_(produces), consumes_(consumes), handler_(handler)
		{
		}

		const endpoint_lambda& endpoint() { return endpoint_; };

		std::atomic<std::uint64_t>& metric_active_count() { return metrics_.active_count_; }

		void metric_response_latency(std::uint64_t response_latency)
		{
			return metrics_.response_latency_.store(response_latency);
		}

		void update_hitcount_and_timing_metrics(
			std::chrono::high_resolution_clock::duration request_duration,
			std::chrono::high_resolution_clock::duration new_processing_duration_)
		{
			metrics_.request_latency_.store(
				std::chrono::duration_cast<std::chrono::milliseconds>(request_duration).count());
			metrics_.processing_duration_.store(
				std::chrono::duration_cast<std::chrono::milliseconds>(new_processing_duration_).count());
			metrics_.hit_count_++;
		}

		metrics& route_metrics() { return metrics_; };

		const std::vector<std::string>& produces() const { return produces_; }
		const std::vector<std::string>& consumes() const { return consumes_; }
		const std::string& handler() const { return handler_; }
		std::unique_ptr<routing::middlewares>& middlewares() { return middlewares_; }

	private:
		endpoint_lambda endpoint_;
		metrics metrics_;
		std::vector<std::string> produces_;
		std::vector<std::string> consumes_;
		std::string handler_;
		std::unique_ptr<routing::middlewares> middlewares_;
	};

	routing(result r = http::api::router_match::no_route) : result_(r) {}

	result& match_result() { return result_; }
	result match_result() const { return result_; }
	route& the_route() { return *route_; }
	void set_route(route* r) { route_ = r; }

	const route& the_route() const { return *route_; }
	middlewares& middlewares_vector() { return middlewares_; }
	const middlewares& middlewares_vector() const { return middlewares_; }

	std::string& allowed_methods() { return allowed_methods_; }
	const std::string& allowed_methods() const { return allowed_methods_; }

	void private_request(bool value) { is_private_base_request_ = value; }
	bool is_private_base_request() const {return is_private_base_request_;}

private:
	result result_;
	route* route_{ nullptr };
	middlewares middlewares_;
	std::string allowed_methods_;
	bool is_private_base_request_;
};

template <
	typename M = http::method::method_t,
	typename T = std::string,
	typename R = routing::endpoint_lambda,
	typename W = routing::middleware_lambda,
	typename E = routing::exception_lambda>
class router
{
public:
	using route_http_method_type = M;
	using route_url_type = T;
	using route_endpoint_type = R;
	using route_middleware_type = W;
	using route_exception_type = E;
	using request_result_type = routing;

	class route_part
	{
		friend class router;

	private:
		std::vector<std::pair<T, std::unique_ptr<route_part>>> link_;
		std::unique_ptr<std::vector<std::pair<M, std::unique_ptr<routing::route>>>> endpoints_;
		std::unique_ptr<routing::middlewares> middlewares_;

		std::string name_;
		std::string service_;

	public:
		route_part(const std::string& service, const std::string& name) : name_(name), service_(service){};

		using const_iterator = typename std::vector<std::pair<T, std::unique_ptr<route_part>>>::const_iterator;

		const_iterator match_param(const std::string& url_part, params& params) const
		{
			for (auto i = link_.cbegin(); i != link_.cend(); i++)
			{
				if (i->first == "*")
				{
					return i;
				}
				else if (*(i->first.begin()) == '{' && *(i->first.rbegin()) == '}')
				{
					params.insert(i->first.substr(1, i->first.size() - 2), http::request_parser::url_decode(url_part));
					return i;
				}
				else if (*(i->first.begin()) == ':')
				{
					params.insert(i->first.substr(1, i->first.size() - 1), http::request_parser::url_decode(url_part));
					return i;
				}
			}

			return link_.cend();
		}

		void to_json(json& result, std::vector<std::string>& path, json middleware_stack = json{})
		{
			if (endpoints_)
			{
				for (auto endpoint = endpoints_.get()->cbegin(); endpoint != endpoints_.get()->cend(); ++endpoint)
				{
					std::stringstream s;
					for (auto& element : path)
						s << "/" << element;

					s << "|" << util::to_lower(http::method::to_string(endpoint->first));

					auto endpoint_json = json::object();

					for (auto& middleware_stack_item : middleware_stack)
					{
						endpoint_json["middlewares"].emplace_back(middleware_stack_item);
					}

					if (middlewares_)
					{
						for (auto& middleware : *middlewares_.get())
						{
							json middleware_json = json::object();
							if (middleware.first.middleware_attribute().empty() == false)
								middleware_json["pre"] = middleware.first.middleware_attribute();

							if (middleware.second.middleware_attribute().empty() == false)
								middleware_json["post"] = middleware.second.middleware_attribute();

							endpoint_json["middlewares"].emplace_back(middleware_json);
						}
					}

					if (endpoint->second->middlewares())
					{
						for (auto& middleware : *endpoint->second->middlewares().get())
						{
							json middleware_json = json::object();
							if (middleware.first.middleware_attribute().empty() == false)
								middleware_json["pre"] = middleware.first.middleware_attribute();

							if (middleware.second.middleware_attribute().empty() == false)
								middleware_json["post"] = middleware.second.middleware_attribute();

							endpoint_json["middlewares"].emplace_back(middleware_json);
						}
					}

					json metrics_json;
					endpoint->second->route_metrics().to_json(metrics_json);

					if (endpoint->second->produces().size())
					{
						for (const auto& produce_entry : endpoint->second->produces())
							endpoint_json["produces"].emplace_back(produce_entry);
					}

					if (endpoint->second->consumes().size())
					{
						for (const auto& consumes_entry : endpoint->second->consumes())
							endpoint_json["consumes"].emplace_back(consumes_entry);
					}

					endpoint_json["details"] = metrics_json;
					endpoint_json["service"] = service_;
					endpoint_json["name"] = name_;

					if (endpoint->second->handler().empty() == false)
						endpoint_json["handler"] = endpoint->second->handler();

					result[s.str()] = endpoint_json;
				}
			}

			auto middleware_stack_org = middleware_stack;

			for (auto link = link_.cbegin(); link != link_.cend(); ++link)
			{
				path.push_back(link->first);

				if (middlewares_)
				{
					for (auto& middleware : *middlewares_.get())
					{
						json middleware_json = json::object();
						if (middleware.first.middleware_attribute().empty() == false)
							middleware_json["pre"] = middleware.first.middleware_attribute();

						if (middleware.second.middleware_attribute().empty() == false)
							middleware_json["post"] = middleware.second.middleware_attribute();

						middleware_stack.emplace_back(middleware_json);
					}
				}

				link->second->to_json(result, path, middleware_stack);

				middleware_stack = middleware_stack_org;
				path.pop_back();
			}
		}

		void to_string_stream(std::stringstream& s, std::vector<std::string>& path)
		{
			if (endpoints_)
			{
				for (const auto& endpoint : *(endpoints_))
				{
					if (path.size() == 0) s << "/";

					for (auto& element : path)
						s << "/" << element;

					s << ", [" << http::method::to_string(endpoint.first) << "], "
					  << endpoint.second->route_metrics().to_string() << "\n";
				}
			}

			for (const auto& link : link_)
			{
				path.push_back(link.first);
				link.second->to_string_stream(s, path);
				path.pop_back();
			}
		}
	};

public:
	std::unique_ptr<route_part> root_;
	E internal_error_method_;
	std::function<bool()> server_started_method_;
	std::function<void(bool)> idle_method_;
	std::function<void()> busy_method_;

	std::string private_base_;

public:
	router(std::string private_base) : root_(new router::route_part{ "root", "root" }), private_base_(private_base) {}

	enum class middleware_type
	{
		pre,
		post,
		both
	};

	std::map<std::string, std::pair<std::string, routing::route*>> service_lookup_;
	std::map<std::string, json> middleware_definiton_cache_;

	using search_result = std::tuple<bool, std::string, routing::route*>;

	search_result search(const std::string& service, const std::string& name)
	{
		auto result = service_lookup_.find(service + "/" + name);
		if (result != service_lookup_.end())
			return search_result{ true, result->second.first, result->second.second };
		else
			return search_result{ false, "", nullptr };
	}

	using on_error = std::function<bool(const std::string& current_file, const std::string& message)>;
	using on_use_middleware = std::function<void(
		const std::string& current_file,
		const std::string& service,
		const std::string& name,
		http::method::method_t method,
		const std::string& path,
		const std::string& type,
		const std::string& pre_attribute,
		const std::string& post_attribute)>;
	using on_use_endpoint = std::function<void(
		const std::string& current_file,
		const std::string& service,
		const std::string& name,
		http::method::method_t method,
		const std::string& route,
		const std::string& type,
		const std::string& endpoint_handler,
		const std::vector<std::string>& consumes,
		const std::vector<std::string>& produces)>;
	using on_use_include_file = std::function<std::string(const std::string&, const std::string&)>;

	void use_registry(
		const std::string& route_path,
		const std::string& registry_file,
		on_error on_error,
		on_use_middleware on_use_middleware,
		on_use_endpoint on_use_endpoint)
	{
		use_registry(
			route_path,
			registry_file,
			on_error,
			[](const std::string& file_path) { return file_path; },
			on_use_middleware,
			on_use_endpoint);
	}

	void use_middleware_from_registry(
		const std::string& route_path,
		const std::string& registry_file,
		const std::string& service,
		json middleware_entry,
		on_error on_error,
		on_use_include_file file_path_conversion,
		on_use_middleware on_use_middleware,
		on_use_endpoint on_use_endpoint)
	{
		auto registry_base_path = registry_file.substr(0, registry_file.find_last_of('/') + 1);

		if (middleware_entry.is_object())
		{
			auto type = middleware_entry.value("type", "");
			auto pre = middleware_entry.value("pre", "");
			auto post = middleware_entry.value("post", "");

			on_use_middleware(registry_file, service, "", http::method::unknown, route_path, type, pre, post);
		}
		else
			for (auto& middlewares : middleware_entry)
			{
				for (auto& middleware : middlewares.items())
				{
					if (middleware.key() == "$ref")
					{
						auto tokens = util::split(middleware.value(), "#");

						auto middleware_json = middleware_definiton_cache_.find(tokens[1]);

						if (middleware_json == middleware_definiton_cache_.end())
						{
							use_registry(
								registry_file,
								route_path,
								registry_base_path + tokens[0],
								on_error,
								file_path_conversion,
								on_use_middleware,
								on_use_endpoint);

							middleware_json = middleware_definiton_cache_.find(tokens[1]);

							if (middleware_json == middleware_definiton_cache_.cend())
							{
								on_error(
									registry_file,
									"error when reading router registry file " + registry_file + " : " + tokens[1]
										+ " is not defined");

								break;
							}
						}

						auto type = middleware_json->second.value("type", "");
						auto pre = middleware_json->second.value("pre", "");
						auto post = middleware_json->second.value("post", "");

						on_use_middleware(
							registry_file, service, "", http::method::unknown, route_path, type, pre, post);
					}
					else
					{
						// local definition of the middleware
						// as we are in an entrys() loop we hit this for each object property
						auto type = middlewares.value("type", "");
						auto pre = middlewares.value("pre", "");
						auto post = middlewares.value("post", "");

						on_use_middleware(
							registry_file, service, "", http::method::unknown, route_path, type, pre, post);

						break; // NDJ --> do not enumerate this is a no-name middleware;
					}
				}
			}
	}

	void use_route_path_from_registry(
		const std::string& route_path,
		const std::string& registry_file,
		const std::string& base_service,
		json path_entry,
		on_error on_error,
		on_use_include_file on_use_include_file,
		on_use_middleware on_use_middleware,
		on_use_endpoint on_use_endpoint)
	{
		auto registry_base_path = registry_file.substr(0, registry_file.find_last_of('/') + 1);

		for (auto& path : path_entry.items())
		{
			auto test = path.key();

			if (path.key() == "middlewares")
			{
				use_middleware_from_registry(
					route_path,
					registry_file,
					base_service,
					path.value(),
					on_error,
					on_use_include_file,
					on_use_middleware,
					on_use_endpoint);
			}
			else if (path.key() == "$ref" || path.key() == "#include")
			{
				use_registry(
					registry_file,
					route_path,
					path.value(),
					on_error,
					on_use_include_file,
					on_use_middleware,
					on_use_endpoint);
			}
			else if (path.value().is_array() == true)
			{
				for (auto& path_elements : path.value().items())
				{
					std::string route_path_new = route_path == "/" ? path.key() : route_path + path.key();
					std::string name = path_elements.value().value("name", "");
					std::string service = path_elements.value().value("service", base_service);

					use_route_path_from_registry(
						route_path_new,
						registry_file,
						service,
						path_elements.value(),
						on_error,
						on_use_include_file,
						on_use_middleware,
						on_use_endpoint);
				}
			}
			else if (path.value().is_object() == true)
			{
				std::string route_path_new = route_path == "/" ? path.key() : route_path + path.key();
				std::string name = path.value().value("name", "");
				std::string service = path.value().value("service", base_service);

				for (auto& path_elements : path.value().items())
				{
					auto key = path_elements.key();
					std::transform(
						key.begin(), key.end(), key.begin(), [](char c) { return static_cast<char>(std::toupper(c)); });

					auto method = http::method::to_method(key);
					if (method != http::method::unknown)
					{
						std::string handler = path_elements.value().at("endpoint").at("handler");
						std::string type = path_elements.value().at("endpoint").at("type");

						std::vector<std::string> produces;
						std::vector<std::string> consumes;

						if (path_elements.value().contains("produces"))
							for (auto& produces_entry : path_elements.value().at("produces").items())
							{
								produces.emplace_back(produces_entry.value());
							}

						if (path_elements.value().contains("consumes"))
							for (auto& consumes_entry : path_elements.value().at("consumes").items())
							{
								consumes.emplace_back(consumes_entry.value());
							}

						on_use_endpoint(
							registry_file, service, name, method, route_path_new, type, handler, produces, consumes);

						if (path_elements.value().contains("middlewares"))
						{
							// local definition of the middleware
							// as we are in an entrys() loop we hit this for each object property
							for (auto& middlewares_entry : path_elements.value().at("middlewares").items())
							{
								auto type = middlewares_entry.value().value("type", "");
								auto pre = middlewares_entry.value().value("pre", "");
								auto post = middlewares_entry.value().value("post", "");

								on_use_middleware(
									registry_file, service, name, method, route_path_new, type, pre, post);
							}
						}
					}
					else if (path_elements.key() == "paths")
					{
						use_route_path_from_registry(
							route_path_new,
							registry_file,
							service,
							path_elements.value(),
							on_error,
							on_use_include_file,
							on_use_middleware,
							on_use_endpoint);
					}
					else if (path_elements.key() == "middlewares")
					{
						use_middleware_from_registry(
							route_path_new,
							registry_file,
							service,
							path_elements.value(),
							on_error,
							on_use_include_file,
							on_use_middleware,
							on_use_endpoint);
					}
				}
			}
		}
		// if (path_entry.key() == "paths")
		//{
		//	for (auto& path : path_entry.items())
		//	{
		//		std::string route_path_new = route_path == "/" ? path.key() : route_path_new + path.key();
		//		use_route_path_from_registry(route_path_new, registry_file, path.value(), logger, file_path_conversion);
		//	}
		//}
		// else
		//{

		//}
	}

	void use_registry(
		const std::string& registry_file_base,
		const std::string& route_path,
		const std::string& registry_file,
		on_error on_error,
		on_use_include_file on_use_include_file,
		on_use_middleware on_use_middleware,
		on_use_endpoint on_use_endpoint)
	{
		try
		{
			auto registry_base_path = registry_file.substr(0, registry_file.find_last_of('/') + 1);
			auto root_registry_json
				= load_registry_file(registry_file_base, registry_file, on_error, on_use_include_file);
			if (root_registry_json.is_object() == false) return;

			std::string registry_version = root_registry_json["httpreg"];
			std::string date = root_registry_json.at("info").at("date");
			std::string name = root_registry_json.at("info").at("name");

			if (root_registry_json.at("data").contains("middlewares"))
				for (auto& entry : root_registry_json.at("data").at("middlewares").items())
				{
					auto key = entry.key();
					auto value = entry.value();

					middleware_definiton_cache_["/middlewares/" + key] = value;
				}

			if (root_registry_json.at("data").contains("paths"))
				for (auto& entry : root_registry_json.at("data").at("paths").items())
				{
					auto key = entry.key();
					auto value = entry.value();

					if (value.is_array() && key == "middlewares")
					{
						use_middleware_from_registry(
							route_path,
							registry_file,
							"",
							value,
							on_error,
							on_use_include_file,
							on_use_middleware,
							on_use_endpoint);
					}
					else if (value.is_array() && key[0] == '/')
					{
						std::string route_path_new = route_path == "/" ? key : route_path + key;

						for (auto& path_entry : value.items())
						{

							for (auto& path : path_entry.value().items())
							{
								std::string service{};
								auto route = path.key();
								auto details = path.value();
								if (path_entry.value().is_object()) service = path_entry.value().value("service", "");

								if (route == "$ref")
								{
									use_registry(
										registry_file,
										route_path_new,
										registry_base_path + std::string{ details },
										on_error,
										on_use_include_file,
										on_use_middleware,
										on_use_endpoint);
								}
								else if (route == "paths")
								{
									use_route_path_from_registry(
										route_path_new,
										registry_file,
										service,
										details,
										on_error,
										on_use_include_file,
										on_use_middleware,
										on_use_endpoint);
								}
								else if (route == "middlewares")
								{
									use_middleware_from_registry(
										route_path_new,
										registry_file,
										service,
										details,
										on_error,
										on_use_include_file,
										on_use_middleware,
										on_use_endpoint);
								}
							}
						}
					}
					else if (value.is_object() && key[0] == '/')
					{
						std::string route_path_new = route_path == "/" ? key : route_path + key;
						std::string service = value.value("service", "");

						if (value.contains("middlewares"))
						{
							use_middleware_from_registry(
								route_path_new,
								registry_file,
								service,
								value.at("middlewares"),
								on_error,
								on_use_include_file,
								on_use_middleware,
								on_use_endpoint);
						}

						if (value.contains("paths"))
						{
							for (auto& path : value.at("paths").items())
							{
								use_route_path_from_registry(
									route_path_new,
									registry_file,
									service,
									path,
									on_error,
									on_use_include_file,
									on_use_middleware,
									on_use_endpoint);
							}
						}
						else
						{
							std::string route_path_new = route_path == "/" ? key : route_path + key;
							std::string name = value.value("name", "");
							std::string service = value.value("service", "");

							for (auto& path_elements : value.items())
							{
								auto key = path_elements.key();
								std::transform(key.begin(), key.end(), key.begin(), [](char c) {
									return static_cast<char>(std::toupper(c));
								});

								auto method = http::method::to_method(key);
								if (method != http::method::unknown)
								{
									std::string handler = path_elements.value().at("endpoint").at("handler");
									std::string type = path_elements.value().at("endpoint").at("type");

									std::vector<std::string> produces;
									std::vector<std::string> consumes;

									if (path_elements.value().contains("produces"))
										for (auto& produces_entry : path_elements.value().at("produces").items())
										{
											produces.emplace_back(produces_entry.value());
										}

									if (path_elements.value().contains("consumes"))
										for (auto& consumes_entry : path_elements.value().at("consumes").items())
										{
											consumes.emplace_back(consumes_entry.value());
										}

									on_use_endpoint(
										registry_file,
										service,
										name,
										method,
										route_path_new,
										type,
										handler,
										produces,
										consumes);

									if (path_elements.value().contains("middlewares"))
									{
										// local definition of the middleware
										// as we are in an entrys() loop we hit this for each object property
										for (auto& middlewares_entry : path_elements.value().at("middlewares").items())
										{
											auto type = middlewares_entry.value().value("type", "");
											auto pre = middlewares_entry.value().value("pre", "");
											auto post = middlewares_entry.value().value("post", "");

											on_use_middleware(
												registry_file, service, name, method, route_path_new, type, pre, post);
										}
									}
								}
								else if (path_elements.key() == "paths")
								{
									use_route_path_from_registry(
										route_path_new,
										registry_file,
										service,
										path_elements.value(),
										on_error,
										on_use_include_file,
										on_use_middleware,
										on_use_endpoint);
								}
								else if (path_elements.key() == "middlewares")
								{
									use_middleware_from_registry(
										route_path_new,
										registry_file,
										service,
										path_elements.value(),
										on_error,
										on_use_include_file,
										on_use_middleware,
										on_use_endpoint);
								}
							}
						}
					}
					else if (value.is_null())
					{
					}
					else
					{
						on_error(
							registry_file,
							"warning: wrong json type found in path object" + registry_file + " : " + key);
					}
				}
		}
		catch (json::exception& e)
		{
			on_error(registry_file, "error when reading router registry file: " + registry_file + " : " + e.what());
		}
	}

	json load_registry_file(
		const std::string& registry_file_included_from,
		const std::string& registry_file,
		on_error on_error,
		on_use_include_file on_use_include_file)
	{
		std::string real_registry_file = on_use_include_file(registry_file_included_from, registry_file);

		std::ifstream registry_stream{ real_registry_file };

		auto registry_stream_available = registry_stream.fail() == false;

		if (registry_stream_available)
		{
			try
			{
				return json::parse(registry_stream);
			}
			catch (json::exception& e)
			{
				on_error(
					registry_file_included_from,
					"error when reading router registry file: " + registry_file + " : " + e.what());
			}
		}

		on_error(
			registry_file_included_from,
			"error when reading router registry file: " + registry_file + " : file not found");

		return json{};
	}

	void use_middleware(
		const std::string& service,
		const std::string& name,
		const M method,
		const std::string& path,
		const std::string& type,
		const std::string& pre_middleware_attribute,
		const std::string& post_middleware_attribute)
	{
		W empty;

		auto middleware_pair = std::make_pair<routing::middleware, routing::middleware>(
			{ type, pre_middleware_attribute, empty }, { type, post_middleware_attribute, empty });

		on_middleware(service, name, method, path, middleware_pair);
	}

	void use_middleware(
		const std::string& service,
		const std::string& name,
		const std::string& path,
		const std::string& type,
		const std::string& pre_middleware_attribute,
		const std::string& post_middleware_attribute)
	{
		W empty;

		auto middleware_pair = std::make_pair<routing::middleware, routing::middleware>(
			{ type, pre_middleware_attribute, empty }, { type, post_middleware_attribute, empty });

		on_middleware(service, name, path, middleware_pair);
	}

	void use_middleware(
		const std::string& service,
		const std::string& name,
		const M method,
		const std::string& path,
		const std::string& pre_middleware_attribute,
		W&& middleware_pre_function,
		const std::string& post_middleware_attribute,
		W&& middleware_post_function)
	{
		auto middleware_pair = std::make_pair<routing::middleware, routing::middleware>(
			{ "C++", pre_middleware_attribute, middleware_pre_function },
			{ "C++", post_middleware_attribute, middleware_post_function });

		on_middleware(service, name, method, path, middleware_pair);
	}

	void use_middleware(const std::string& path, W&& middleware_pre_function, W&& middleware_post_function)
	{
		auto middleware_pair = std::make_pair<routing::middleware, routing::middleware>(
			{ "C++", {}, middleware_pre_function }, { "C++", {}, middleware_post_function });

		on_middleware(path, middleware_pair);
	}
	void on_server_started(std::function<bool()>&& server_started_method)
	{
		server_started_method_ = std::move(server_started_method);
	}

	void on_idle(std::function<void(bool)>&& idle_method) { idle_method_ = std::move(idle_method); }

	void on_busy(std::function<void()>&& busy_method) { busy_method_ = std::move(busy_method); }

	void on_internal_error(E&& internal_error_method) { internal_error_method_ = std::move(internal_error_method); }

	void on_get(std::string&& route, R&& api_method) { on_http_method(method::get, route, std::move(api_method)); }

	void on_post(std::string&& route, R&& api_method) { on_http_method(method::post, route, std::move(api_method)); }

	void on_head(std::string&& route, R&& api_method) { on_http_method(method::head, route, std::move(api_method)); }

	void on_put(std::string&& route, R&& api_method) { on_http_method(method::put, route, std::move(api_method)); }

	void on_delete(std::string&& route, R&& api_method)
	{
		on_http_method(method::delete_, route, std::move(api_method));
	}

	void on_patch(std::string&& route, R&& api_method) { on_http_method(method::patch, route, std::move(api_method)); }

	void on_options(std::string&& route, R&& api_method)
	{
		on_http_method(method::options, route, std::move(api_method));
	}

	void on_proxy_pass(std::string&& route, R&& api_method)
	{
		on_http_method(method::proxy_pass, route, std::move(api_method));
	}

	void on_middleware(
		const std::string& service,
		const std::string& name,
		M method,
		const T& route,
		const std::pair<routing::middleware, routing::middleware>& middleware_pair)
	{
		auto it = root_.get();

		auto parts = util::split(route, "/");

		for (const auto& part : parts)
		{
			// auto& l = it->link_[part];

			auto l = std::find_if(
				it->link_.begin(), it->link_.end(), [&part](const std::pair<T, std::unique_ptr<route_part>>& l) {
					return (l.first == part);
				});

			if (l == it->link_.end())
			{
				l = it->link_.insert(
					it->link_.end(),
					std::pair<T, std::unique_ptr<router::route_part>>{
						T{ part }, std::unique_ptr<router::route_part>{ new router::route_part{ service, name } } });
			}

			it = l->second.get();
		}

		if (method != http::method::unknown)
		{
			if (it->endpoints_)
			{
				auto endpoint = std::find_if(
					it->endpoints_->begin(),
					it->endpoints_->end(),
					[method](const std::pair<M, std::unique_ptr<routing::route>>& e) { return (e.first == method); });

				if (endpoint != it->endpoints_->end())
				{
					if (!endpoint->second->middlewares())
						endpoint->second->middlewares().reset(new routing::middlewares{});
					endpoint->second->middlewares()->emplace_back(middleware_pair);
				}
			}
		}
		else
		{
			if (!it->middlewares_) it->middlewares_.reset(new routing::middlewares{});

			it->middlewares_->emplace_back(middleware_pair);
		}
	}

	void on_middleware(
		const std::string& service,
		const std::string& name,
		const T& route,
		const std::pair<routing::middleware, routing::middleware>& middleware_pair)
	{
		auto it = root_.get();

		auto parts = util::split(route, "/");

		for (const auto& part : parts)
		{
			// auto& l = it->link_[part];

			auto l = std::find_if(
				it->link_.begin(), it->link_.end(), [&part](const std::pair<T, std::unique_ptr<route_part>>& l) {
					return (l.first == part);
				});

			if (l == it->link_.end())
			{
				l = it->link_.insert(
					it->link_.end(),
					std::pair<T, std::unique_ptr<router::route_part>>{
						T{ part }, std::unique_ptr<router::route_part>{ new router::route_part{ service, name } } });
			}

			it = l->second.get();
		}

		if (!it->middlewares_) it->middlewares_.reset(new routing::middlewares{});

		it->middlewares_->emplace_back(middleware_pair);
	}

	void on_http_method(const M method, const T& route, R&& end_point)
	{
		auto split_route = util::split(route, "/");
		auto last_part = std::string{};

		if (split_route.size())
		{
			last_part = *(split_route.crbegin());

			if (last_part[0] == '{')
				if (split_route.size() > 2) last_part = *(split_route.crbegin() + 1);
		}

		on_http_method("root", last_part, method, route, "", {}, {}, std::move(end_point));
	}

	void on_http_method(
		const std::string& service,
		const std::string& name,
		const M method,
		const T& route,
		const std::string& meta_data,
		const std::vector<std::string>& produces,
		const std::vector<std::string>& consumes,
		R&& end_point)
	{
		auto it = root_.get();

		auto parts = util::split(route, "/");

		for (auto part : parts)
		{
			auto l = std::find_if(
				it->link_.begin(), it->link_.end(), [&part](const std::pair<T, std::unique_ptr<route_part>>& l) {
					return (l.first == part);
				});

			if (l == it->link_.end())
			{
				l = it->link_.insert(
					it->link_.end(),
					std::pair<T, std::unique_ptr<router::route_part>>{
						std::string{ part },
						std::unique_ptr<router::route_part>{ new router::route_part{ service, name } } });
			}

			it = l->second.get();
		}

		if (!it->endpoints_) it->endpoints_.reset(new std::vector<std::pair<M, std::unique_ptr<routing::route>>>);

		auto new_endpoint = it->endpoints_->insert(
			it->endpoints_->end(),
			std::pair<M, std::unique_ptr<routing::route>>{
				M{ method },
				std::unique_ptr<routing::route>{ new routing::route{ end_point, meta_data, consumes, produces } } });

		service_lookup_[service + "/" + name]
			= std::pair<std::string, routing::route*>{ route, new_endpoint->second.get() };
	}

	routing match_route(const http::method::method_t& method, const std::string& url, params& params) const noexcept
	{
		routing result{};
		auto it = root_.get();

		if (it->middlewares_)
		{
			for (auto m = it->middlewares_->cbegin(); m != it->middlewares_->cend(); ++m)
			{
				result.middlewares_vector().emplace_back(*m);
			}
		}

		auto parts = util::split(url, "/");
		auto part_index = size_t(0);
		for (const auto& part : parts)
		{
			auto l = std::find_if(
				it->link_.cbegin(), it->link_.cend(), [&part](const std::pair<T, std::unique_ptr<route_part>>& l) {
					return (l.first == part);
				});

			if (l == std::end(it->link_))
			{
				auto parameter_route = it->match_param(part, params);
				if (parameter_route == it->link_.cend())
				{
					if (it->endpoints_)
					{
						auto endpoint = std::find_if(
							it->endpoints_->cbegin(),
							it->endpoints_->cend(),
							[](const std::pair<M, std::unique_ptr<routing::route>>& e) {
								return (e.first == http::method::proxy_pass);
							});

						if (endpoint != it->endpoints_->cend())
						{
							result.match_result() = http::api::router_match::match_found;
							result.set_route(endpoint->second.get());
							if (endpoint->second->middlewares())
							{
								for (auto m = endpoint->second->middlewares()->cbegin();
									 m != endpoint->second->middlewares()->cend();
									 ++m)
								{
									result.middlewares_vector().emplace_back(*m);
								}
							}

							return result;
						}
						else
							return routing(http::api::router_match::no_route);
					}
					else
					{
						// no route found, return proxy_pass if root is proxy_pass
						if (root_->endpoints_)
						{
							auto endpoint = std::find_if(
								root_->endpoints_->cbegin(),
								root_->endpoints_->cend(),
								[](const std::pair<M, std::unique_ptr<routing::route>>& e) {
									return (e.first == http::method::proxy_pass);
								});

							if (endpoint != root_->endpoints_->cend())
							{
								result.match_result() = http::api::router_match::match_found;
								result.set_route(endpoint->second.get());
								return result;
							}
						}
						else
						{
							return routing(http::api::router_match::no_route);
						}
					}
				}
				else
				{
					l = it->link_.begin();

					{
						// /url/* matching is work in progress. If no other route exists with the same prefix it seems
						// to work.
						if (l->first == "*")
						{
							std::string url_remainder{};
							for (auto i = part_index; i < parts.size(); i++)
							{
								url_remainder += parts[i];

								if (i < (parts.size() - 1))
								{
									url_remainder += "/";
								}
							}
							params.insert("*", url_remainder); // Unencoded (?)
							it = l->second.get(); // make sure endpoint can be found and we can continue;
							break;
						}
						else
						{
							l = parameter_route;
						}
					}
				}
			}

			if (l->second->middlewares_)
			{
				for (auto m = l->second->middlewares_->cbegin(); m != l->second->middlewares_->cend(); ++m)
				{
					result.middlewares_vector().emplace_back(*m);
				}
			}

			part_index++;
			it = l->second.get();
		}

		if (!it->endpoints_) return result;

		auto endpoint = std::find_if(
			it->endpoints_->cbegin(),
			it->endpoints_->cend(),
			[&method](const std::pair<M, std::unique_ptr<routing::route>>& e) { return (e.first == method); });

		if (endpoint != it->endpoints_->end())
		{
			if (endpoint->second->middlewares())
			{
				for (auto m = endpoint->second->middlewares()->cbegin(); m != endpoint->second->middlewares()->cend();
					 ++m)
				{
					result.middlewares_vector().emplace_back(*m);
				}
			}

			result.match_result() = http::api::router_match::match_found;
			result.set_route(endpoint->second.get());
			return result;
		}
		else
		{
			for (const auto& endpoint_entry : *(it->endpoints_))
			{
				if (result.allowed_methods().empty() == false)
					result.allowed_methods()
						= http::method::to_string(endpoint_entry.first) + ", " + result.allowed_methods();
				else
					result.allowed_methods() = http::method::to_string(endpoint_entry.first);
			}

			result.match_result() = http::api::router_match::no_method;
			return result;
		}
	}

	json to_json()
	{
		json result;
		std::vector<std::string> path_stack;
		root_->to_json(result["endpoints"], path_stack);

		for (const auto& service : service_lookup_)
			result["services"][service.first] = service.second.first;

		return result;
	}

	std::string to_json_string()
	{
		std::stringstream result;

		std::vector<std::string> path_stack;

		root_->to_string_stream_json(result, path_stack);

		return result.str();
	}

	std::string to_string()
	{
		std::stringstream result;

		std::vector<std::string> path_stack;

		root_->to_string_stream(result, path_stack);

		return result.str();
	}

	http::api::routing call_route(session_handler_type& session)
	{
		auto url = session.request().url_requested().substr(0, session.request().url_requested().find_first_of('?'));

		params route_params;

		auto route_context = match_route(session.request().method(), url, route_params);

		session.routing(route_context);
		session.params(route_params);

		if (route_context.match_result() == http::api::router_match::match_found)
		{
			auto t0 = std::chrono::steady_clock::now();
			route_context.the_route().metric_active_count()++;

			if (internal_error_method_)
			{
				try
				{
					route_context.the_route().endpoint()(session);
				}
				catch (std::exception& e)
				{
					if (internal_error_method_) internal_error_method_(session, e);
				}
			}
			else
				route_context.the_route().endpoint()(session);

			route_context.the_route().metric_active_count()--;

			auto t1 = std::chrono::steady_clock::now();
			route_context.the_route().update_hitcount_and_timing_metrics(t0 - session.t0(), t1 - t0);
		}
		return route_context;
	}
};

} // namespace api

#if !defined(HTTP_DO_NOT_USE_CURL)
namespace client
{

class curl_session
{
public:
	curl_session() : hnd_(curl_easy_init()) { static curl_global c; }

	~curl_session()
	{
		curl_easy_cleanup(hnd_);
		hnd_ = nullptr;
	}

	CURL* as_handle() const { return hnd_; }

private:
	CURL* hnd_;

	class curl_global
	{
	public:
		curl_global() { curl_global_init(CURL_GLOBAL_ALL); }

		~curl_global() { curl_global_cleanup(); }
	};
};

class curl
{
	const curl_session& session_;
	std::ostringstream buffer_;
	char error_buf_[CURL_ERROR_SIZE];
	curl_slist* headers_;
	http::response_message response_message_;
	http::response_parser response_message_parser_;
	http::response_parser::result_type response_message_parser_result_;
	std::string verb_;
	std::string url_;

	// needed by cURL to read the data from the http(s) connection
	static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp)
	{
		auto* str = static_cast<std::ostringstream*>(userp);
		char* buf = static_cast<char*>(contents);
		str->write(buf, size * nmemb);

		return size * nmemb;
	}

	static size_t recv_header_callback(char* buffer, size_t size, size_t nmemb, void* userp)
	{
		std::string headerline(buffer);
		char* c = nullptr;
		auto this_curl = static_cast<curl*>(userp);

		std::tie(this_curl->response_message_parser_result_, c)
			= this_curl->response_message_parser_.parse(this_curl->response_message_, buffer, buffer + (size * nmemb));

		return size * nmemb;
	}

	// debugger callback for cURL tracing.
	static int debug_callback(CURL*, curl_infotype type, char* data, size_t size, void* userptr)
	{
		std::ostream& out = *static_cast<std::ostream*>(userptr);
		std::string data_str{ data, size };

		switch (type)
		{
			case CURLINFO_TEXT:
				out << "== Info: " << data_str;
				return 0;
			default: /* in case a new one is introduced to shock us */
				return 0;
			case CURLINFO_HEADER_OUT:
				out << "=> Send header\n";
				break;
			case CURLINFO_DATA_OUT:
				out << "=> Send data";
				break;
			case CURLINFO_SSL_DATA_OUT:
				out << "=> Send SSL data\n";
				break;
			case CURLINFO_HEADER_IN:
				out << "<= Recv header\n";
				break;
			case CURLINFO_DATA_IN:
				out << "<= Recv data\n";
				break;
			case CURLINFO_SSL_DATA_IN:
				out << "<= Recv SSL data";
				break;
		}

		out << "==start==\n" << data_str << "\n==end==\n";

		return 0;
	}

public:
	curl(
		const curl_session& session,
		const std::string& verb,
		const std::string& url,
		std::initializer_list<std::string> hdrs,
		const std::string& body,
		bool verbose = false,
		std::ostream& verbose_output_stream = std::clog)
		: session_(session), buffer_(), headers_(nullptr), verb_(verb), url_(url)
	{
		strcpy(error_buf_, "");

		if (verbose)
		{
			curl_easy_setopt(session_.as_handle(), CURLOPT_VERBOSE, 1);
			curl_easy_setopt(session_.as_handle(), CURLOPT_DEBUGFUNCTION, debug_callback);
			curl_easy_setopt(session_.as_handle(), CURLOPT_DEBUGDATA, reinterpret_cast<void*>(&verbose_output_stream));
		}
		curl_easy_setopt(session_.as_handle(), CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(session_.as_handle(), CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(session_.as_handle(), CURLOPT_WRITEDATA, (void*)&buffer_);
		curl_easy_setopt(session_.as_handle(), CURLOPT_ERRORBUFFER, error_buf_);
		curl_easy_setopt(session_.as_handle(), CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(session_.as_handle(), CURLOPT_HEADERFUNCTION, recv_header_callback);
		curl_easy_setopt(session_.as_handle(), CURLOPT_HEADERDATA, (void*)this);
		curl_easy_setopt(session_.as_handle(), CURLOPT_TIMEOUT_MS, 1000L);
		curl_easy_setopt(session_.as_handle(), CURLOPT_CONNECTTIMEOUT_MS, 1000L);
		curl_easy_setopt(session_.as_handle(), CURLOPT_TCP_NODELAY, 0);
		curl_easy_setopt(session_.as_handle(), CURLOPT_NOPROGRESS, 1L);

		for (const auto& a : hdrs)
		{
			headers_ = curl_slist_append(headers_, a.c_str());
		}
		headers_ = curl_slist_append(headers_, std::string{ "Expect: " }.c_str());
		curl_easy_setopt(session_.as_handle(), CURLOPT_HTTPHEADER, headers_);
		curl_easy_setopt(session_.as_handle(), CURLOPT_CUSTOMREQUEST, verb.c_str());
		curl_easy_setopt(session_.as_handle(), CURLOPT_URL, url.c_str());

		curl_easy_setopt(session_.as_handle(), CURLOPT_POSTFIELDS, body.data());
		curl_easy_setopt(session_.as_handle(), CURLOPT_POSTFIELDSIZE, body.size());
	}

	curl(
		const curl_session& session,
		const std::string host,
		const http::request_message& request,
		bool verbose = false,
		std::ostream& verbose_output_stream = std::clog)
		: session_(session)
		, buffer_()
		, headers_(nullptr)
		, verb_(http::method::to_string(request.method()))
		, url_(host + request.url_requested())
	{
		strcpy(error_buf_, "");

		if (verbose)
		{
			curl_easy_setopt(session_.as_handle(), CURLOPT_VERBOSE, 1);
			curl_easy_setopt(session_.as_handle(), CURLOPT_DEBUGFUNCTION, debug_callback);
			curl_easy_setopt(session_.as_handle(), CURLOPT_DEBUGDATA, reinterpret_cast<void*>(&verbose_output_stream));
		}
		curl_easy_setopt(session_.as_handle(), CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(session_.as_handle(), CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(session_.as_handle(), CURLOPT_WRITEDATA, (void*)&buffer_);
		curl_easy_setopt(session_.as_handle(), CURLOPT_ERRORBUFFER, error_buf_);
		curl_easy_setopt(session_.as_handle(), CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(session_.as_handle(), CURLOPT_HEADERFUNCTION, recv_header_callback);
		curl_easy_setopt(session_.as_handle(), CURLOPT_HEADERDATA, (void*)this);
		curl_easy_setopt(session_.as_handle(), CURLOPT_TIMEOUT_MS, 1000L);
		curl_easy_setopt(session_.as_handle(), CURLOPT_CONNECTTIMEOUT_MS, 1000L);
		curl_easy_setopt(session_.as_handle(), CURLOPT_TCP_NODELAY, 0);
		curl_easy_setopt(session_.as_handle(), CURLOPT_NOPROGRESS, 1L);

		for (const auto& header : request.headers())
		{
			headers_ = curl_slist_append(headers_, std::string{ header.name + ": " + header.value }.c_str());
		}
		headers_ = curl_slist_append(headers_, std::string{ "Expect: " }.c_str());
		curl_easy_setopt(session_.as_handle(), CURLOPT_HTTPHEADER, headers_);
		curl_easy_setopt(session_.as_handle(), CURLOPT_CUSTOMREQUEST, verb_.c_str());
		curl_easy_setopt(session_.as_handle(), CURLOPT_URL, url_.c_str());
		curl_easy_setopt(session_.as_handle(), CURLOPT_POSTFIELDS, request.body().data());
		curl_easy_setopt(session_.as_handle(), CURLOPT_POSTFIELDSIZE, request.body().size());
	}

	~curl() { curl_slist_free_all(headers_); }

	http::response_message call(std::string& error) noexcept
	{
		CURLcode ret = curl_easy_perform(session_.as_handle());
		curl_easy_reset(session_.as_handle());
		if (ret != CURLE_OK)
		{
			error = std::string{ curl_easy_strerror(ret) } + " when requesting " + verb_ + " on url: " + url_;
			return response_message_;
		}
		else
		{
			response_message_.body() = buffer_.str();
			return response_message_;
		}
	}

	http::response_message call()
	{
		CURLcode ret = curl_easy_perform(session_.as_handle());

		if (ret != CURLE_OK)
		{
			throw std::runtime_error{ std::string{ curl_easy_strerror(ret) } + " request:" + verb_ + " " + url_ };
		}
		else
		{
			response_message_.body() = buffer_.str();
			return response_message_;
		}
	}
};

} // namespace client
#endif

class server
{
public:
	server(const http::configuration& configuration)
		: manager_(*this)
		, router_(configuration.get<std::string>("private_base", ""))
		, configuration_(configuration)
		, logger_(
			  configuration.get<std::string>("access_log_file", "access_log.txt"),
			  configuration.get<std::string>("access_log_level", "access_log"),
			  configuration.get<std::string>("extended_log_file", "console"),
			  configuration.get<std::string>("extended_log_level", "none")){};

	server(const server&) = delete;
	server(server&&) = delete;

	server& operator=(server&&) = delete;
	server& operator=(const server&) = delete;

	virtual ~server() = default;

	enum class state
	{
		not_active,
		activating,
		active,
		deactivating
	};

	std::atomic<state>& get_status() { return state_; }

	void deactivate() { state_.store(state::deactivating); }
	bool is_active() { return state_.load() == state::active; }
	bool is_deactivating() { return state_.load() == state::deactivating; }
	bool is_activating() { return state_.load() == state::activating; }

	virtual server::state start()
	{
		state_.store(state::active);
		return state_;
	}

	virtual server::state stop()
	{
		state_.store(state::not_active);
		return state_;
	}

	const configuration& config() const { return configuration_; }

	class server_manager
	{
	private:
		std::string server_information_;
		std::string router_information_;

		std::atomic<size_t> connections_accepted_{ 0 };
		std::atomic<std::int16_t> requests_current_{ 0 };

		std::atomic<std::int16_t> connections_current_{ 0 };
		std::atomic<std::int16_t> connections_highest_{ 0 };

		std::atomic<std::int64_t> idle_since_{ 0 };

		std::atomic<std::uint16_t> responses_1xx_{ 0 };
		std::atomic<std::uint16_t> responses_2xx_{ 0 };
		std::atomic<std::uint16_t> responses_3xx_{ 0 };
		std::atomic<std::uint16_t> responses_4xx_{ 0 };
		std::atomic<std::uint16_t> responses_5xx_{ 0 };
		std::atomic<std::uint16_t> responses_tot_{ 0 };
		std::atomic<std::uint16_t> responses_diff_{ 0 };
		std::atomic<std::uint16_t> responses_health_{ 0 };
		std::atomic<std::uint16_t> rate_{ 0 };

		std::vector<std::string> access_log_;
		mutable std::mutex mutex_;
		http::server& server_;

	public:
		server_manager(http::server& server) noexcept
			: idle_since_(std::chrono::steady_clock::now().time_since_epoch().count()), server_(server)
		{
			access_log_.reserve(32);
		};

		void idle_time_reset() { idle_since_ = std::chrono::steady_clock::now().time_since_epoch().count(); }

		std::int64_t idle_time()
		{
			return (std::chrono::duration<std::int64_t, std::milli>(
						std::chrono::steady_clock::now().time_since_epoch().count() - idle_since_.load())
						.count())
				   / 1000000000;
		}

		void update_health_check_metrics() { responses_health_++; }

		void update_status_code_metrics(std::int32_t status)
		{
			assert(status >= 100);
			assert(status < 600);

			if (status >= 100 && status < 200) responses_1xx_++;
			if (status >= 200 && status < 300) responses_2xx_++;
			if (status >= 300 && status < 400) responses_3xx_++;
			if (status >= 400 && status < 500) responses_4xx_++;
			if (status >= 500 && status < 600) responses_5xx_++;

			responses_tot_++;
		}

		std::atomic<std::size_t>& connections_accepted() { return connections_accepted_; }
		std::atomic<std::int16_t>& connections_current()
		{
			if (connections_current_ > connections_highest_) connections_highest_.store(connections_current_.load());
			return connections_current_;
		}

		std::atomic<std::int16_t>& requests_current(bool internal_route = false)
		{
			if (!internal_route && requests_current_.load() > 0)
			{
				idle_since_.store(std::chrono::steady_clock::now().time_since_epoch().count());
			}

			return requests_current_;
		}

		void update_rate()
		{
			rate_.store(static_cast<std::uint16_t>(responses_tot_ - responses_diff_));
			responses_diff_.store(responses_tot_);
		}

		std::string log_access(http::session_handler& session, http::api::routing::metrics m)
		{
			std::lock_guard<std::mutex> g(mutex_);

			auto response_time = (m.processing_duration_ + m.request_latency_ + m.response_latency_);

			std::string msg = lgr::logger::format<lgr::prefix::access_log>(
				"{s} - {s} - \"{s} {s} {s}\" - {d} - {u} - {u} - {u}",
				session.request().get("X-Forwarded-For", std::string{}),
				session.request().get("X-Request-ID", std::string{}),
				http::method::to_string(session.request().method()),
				session.request().url_requested(),
				session.request().version(),
				http::status::to_int(session.response().status()),
				session.request().content_length(),
				session.response().content_length(),
				response_time);

			access_log_.emplace_back(msg);

			if (access_log_.size() >= 32) access_log_.erase(access_log_.begin());

			return msg;
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

		enum class json_status_options
		{
			full,
			config,
			server_metrics,
			router,
			access_log
		};

		json to_json(json_status_options options) const
		{
			json result_json = json::object();
			std::unique_lock<std::mutex> g(mutex_);

			switch (options)
			{
				case json_status_options::full:
				{
					g.unlock();
					result_json.update(to_json(json_status_options::config));
					result_json.update(to_json(json_status_options::server_metrics));
					result_json.update(to_json(json_status_options::router));
					result_json.update(to_json(json_status_options::access_log));
					g.lock();
					break;
				}
				case json_status_options::config:
				{
					result_json["configuration"] = server_.configuration_.to_json();
					break;
				}
				case json_status_options::server_metrics:
				{
					// result_json["metrics"]["uptime"] = "";
					// result_json["metrics"]["latency"]["min"] = 0.0;
					// result_json["metrics"]["latency"]["max"] = 0.0;
					// result_json["metrics"]["trafic"]["send"] = 0;
					// result_json["metrics"]["trafic"]["recv"] = 0;
					// result_json["metrics"]["requests"]["rate"] = 0.0;

					result_json["metrics"]["connections"]["active"] = connections_current_.load();
					result_json["metrics"]["connections"]["highest"] = connections_highest_.load();
					result_json["metrics"]["connections"]["accepted"] = connections_accepted_.load();

					result_json["metrics"]["responses"]["1xx"] = responses_1xx_.load();
					result_json["metrics"]["responses"]["2xx"] = responses_2xx_.load();
					result_json["metrics"]["responses"]["3xx"] = responses_3xx_.load();
					result_json["metrics"]["responses"]["4xx"] = responses_4xx_.load();
					result_json["metrics"]["responses"]["5xx"] = responses_5xx_.load();
					result_json["metrics"]["responses"]["total"] = responses_tot_.load();
					result_json["metrics"]["responses"]["health"] = responses_health_.load();

					result_json["metrics"]["requests"]["active"] = requests_current_.load();
					result_json["metrics"]["requests"]["total"] = responses_tot_.load();
					result_json["metrics"]["requests"]["rate"] = rate_.load();

					result_json["metrics"]["idle"]
						= (std::chrono::duration<std::int64_t, std::nano>(
							   std::chrono::steady_clock::now().time_since_epoch().count() - idle_since_.load())
							   .count())
						  / 1000000000;
					break;
				}
				case json_status_options::router:
				{
					result_json["router"] = server_.router_.to_json();
					break;
				}
				case json_status_options::access_log:
				{
					json tmp = json::array();

					for (auto access_log_entry = access_log_.cbegin(); access_log_entry != access_log_.cend();
						 ++access_log_entry)
					{
						result_json["access_log"].emplace_back(*access_log_entry);
					}
					break;
				}
			}

			return result_json;
		}

		std::string to_string() const
		{
			std::ostringstream ss;
			std::lock_guard<std::mutex> g(mutex_);

			ss << "Server Configuration:\n" << server_information_ << "\n";

			ss << "\nStatistics:\n";

			ss << "connections_accepted: " << connections_accepted_ << "\n";
			ss << "connections_highest: " << connections_highest_ << "\n";
			ss << "connections_active: " << connections_current_ << "\n";

			ss << "requests_active: " << requests_current_ << "\n";
			ss << "request/s: " << std::to_string(rate_) << "\n";

			ss << "responses_1xx: " << std::to_string(responses_1xx_) << "\n";
			ss << "responses_2xx: " << std::to_string(responses_2xx_) << "\n";
			ss << "responses_3xx: " << std::to_string(responses_3xx_) << "\n";
			ss << "responses_4xx: " << std::to_string(responses_4xx_) << "\n";
			ss << "responses_5xx: " << std::to_string(responses_5xx_) << "\n";
			ss << "responses_tot: " << std::to_string(responses_tot_) << "\n";
			ss << "health_checks: " << std::to_string(responses_health_) << "\n";

			ss << "idle_time: "
			   << (std::chrono::duration<std::int64_t, std::nano>(
					   std::chrono::steady_clock::now().time_since_epoch().count() - idle_since_.load())
					   .count())
					  / 1000000000
			   << "s\n";

			ss << "\nEndPoints:\n" << router_information_ << "\n";

			ss << "\nAccess Log:\n";

			for (auto& access_log_entry : access_log_)
				ss << access_log_entry << "\n";

			return ss.str();
		}
	};

	server_manager& manager() { return manager_; }
	lgr::logger& logger() { return logger_; }
	const lgr::logger& logger() const { return logger_; }
	http::api::router<>& router() { return router_; }

protected:
	server_manager manager_;
	http::api::router<> router_;
	http::configuration configuration_;
	lgr::logger logger_;
	std::atomic<state> state_{ state::activating };
}; // namespace basic

namespace sync
{

class server : public http::server
{
	using socket_t = SOCKET;

public:
	server(const http::configuration& configuration)
		: http::server{ configuration }
		, http_watchdog_idle_timeout_(configuration.get<std::int16_t>("http_watchdog_idle_timeout", 0))
		, http_watchdog_max_requests_concurrent_(
			  configuration.get<std::int16_t>("http_watchdog_max_requests_concurrent", 0))
		, http_use_portsharding_(configuration.get<bool>("http_use_portsharding", false))
		, http_enabled_(configuration.get<bool>("http_enabled", true))
		, http_listen_port_begin_(configuration.get<int>("http_listen_port_begin", 3000))
		, http_listen_port_end_(configuration.get<int>("http_listen_port_end", http_listen_port_begin_))
		, http_listen_port_(network::tcp::socket::invalid_socket)
		, http_listen_address_(configuration.get<std::string>("http_listen_address", "::0"), http_listen_port_begin_)
		, https_use_portsharding_(configuration.get<bool>("https_use_portsharding", false))
		, https_enabled_(configuration.get<bool>("https_enabled", false))
		, https_listen_port_begin_(configuration.get<int>(
			  "https_listen_port_begin", configuration.get<int>("http_listen_port_begin") + 2000))
		, https_listen_port_end_(configuration.get<int>("https_listen_port_end", https_listen_port_begin_))
		, https_listen_port_(network::tcp::socket::invalid_socket)
		, endpoint_https_(configuration.get<std::string>("https_listen_address", "::0"), https_listen_port_begin_)
		, connection_timeout_(configuration.get<int>("keepalive_timeout", 5))
	{
		logger_.debug("server created\n");
	}

	virtual ~server()
	{
		if (is_active() || is_activating()) this->stop();

		logger_.debug("server deleted\n");
	}

	server() = delete;
	server(server&&) = delete;
	server(const server&) = delete;

	server& operator=(const server&) = delete;
	server& operator=(const server&&) = delete;

	http::server::state start() override
	{
		http_connection_thread_ = std::thread{ [this]() { http_listener_handler(); } };
		https_connection_thread_ = std::thread{ [this]() { https_listener_handler(); } };

		// wait for listener(s to have an valid listen socket if listener is enabled)
		auto waiting = 0;
		auto timeout = 5;

		while (http_enabled_ && http_listen_port_.load() == network::tcp::socket::invalid_socket && waiting < timeout)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			waiting++;
		}

		while (https_enabled_ && https_listen_port_.load() == network::tcp::socket::invalid_socket && waiting < timeout)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
			waiting++;
		}

		if (http_enabled_ && (http_listen_port_.load() == network::tcp::socket::invalid_socket))
		{
			state_.store(http::server::state::deactivating);

			if (this->http_listen_port_end_)
				logger_.error(
					"failed to start http listener in ports: {d}-{d}\n",
					this->http_listen_port_begin_,
					this->http_listen_port_end_);
			else
				logger_.error("failed to start http on port: {d}\n", this->http_listen_port_begin_);

			return state_.load();
		}

		if (https_enabled_ && (https_listen_port_.load() == network::tcp::socket::invalid_socket))
		{
			state_.store(http::server::state::deactivating);

			if (this->http_listen_port_end_)
				logger_.error(
					"failed to start https listener in ports: {d}-{d}\n",
					this->http_listen_port_begin_,
					this->http_listen_port_end_);
			else
				logger_.error("failed to start https on port: {d}\n", this->http_listen_port_begin_);

			return state_.load();
		}

		logger_.info("routes: \n{s}", router_.to_string());

		// before takeoff checklist complete....
		state_.store(http::server::state::active);
		// takeoff....
		logger_.info("start: state set to active\n");

		return state_.load();
	}

	virtual http::server::state stop() override
	{
		http::server::state_.store(state::deactivating);
		logger_.info("stop: state set to deactivating\n");

		if (http_connection_thread_.joinable()) http_connection_thread_.join();
		if (https_connection_thread_.joinable()) https_connection_thread_.join();

		logger_.debug("stop: server joined listening threads\n");

		// Wait for all connections to close:
		while (manager_.connections_current() > 0)
		{
			logger_.debug("stop: server still hass connections\n");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		logger_.info("start: state set to not_active\n");
		state_.store(state::not_active);
		return state_;
	}

	void https_listener_handler()
	{
		logger_.debug("https_listener_handler: start\n");

		if (https_enabled_ == true)
		{
			try
			{
				network::tcp::acceptor acceptor_https{};

				acceptor_https.open(endpoint_https_.protocol());

				if (https_listen_port_begin_ == https_listen_port_end_)
					network::reuse_address(endpoint_https_.socket(), 1);
				else
					network::reuse_address(endpoint_https_.socket(), 0);

				network::ipv6only(endpoint_https_.socket(), 0);

				if ((https_use_portsharding_ == true) && (https_listen_port_begin_ != 0)
					&& (https_listen_port_begin_ == https_listen_port_end_))
					network::use_portsharding(endpoint_https_.socket(), 1);
				else
					network::use_portsharding(endpoint_https_.socket(), 0);

				network::error_code ec = network::error::success;

				auto https_listen_port_probe = https_listen_port_begin_;

				for (; https_listen_port_probe <= https_listen_port_end_; https_listen_port_probe++)
				{
					endpoint_https_.port(https_listen_port_probe);

					acceptor_https.bind(endpoint_https_, ec);

					if (ec == network::error::success)
					{
						if (!https_listen_port_probe)
						{
							network::tcp::v6 endpoint_https_tmp{ 0 };
							acceptor_https.get_local_endpoint(endpoint_https_tmp, ec);

							https_listen_port_probe = endpoint_https_tmp.port();
						}
						break;
					}
					else if (ec == network::error::address_in_use)
					{
						continue;
					}
					else
					{
						break;
					}
				}
				if (ec)
				{
					throw std::runtime_error(std::string(
						"cannot bind/listen to port in range: [ " + std::to_string(https_listen_port_begin_) + ":"
						+ std::to_string(https_listen_port_end_) + " ]"));
				}

				network::ssl::context ssl_context(network::ssl::context::tlsv12);

				ssl_context.use_certificate_chain_file(
					configuration_.get<std::string>("ssl_certificate", std::string("")).c_str());
				ssl_context.use_private_key_file(
					configuration_.get<std::string>("ssl_certificate_key", std::string("")).c_str());

				acceptor_https.listen();

				configuration_.set("https_listen_port", std::to_string(https_listen_port_probe));
				logger_.info("http listener on port: {d} started\n", https_listen_port_probe);
				https_listen_port_.store(https_listen_port_probe);

				while (is_activating() || is_active())
				{
					network::ssl::stream<network::tcp::socket> https_socket(ssl_context);
					ec = network::error::success;
					acceptor_https.accept(https_socket.lowest_layer(), ec, 5);

					if (ec == network::error::interrupted) break;
					if (ec == network::error::operation_would_block) continue;

					network::timeout(https_socket.lowest_layer(), connection_timeout_);
					https_socket.handshake(network::ssl::stream_base::server);
					network::tcp_nodelay(https_socket.lowest_layer(), 1);

					if (https_socket.lowest_layer().lowest_layer() > network::tcp::socket::invalid_socket)
					{
						auto new_connection_handler
							= std::make_shared<connection_handler<network::ssl::stream<network::tcp::socket>>>(
								*this,
								std::move(https_socket),
								connection_timeout_,
								configuration_.get<int>("gzip_min_size", 1024));

						std::thread connection_thread(
							[new_connection_handler]() { new_connection_handler->proceed(); });
						connection_thread.detach();

						++manager_.connections_accepted();
						++manager_.connections_current();
					}
				}
				logger_.info("https listener on port: {d} stopped\n", https_listen_port_probe);
			}
			catch (std::runtime_error& e)
			{
				https_listen_port_ = network::tcp::socket::invalid_socket;
				logger_.error(e.what());
			}
		}
	}

	void http_listener_handler()
	{
		logger_.debug("http_listener_handler: start\n");

		if (http_enabled_ == true)
		{
			try
			{
				network::tcp::acceptor acceptor_http{};

				acceptor_http.open(endpoint_https_.protocol());

				if (http_listen_port_begin_ == http_listen_port_end_)
					network::reuse_address(http_listen_address_.socket(), 1);
				else
					network::reuse_address(http_listen_address_.socket(), 0);

				network::ipv6only(http_listen_address_.socket(), 0);

				if ((http_use_portsharding_ == true) && (http_listen_port_begin_ != 0)
					&& (http_listen_port_begin_ == http_listen_port_end_))
					network::use_portsharding(http_listen_address_.socket(), 1);
				else
					network::use_portsharding(http_listen_address_.socket(), 0);

				network::error_code ec = network::error::success;

				auto http_listen_port_probe = http_listen_port_begin_;

				for (; http_listen_port_probe <= http_listen_port_end_; http_listen_port_probe++)
				{
					http_listen_address_.port(http_listen_port_probe);

					acceptor_http.bind(http_listen_address_, ec);

					if (ec == network::error::success)
					{
						if (!http_listen_port_probe)
						{
							network::tcp::v6 endpoint_http_tmp{ 0 };
							acceptor_http.get_local_endpoint(endpoint_http_tmp, ec);

							http_listen_port_probe = endpoint_http_tmp.port();
						}
						break;
					}
					else if (ec == network::error::address_in_use)
					{
						continue;
					}
					else
					{
						break;
					}
				}

				if (ec)
				{
					throw std::runtime_error(std::string(
						"cannot bind/listen to port in range: [ " + std::to_string(http_listen_port_begin_) + ":"
						+ std::to_string(http_listen_port_end_) + " ]"));
				}

				acceptor_http.listen();

				configuration_.set("http_listen_port", std::to_string(http_listen_port_probe));

				if (configuration_.get<std::string>("http_listen_address", "::0") == "::0")
				{
					configuration_.set(
						"http_this_server_base_url",
						"http://" + network::hostname() + ":" + configuration_.get<std::string>("http_listen_port"));
				}
				configuration_.set(
					"http_this_server_local_url",
					"http://localhost:" + configuration_.get<std::string>("http_listen_port"));

				logger_.info("http listener on port: {d} started\n", http_listen_port_probe);
				http_listen_port_.store(http_listen_port_probe);

				if (router_.server_started_method_) router_.server_started_method_();

				while (is_activating() || is_active())
				{
					network::tcp::socket http_socket{};

					acceptor_http.accept(http_socket, ec, 5);

					if (ec == network::error::interrupted)
						break;
					else if (ec == network::error::operation_would_block)
					{
						auto idle_since = this->manager_.idle_time();

						if (router_.idle_method_)
						{
							router_.idle_method_(
								http_watchdog_idle_timeout_ > 0 && idle_since > http_watchdog_idle_timeout_);
						}
						continue;
					}

					network::timeout(http_socket, connection_timeout_);
					network::tcp_nodelay(http_socket, 1);

					if (http_socket.lowest_layer() != network::tcp::socket::invalid_socket)
					{
						auto new_connection_handler = std::make_shared<connection_handler<network::tcp::socket>>(
							*this,
							std::move(http_socket),
							connection_timeout_,
							configuration_.get<int>("gzip_min_size", 1024));

						std::thread connection_thread(
							[new_connection_handler]() { new_connection_handler->proceed(); });
						connection_thread.detach();

						++manager_.connections_accepted();
						++manager_.connections_current();

						if ((router_.busy_method_) && (http_watchdog_max_requests_concurrent_ > 0)
							&& (manager_.requests_current() >= http_watchdog_max_requests_concurrent_))
						{
							router_.busy_method_();
						}
					}
				}
				logger_.info("http listener on port: {d} stopped\n", http_listen_port_probe);
			}
			catch (std::runtime_error& e)
			{
				http_listen_port_ = network::tcp::socket::invalid_socket;
				logger_.error(e.what());
			}
		}
	}

	template <class S> class connection_handler
	{
	public:
		connection_handler(http::sync::server& server, S&& client_socket, int connection_timeout, size_t gzip_min_size)
			: server_(server)
			, client_socket_(std::move(client_socket))
			, session_handler_(
				  server.configuration_.get<std::string>("server", "server_no_id"),
				  server.configuration_.get<int>("keepalive_count", 1024 * 8),
				  server.configuration_.get<int>("keepalive_max", 120),
				  server.configuration_.get<int>("gzip_min_size", 1024),
				  http::protocol::http) // for now.
			, connection_timeout_(connection_timeout)
			, gzip_min_size_(gzip_min_size)
		{
			server_.logger_.debug("connection_handler: created\n");
		}

		~connection_handler()
		{
			network::shutdown(client_socket_, network::shutdown_send);
			--server_.manager().connections_current();
			server_.logger_.debug("connection_handler: destructed \n");
		}

		connection_handler(const connection_handler&) = delete;
		connection_handler(connection_handler&&) = delete;

		connection_handler& operator=(connection_handler&) = delete;
		connection_handler& operator=(const connection_handler&&) = delete;

		void proceed()
		{
			server_.logger_.info("connection_handler: start\n");

			using data_store_buffer_t = std::array<char, 1024 * 4>;
			data_store_buffer_t buffer{};
			auto data_begin = std::begin(buffer);
			auto data_end = data_begin;
			std::chrono::steady_clock::time_point t0{};

			while (true)
			{
				assert(data_begin <= data_end);
				if (data_begin == data_end)
				{
					data_begin = std::begin(buffer);

					int ret = network::read(client_socket_, network::buffer(&*data_begin, buffer.size()));
					server_.logger_.debug("connection_handler > network::read returned: {d}\n", ret);
					if (ret <= 0)
					{
						break;
					}

					data_end = data_begin + ret;
				}

				http::session_handler::result_type parse_result;
				auto& response = session_handler_.response();
				auto& request = session_handler_.request();

				session_handler_.t0() = std::chrono::steady_clock::now();

				std::tie(parse_result, data_begin) = session_handler_.parse_request(data_begin, data_end);
				assert(data_begin <= data_end);

				if ((parse_result == http::request_parser::result_type::good) && (request.has_content_length()))
				{
					auto content_length = request.content_length();

					// Assign any data left in the buffer, possibly none:
					request.body().assign(data_begin, data_end);
					data_begin = data_end;

					while (request.body().size() < content_length)
					{
						data_begin = std::begin(buffer);
						int ret = network::read(client_socket_, network::buffer(&*data_begin, buffer.size()));
						server_.logger_.debug("connection_handler > network::read returned: {d}\n", ret);

						if (ret <= 0)
						{
							parse_result = http::request_parser::result_type::bad;
							break;
						}
						data_end = data_begin + ret;
						request.body().append(data_begin, data_end);
						data_begin = data_end;
					}

					if (request.body().length() > content_length)
					{
						parse_result = http::request_parser::result_type::bad;
					}
				}

				if ((parse_result == http::request_parser::result_type::good)
					|| (parse_result == http::request_parser::result_type::bad))
				{
					if (parse_result == http::request_parser::result_type::good)
					{
						if (server_.is_active())
						{
							session_handler_.request().set(
								"X-Forwarded-For",
								session_handler_.request().get(
									"X-Forwarded-For", network::get_client_info(client_socket_)));

							bool private_base_request = request.target().find(server_.router_.private_base_, 0) == 0;

							if (server_.logger_.current_extended_log_level() == lgr::level::debug)
							{
								server_.logger_.debug("request:\n{s}\n", http::to_dbg_string(request));
							}

							if (private_base_request == false)
							{
								++server_.manager().requests_current(private_base_request);
							}
							else
							{
								server_.manager().requests_current(private_base_request);
							}

							http::api::router<>::request_result_type routing
								= session_handler_.handle_request(server_.router_);

							session_handler_.handle_response<http::api::router<>>(routing);

							t0 = std::chrono::steady_clock::now();

							if (private_base_request == false)
							{
								--server_.manager().requests_current(private_base_request);
								server_.manager().update_status_code_metrics(
									http::status::to_int(session_handler_.response().status()));
							}
							else
							{
								server_.manager().requests_current(private_base_request);
							}

							(void)network::write(client_socket_, http::to_string(response));

							if (routing.match_result() == http::api::router_match::match_found)
							{
								auto t1 = std::chrono::duration_cast<std::chrono::milliseconds>(
											  std::chrono::steady_clock::now() - t0)
											  .count();

								routing.the_route().metric_response_latency(static_cast<std::uint64_t>(t1));

								if (private_base_request == false
									&& server_.logger_.current_access_log_level() >= lgr::level::access_log)
								{
									auto log_msg = server_.manager().log_access(
													   session_handler_, routing.the_route().route_metrics())
												   + "\n";

									server_.logger_.access_log(log_msg);
								}
							}
							else
							{
								std::string log_msg
									= server_.manager().log_access(session_handler_, http::api::routing::metrics{})
									  + "\n";

								server_.logger_.access_log(log_msg);
							}

							if (server_.logger_.current_extended_log_level() == lgr::level::debug)
							{
								server_.logger_.debug("response:\n{s}\n", http::to_dbg_string(response));
							}
						}
						else
						{
							// The server is not active; do not accept further requests.
							server_.logger_.warning(
								"server deactivated or deactivating, send server unavailable(503) reply\n");

							response.status(http::status::service_unavailable);
							response.body() = "HTTP server has been stopped";
							response.type("text");
							response.set("Connection", "close");
							response.content_length(response.body().size());
							(void)network::write(client_socket_, http::to_string(response));
						}
					}
					else
					{
						// Parse error
						response.status(http::status::bad_request);
						auto error_reason = session_handler_.parse_error_reason();
						server_.logger_.error(
							"parse error, send bad request(400) reply, reason \"{s}\"\n", error_reason);

						if (error_reason.size() > 0)
						{
							response.body() = error_reason;
							response.type("text");
							response.content_length(error_reason.size());
							(void)network::write(client_socket_, http::to_string(response));
						}
					}

					if (response.connection_keep_alive() == true)
					{
						server_.logger_.info("connection_handler: restart\n");
						session_handler_.reset();
					}
					else
					{
						break;
					}
				}
				else if (parse_result == http::request_parser::result_type::indeterminate)
				{
					continue;
				}
			}
			server_.logger_.info("connection_handler: stop\n");
		}

	protected:
		http::sync::server& server_;
		S client_socket_;
		http::session_handler session_handler_;
		int connection_timeout_;
		size_t gzip_min_size_;
		void reset_session() { session_handler_.reset(); }
	};

private:
	std::int16_t http_watchdog_idle_timeout_;
	std::int16_t http_watchdog_max_requests_concurrent_;

	bool http_use_portsharding_;
	bool http_enabled_;
	std::int32_t http_listen_port_begin_;
	std::int32_t http_listen_port_end_;
	std::atomic<network::socket_t> http_listen_port_;
	network::tcp::v6 http_listen_address_;

	bool https_use_portsharding_;
	bool https_enabled_;
	std::int32_t https_listen_port_begin_;
	std::int32_t https_listen_port_end_;
	std::atomic<network::socket_t> https_listen_port_;

	network::tcp::v6 endpoint_https_;

	int connection_timeout_;
	std::mutex configuration_mutex_;

	std::thread http_connection_thread_;
	std::thread https_connection_thread_;
};

} // namespace sync

using middleware = http::api::router<>::middleware_type;

#if !defined(HTTP_DO_NOT_USE_CURL)
namespace client
{

class session
{
public:
	session() = default;

	const http::client::curl_session& as_session() const { return session_; }

private:
	const http::client::curl_session session_;
};

template <http::method::method_t method>
http::response_message request(
	const http::client::session& session,
	const std::string& url,
	std::string& ec,
	std::initializer_list<std::string> hdrs = {},
	const std::string& body = std::string{},
	std::ostream& s = std::clog,
	bool verbose = false)
{
	http::client::curl curl{ session.as_session(), http::method::to_string(method), url, hdrs, body, verbose, s };

	return curl.call(ec); // RVO
}

template <http::method::method_t method>
http::response_message request(
	const std::string& url,
	std::string& ec,
	std::initializer_list<std::string> hdrs = {},
	const std::string& body = std::string{},
	std::ostream& s = std::clog,
	bool verbose = false)
{
	http::client::session session;
	http::client::curl curl{ session.as_session(), http::method::to_string(method), url, hdrs, body, verbose, s };

	return curl.call(ec); // RVO
}

template <http::method::method_t method>
http::response_message request(
	const http::client::session& session,
	const std::string& url,
	std::string& ec,
	std::ostream& s = std::clog,
	bool verbose = false)
{
	http::client::curl curl{ session.as_session(), http::method::to_string(method), url, {}, {}, verbose, s };

	return curl.call(ec); // RVO
}

template <http::method::method_t method>
http::response_message
request(const std::string& url, std::string& ec, std::ostream& s = std::clog, bool verbose = false)
{
	http::client::session session;
	http::client::curl curl{ session.as_session(), http::method::to_string(method), url, {}, {}, verbose, s };

	return curl.call(ec); // RVO
}

} // namespace client
#endif

} // namespace http

#include <iostream>

namespace util
{

std::string get_time_stamp()
{
	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

	std::stringstream ss;
	std::tm buf;

	(void)gmtime_r(&in_time_t, &buf);

	ss << std::put_time(&buf, "%FT%T");
	ss << "." << msec << "Z";

	return ss.str();
}

std::size_t get_thread_id() noexcept
{
	static std::atomic<std::size_t> thread_idx{ 0 };
	thread_local std::size_t id = thread_idx;
	thread_idx++;
	return id;
}

template <typename... A> std::string format(const char* format) { return std::string{ format }; } // namespace util

template <typename... A> std::string format(const char* format, const A&... args)
{
	class argument
	{
	public:
		enum type
		{
			int_,
			string_,
			double_
		};
		type value_;
		union {
			int int_value_;
			double dbl_value_;
			struct
			{
				const char* string_value_;
				size_t string_size_;
			} string_v_;
		} u;

	public:
		argument(int value) : value_(int_) { u.int_value_ = value; }
		argument(double value) : value_(double_) { u.dbl_value_ = value; }
		argument(const char* value) : value_(string_)
		{
			u.string_v_.string_value_ = value;
			u.string_v_.string_size_ = std::strlen(value);
		}
		argument(const std::string& value) : value_(string_)
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
	size_t i = 0;

	auto now = std::chrono::system_clock::now();
	auto in_time_t = std::chrono::system_clock::to_time_t(now);
	auto msec = static_cast<int>(
		std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);

	std::string buffer(size_t{ 255 }, char{ 0 });
	std::array<char, 30> tmp{ char{ 0 } };

	std::strftime(&tmp[i], sizeof(tmp), "%FT%T", std::gmtime(&in_time_t));
	
	buffer.assign(&tmp[0]);
	buffer.append(std::to_string(msec));
	buffer.append(" T");
	buffer.append(std::to_string(get_thread_id()));
	buffer.append(" info : ");

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
				if (expect == format_state::type && argument_array[argument_index].value_ == argument::type::string_)
				{
					buffer.append(
						argument_array[argument_index].u.string_v_.string_value_,
						argument_array[argument_index].u.string_v_.string_size_);

					i += argument_array[argument_index].u.string_v_.string_size_;
					argument_index++;
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
					auto s = snprintf(&tmp[0], tmp.size(), "%d", argument_array[argument_index++].value_);
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
					auto s = snprintf(&tmp[0], tmp.size(), "%x", argument_array[argument_index++].u.int_value_);
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
					auto s = snprintf(&tmp[0], tmp.size(), "%X", argument_array[argument_index++].u.int_value_);
					buffer.append(&tmp[0], s);
					expect = format_state::end;
				}
				else
				{
					buffer.append(size_t{ 1 }, *format);
				}
				break;
			case 'f':
				if (expect == format_state::type && argument_array[argument_index].value_ == argument::type::double_)
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
		throw std::runtime_error{ "wrong nr of arguments format: " + argument_index
								  + std::string("arguments: " + arguments_count) };
	}

	return buffer;
}

class prefixbuf : public std::streambuf
{
	std::string prefix_;

	std::streambuf* sbuf;
	bool need_prefix;

	int sync() { return this->sbuf->pubsync(); }
	int overflow(int c)
	{
		if (c != std::char_traits<char>::eof())
		{
			if (this->need_prefix && !this->prefix_.empty())
			{
				std::array<char, 64> prefix_buf;
				auto now = std::chrono::system_clock::now();
				auto in_time_t = std::chrono::system_clock::to_time_t(now);
				auto msec
					= std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

				std::tm buf;
				(void)gmtime_r(&in_time_t, &buf);

				auto prefix_size = snprintf(
					&prefix_buf[0],
					prefix_buf.size(),
					"%04d-%02d-%02dT%02d:%02d:%02d.%lldZ T%llu %s: ",
					buf.tm_year + 1900,
					buf.tm_mon + 1,
					buf.tm_mday,
					buf.tm_hour,
					buf.tm_min,
					buf.tm_sec,
					msec,
					get_thread_id(),
					prefix_.data());

				if (static_cast<std::streamsize>(prefix_buf.size()) != this->sbuf->sputn(&prefix_buf[0], prefix_size))
				{
					return std::char_traits<char>::eof();
				}
			}
			this->need_prefix = c == '\n';
		}
		return this->sbuf->sputc(static_cast<char>(c));
	}

public:
	prefixbuf(std::string const& prefix, std::streambuf* sbuf) : prefix_(prefix), sbuf(sbuf), need_prefix(true) {}
};

class oprefixstream : private virtual prefixbuf, public std::ostream
{
public:
	oprefixstream(std::string const& prefix, std::ostream& out_stream)
		: prefixbuf(prefix, out_stream.rdbuf())
		, std::ios(static_cast<std::streambuf*>(this))
		, std::ostream(static_cast<std::streambuf*>(this))
	{
	}
};

} // namespace util

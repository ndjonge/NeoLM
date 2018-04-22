#include <map>
#include <string>
#include <vector>

#pragma warning(disable : 4521)

//#define BOOST_SPIRIT_X3_DEBUG

#include <boost/container/stable_vector.hpp>
#include <boost/fusion/include/std_pair.hpp>
#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/core/parser.hpp>
#include <boost/spirit/home/x3/core/skip_over.hpp>
#include <boost/spirit/home/x3/support/ast/variant.hpp>
#include <boost/spirit/home/x3/support/context.hpp>
#include <boost/spirit/home/x3/support/unused.hpp>

namespace json
{
namespace x3 = boost::spirit::x3;

using string_t = std::string;
using double_t = double;
using float_t = double;
using int_t = int64_t;
using bool_t = bool;

struct null_t
{
};

class value;

using object_t = std::map<std::string, value>;
using object_member_t = object_t::value_type;
using member_pair_t = std::pair<object_t::key_type, object_t::mapped_type>;
// using array_t = std::vector<value>;
using array_t = boost::container::stable_vector<value>;

class value : public x3::variant<null_t, bool_t, string_t, int_t, double_t, object_t, array_t>
{
public:
	using value_type = value;
	using base_type::base_type;
	using base_type::operator=;

	value(null_t val = null_t{})
		: base_type(val)
	{
	}
	value(const char* val)
		: base_type(string_t(val))
	{
	}

	template <typename T>
	value(T val, typename std::enable_if<std::is_floating_point<T>::value>::type)
		: base_type(double_t{ val })
	{
	}

	template <typename T>
	value(T val, typename std::enable_if<std::is_integral<T>::value::type>)
		: base_type(int_t{ val })
	{
	}
};

namespace parser
{
	auto const append = [](auto& ctx) { x3::_val(ctx) += x3::_attr(ctx); };

	using uchar = unsigned char;

	x3::uint_parser<uchar, 16, 4, 4> const hex4 = {};

	auto push_esc = [](auto& ctx) {
		auto& utf8 = _val(ctx);
		switch (_attr(ctx))
		{
		case '"':
			utf8 += '"';
			break;
		case '\\':
			utf8 += '\\';
			break;
		case '/':
			utf8 += '/';
			break;
		case 'b':
			utf8 += '\b';
			break;
		case 'f':
			utf8 += '\f';
			break;
		case 'n':
			utf8 += '\n';
			break;
		case 'r':
			utf8 += '\r';
			break;
		case 't':
			utf8 += '\t';
			break;
		}
	};

	auto push_utf8 = [](auto& ctx) {
		typedef std::back_insert_iterator<std::string> insert_iter;
		insert_iter out_iter(x3::_val(ctx));
		boost::utf8_output_iterator<insert_iter> utf8_iter(out_iter);
		*utf8_iter++ = x3::_attr(ctx);
	};

	auto const escape = ('u' > hex4)[push_utf8] | x3::char_("\"\\/bfnrt")[push_esc];

	auto const char_esc = '\\' > escape;

	auto const double_quoted = x3::lexeme['"' > *(char_esc | (x3::char_("\x20\x21\x23-\x5b\x5d-\x7e")[append])) > '"'];
	auto const unicode_string = x3::rule<struct unicode_string_class, std::string>{ "unicode_string" } = double_quoted;

	auto const null_value = x3::lit("null") >> x3::attr(json::null_t{});

	x3::ascii::bool_type const bool_value = {};

	using value_type = x3::rule<struct value_class, json::value>;
	static value_type const value = "value";

	auto const member_pair = x3::rule<struct member_pair_class, json::member_pair_t>{ "member_pair" } = unicode_string >> ':' >> value;

	auto const object = x3::rule<struct object_class, json::object_t>{ "object" } = x3::lit('{') >> -(member_pair % ',') >> x3::lit('}');

	auto const array = x3::rule<struct array_class, json::array_t>{ "array" } = x3::lit('[') >> -(value % ',') >> x3::lit(']');

	x3::real_parser<double, x3::strict_real_policies<double>> const double_ = {};
	x3::int_parser<int64_t> const int_ = {};

	auto const value_def = null_value | bool_value | object | array | unicode_string | double_ | int_;

	BOOST_SPIRIT_DEFINE(value)

	auto const json = x3::skip(x3::ascii::space)[value];
}

struct writer : public boost::static_visitor<>
{
	typedef void result_type;
	std::stringstream& stream;

	writer(std::stringstream& s)
		: stream(s)
	{
	}

	template <typename T> void operator()(T const& value) const { stream << value; }

	void operator()(null_t const& val) const { stream << "null"; }

	void operator()(bool_t const& b) const
	{
		if (b == true)
			stream << "true";
		else
			stream << "false";
	}

	void operator()(float_t const& f) const { stream << f; }

	void operator()(std::string const& text) const
	{
		stream << '"';

		typedef ::boost::uint32_t ucs4_char;
		typedef boost::u8_to_u32_iterator<std::string::const_iterator> iter_t;

		iter_t f = text.begin();
		iter_t l = text.end();

		for (iter_t i = f; i != l; ++i)
		{
			ucs4_char c = *i;
			switch (c)
			{
			case '"':
				stream << "\\\"";
				break;
			case '\\':
				stream << "\\\\";
				break;
			case '/':
				stream << "\\/";
				break;
			case '\b':
				stream << "\\b";
				break;
			case '\f':
				stream << "\\f";
				break;
			case '\n':
				stream << "\\n";
				break;
			case '\r':
				stream << "\\r";
				break;
			case '\t':
				stream << "\\t";
				break;

			default:
				stream << boost::spirit::x3::to_utf8(c);
			}
		}

		stream << '"';
	}

	void operator()(int_t const& i) const { stream << i; }

	void operator()(array_t const& a) const
	{
		stream << '[';
		for (auto i = 0; i != a.size(); ++i)
		{
			boost::apply_visitor(*this, a[i]);

			if (i < a.size() - 1) stream << ',';
		}
		stream << ']';
	}

	void operator()(object_t const& o) const
	{
		stream << '{';
		int i = 0;

		for (auto& object : o)
		{
			stream << "\"" << object.first << "\" : ";
			boost::apply_visitor(*this, object.second);

			if (i < o.size() - 1) stream << ',';

			i++;
		}
		stream << '}';
	}
};

namespace rpc
{

class request 
{
public:
	using call_table_t = std::map<const char*, std::function<bool(json::array_t& args)>>;
	call_table_t call_table_;

	json::value& value_;

	request(call_table_t& call_table, json::value& value)
		: call_table_(call_table),
		value_(value)
	{
		json::object_t call_object = boost::get<json::object_t>(value);

		json::string_t method = boost::get<json::string_t>(call_object["method"]);
		json::int_t id = boost::get<json::int_t>(call_object["id"]);

		auto x = call_object["params"].var;

		auto y = x.which();

		json::array_t arguments = boost::get<json::array_t>(call_object["params"]);
	}


};



} // namespace rpc

} // namespace json

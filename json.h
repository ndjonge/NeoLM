#include <map>
#include <string>
#include <vector>

#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/core/parser.hpp>
#include <boost/spirit/home/x3/core/skip_over.hpp>
#include <boost/spirit/home/x3/support/ast/variant.hpp>
#include <boost/spirit/home/x3/support/context.hpp>
#include <boost/spirit/home/x3/support/unused.hpp>
#include <boost/fusion/include/std_pair.hpp>



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
using array_t = std::vector<value>;

class value : public x3::variant<null_t, bool_t, string_t, int_t, double_t, object_t, array_t>
{
public:
	using value_type = value;
	using base_type::base_type;
	using base_type::operator=;

	value(null_t val = null_t{}) : base_type(val) {}
	value(char const* val) : base_type(string_t(val)) {}

	template<typename T>
	value(T val, typename std::enable_if<std::is_floating_point<T>::value>::type) : base_type(double_t{ val }) {}

	template<typename T>
	value(T val, typename std::enable_if<std::is_integral<T>::value::type>) : base_type(int_t{ val }) {}
};

namespace parser
{
	auto const append = [](auto& ctx) { x3::_val(ctx) += x3::_attr(ctx); };

	using uchar = unsigned char;

	x3::uint_parser<uchar, 16, 4, 4> const hex4 = {};

	auto push_esc = [](auto& ctx) {
		auto& utf8 = x3::_val(ctx);
		switch (x3::_attr(ctx))
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

} // namespace json
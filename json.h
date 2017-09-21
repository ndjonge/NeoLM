#include <map>
#include <string>
#include <vector>

#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/core/parser.hpp>
#include <boost/spirit/home/x3/core/skip_over.hpp>
#include <boost/spirit/home/x3/support/ast/variant.hpp>
#include <boost/spirit/home/x3/support/context.hpp>
#include <boost/spirit/home/x3/support/unused.hpp>

namespace json
{

using string_t = std::string;
using float_t = double;
using double_t = double;
using int_t = int64_t;
using bool_t = bool;
struct null_t
{
};

class value;

using object_t = std::map<std::string, value>;
using object_member_t = object_t::value_type;
using array_t = std::vector<value>;

enum value_types
{
	string_type,
	double_type,
	int_type,
	bool_type,
	null_type,
	value_type,
	object_type,
	array_type
};

class value : public boost::spirit::x3::variant<null_t, bool_t, int_t, float_t, string_t, object_t, array_t>
{
public:
	using value_type = value;
	using base_type = base_type;
	using base_type::operator=;

	value& operator=(value& rhs) = default;

	value(null_t val = null_t())
		: base_type(val)
	{
	}

	value(char const* val)
		: base_type((string_t(val)))
	{
	}

	// floating point types will be converted to a double
	template <typename T>
	value(T val, typename boost::enable_if<boost::is_floating_point<T>>::type* = 0)
		: base_type((double_t(val)))
	{
	}

	// integral and enums are int type
	template <typename T>
	value(T val, typename boost::enable_if<boost::mpl::or_<boost::is_integral<T>, boost::is_enum<T>>>::type* = 0)
		: base_type((int_t(val)))
	{
	}

	value_types type() const;
};

namespace parser
{
	namespace x3 = boost::spirit::x3;

	struct json_class;
	using json_type = x3::rule<json_class, json::value>;

	BOOST_SPIRIT_DECLARE(json_type)

	struct value_class;
	struct object_class;
	struct member_pair_class;
	struct array_class;

	using value_type = x3::rule<value_class, json::value>;
	using object_type = x3::rule<object_class, json::object_t>;
	using member_pair_type = x3::rule<member_pair_class, json::object_member_t>;
	using array_type = x3::rule<array_class, json::array_t>;

	value_type const value = "value";
	object_type const object = "object";
	member_pair_type const member_pair = "member_pair";
	array_type const array = "array";

	struct unicode_string_class;
	using unicode_string_type = x3::rule<unicode_string_class, std::string>;
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
			utf8 += '"';
			break;
		case '/':
			utf8 += '"';
			break;
		case 'b':
			utf8 += 'b';
			break;
		case 'f':
			utf8 += 'f';
			break;
		case 'n':
			utf8 += 'n';
			break;
		case 'r':
			utf8 += 'r';
			break;
		case 't':
			utf8 += 't';
			break;
		}
	};

	auto push_utf8 = [](auto& ctx) {
		typedef std::back_insert_iterator<std::string> insert_iter;
		insert_iter out_iter(_val(ctx));
		boost::utf8_output_iterator<insert_iter> utf8_iter(out_iter);
		*utf8_iter++ = _attr(ctx);
	};

	auto const escape = ('u' > hex4)[push_utf8]
		| x3::char_("\"\\/bfnrt")[push_esc];

	auto const char_esc = '\\' > escape;


	auto const append = [](auto& ctx) { _val(ctx) += _attr(ctx); };

	auto const double_quoted
		= x3::lexeme['"' > *(char_esc | (x3::char_("\x20\x21\x23-\x5b\x5d-\x7e"))[append]) > '"'];

	auto const unicode_string_def = double_quoted;

	unicode_string_type const unicode_string = "unicode_string";

	BOOST_SPIRIT_DEFINE(unicode_string);

	auto const null_value = x3::lit("null") >> x3::attr(json::null_t{});

	x3::int_parser<int64_t> const int_ = {};

	x3::ascii::bool_type const bool_value = {};

	auto const object_def = x3::lit('{') >> -(member_pair % ',') >> x3::lit('}');

	auto const member_pair_def = unicode_string >> ':' >> value;

	auto const array_def = x3::lit('{') >> -(value % ',') >> x3::lit('}');

	auto const value_def = null_value | bool_value | unicode_string | x3::lexeme[!('+' | (-x3::lit('-') >> '0' >> x3::digit)) >> int_ >> !x3::char_(".eE")]
						   | x3::lexeme[!('+' | (-x3::lit('-') >> '0' >> x3::digit)) >> x3::double_] | object | array;

	BOOST_SPIRIT_DEFINE(value, object, member_pair, array)

	auto const json_grammar = x3::skip(x3::ascii::space)[value];
}

} // namespace json
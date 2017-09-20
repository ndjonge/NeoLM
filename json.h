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

class value; 
struct null_t
{
};

using string_t = std::string;
using float_t = double;
using double_t = double;
using int_t = int64_t;
using bool_t = bool;
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

	value(null_t val = null_t())
		: base_type(val)
	{
	}
	value(bool_t val)
		: base_type(val)
	{
	}
	value(string_t const& val)
		: base_type(val)
	{
	}
	value(char const* val)
		: base_type((string_t(val)))
	{
	}
	value(object_t const& val)
		: base_type(val)
	{
	}
	value(array_t const& val)
		: base_type(val)
	{
	}
	value(value const& rhs)
		: base_type(rhs.get_ast())
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

	auto const value_def = null_value | bool_value | detail::unicode_string | lexeme[!('+' | (-lit('-') >> '0' >> digit)) >> int_ >> !char_(".eE")]
						   | lexeme[!('+' | (-lit('-') >> '0' >> digit)) >> double_] | object | array;

	auto const null_value = lit("null") >> attr(json::null_t{});

	x3::int_parser<int64_t> const int_ = {};
	ascii::bool_type const bool_value = {};

	auto const object_def = lit('{') >> -(member_pair % ',') >> lit('}');

	auto const member_pair_def = detail::unicode_string >> ':' >> value;

	auto const array_def = lit('{') >> -(value % ',') >> lit('}');

	BOOST_SPIRIT_DEFINE(value, object, member_pair, array)

	struct unicode_string_class;
	using unicode_string_type = x3::rule<unicode_string_class, std::string>;
	unicode_string_type const unicode_string = "unicode_string";
	auto const unicode_string_def = double_quoted;

	BOOST_SPIRIT_DEFINE(unicode_string);
}

} // namespace json
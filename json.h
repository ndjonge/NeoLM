//

#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <variant>


static const char* small_JSON(void);
static const char* big_JSON(void);



namespace json
{

class value;

enum type
{
	null_type,
	string_type,
	boolean_type,
	number_type,
	array_type,
	object_type
};
using boolean = bool;
using number = double;
using string = std::string;
using array = std::vector<json::value>;
using object = std::map<json::string, json::value>;

class value
{
public:
	value() : type_(json::type::null_type) {}
	~value() {};

	value(const char* char_value) : type_(json::type::string_type), string_value(std::make_unique<json::string>(char_value)) {}
	value(const std::string& string_value) : type_(json::type::string_type), string_value(std::make_unique<std::string>(string_value))  {}

	value(bool bool_value) : type_(json::type::boolean_type), boolean_value(bool_value) {}
	value(double number_value) : type_(json::type::number_type), number_value(number_value) {}
	value(int integer_value) : type_(json::type::number_type), number_value(integer_value) {}
	value(const json::array& array_value) : type_(json::type::array_type), array_value(std::make_unique<json::array>(array_value)) {}
	value(const json::object& object_value) : type_(json::type::object_type), object_value(std::make_unique<json::object>(object_value)) {} 

	type type() const noexcept {return type_;}

	value(json::value&& source) noexcept : 
		type_(source.type_)
	{
		using std::swap;

		switch (type_)
		{
			case null_type:
				break;
			case string_type:
				swap(string_value, source.string_value);
				break;
			case boolean_type:
				boolean_value = source.boolean_value;
				break;
			case number_type:
				number_value = source.number_value;
				break;
			case array_type:
				swap(array_value, source.array_value);
				break;
			case object_type:
				swap(object_value, source.object_value);
				break;
			default:
				break;
		}

		//source.type_ = json::null_type;
	}

	value(const json::value& source) : 
		type_(source.type_)
	{
		switch (type_)
		{
			case null_type:
				break;
			case string_type:
				string_value.release();
				string_value = std::make_unique<std::string>(*source.string_value);
				break;
			case boolean_type:
				boolean_value = source.boolean_value;
				break;
			case number_type:
				number_value = source.number_value;
				break;
			case array_type:
				array_value.release();
				array_value = std::make_unique<json::array>(*source.array_value);
				break;
			case object_type:
			{
				object_value.release();
				object_value = std::make_unique<json::object>(*source.object_value);
				break;
			}
			default:
				break;
		}
	}

	bool is_null() const { return type_ == json::type::null_type; }
	bool is_string() const { return type_ == json::type::string_type; }
	bool is_bool() const { return type_ == json::type::boolean_type; }
	bool is_number() const { return type_ == json::type::number_type; }
	bool is_array() const { return type_ == json::type::array_type; }
	bool is_object() const { return type_ == json::type::object_type; }

	const json::string& as_string() const { return *string_value; }
	bool as_bool() const  { return boolean_value; }
	double as_number() const { return number_value; }
	const json::array& as_array() const { return *array_value; }
	const json::object& as_object() const { return *object_value; };

	std::size_t count() const {};

	json::value& operator = (const json::value& source)
	{
		using std::copy;

		if (source.type_ == type_)
		{
			switch (type_)
			{
				case null_type:
					break;
				case string_type:
					string_value.reset(new std::string(*source.string_value));
					break;
				case boolean_type:
					boolean_value = source.boolean_value;
					break;
				case number_type:
					number_value = source.number_value;
					break;
				case array_type:
					array_value.reset(new json::array(*source.array_value));
					break;
				case object_type:
				{
					object_value.reset(nullptr);
		
					json::object tmp(*source.object_value);
					object_value = std::make_unique<json::object>(tmp);

					break;
				}
				default:
					break;
			}
		}
		else
		{		
			switch (type_)
			{
				case string_type:
					string_value.release();
					break;
				case array_type:
					array_value.release();
					break;
				case object_type:
					object_value.release();
					break;
				default:
					break;
			}


			switch (type_)
			{
				case null_type:
					break;
				case string_type:
					string_value = std::make_unique<std::string>(*source.string_value);
					break;
				case boolean_type:
					boolean_value = source.boolean_value;
					break;
				case number_type:
					number_value = source.number_value;
					break;
				case array_type:
					array_value = std::make_unique<json::array>(*source.array_value);
					break;
				case object_type:
					object_value = std::make_unique<json::object>(*source.object_value);
					break;
				default:
					break;
			}
		}

		return *this;
	}

protected:

private:
	json::type type_;

	union {
		bool boolean_value;
		double number_value;

		std::unique_ptr<json::string> string_value;		 
		std::unique_ptr<json::array> array_value;		 
		std::unique_ptr<json::object> object_value;		 
	};
};


namespace parser
{
void skipWhiteSpace(const std::string& str, std::string::const_iterator& i);
static json::boolean charIsDigit(char c);
static json::value parseNull(const std::string& str, std::string::const_iterator& i);
static json::string parseString(const std::string& str, std::string::const_iterator& i);
static json::number parseNumber(const std::string& str, std::string::const_iterator& i);
static json::boolean parseBoolean(const std::string& str, std::string::const_iterator& i);
static json::object parseObject(const std::string& str, std::string::const_iterator& i);
static json::array parseArray(const std::string& str, std::string::const_iterator& i);
static void parseString(const std::string& str, std::string::const_iterator& i, std::string& result, bool& containsEscape);
static bool charIsDigit(char c) { return !!isdigit((unsigned int)c); }

static void expectChar(char c, char expectedChar)
{
	if (c != expectedChar)
	{
	}
}

static void expectChar(char c, bool (*fExpectedChars)(char))
{
	if (!fExpectedChars(c))
	{
	}
}

void skipWhiteSpace(const std::string& str, std::string::const_iterator& i)
{
	while (i != str.end())
	{
		switch (*i)
		{
		case 0x20:
		case 0x09:
		case 0x0A:
		case 0x0D:
			i++;
			break;
		default:
			return;
		}
	}
}

void parseString(const std::string& str, std::string::const_iterator& i, std::string& result, bool& containsEscape)
{
	result = "";
	containsEscape = false;

	i++;

	std::string::const_iterator begin = i;

	while (i != str.end() && *i != '"')
	{
		switch (*i)
		{
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
		case 0x08:
		case 0x09:
		case 0x0a:
		case 0x0b:
		case 0x0c:
		case 0x0d:
		case 0x0e:
		case 0x0f:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x1d:
		case 0x1e:
		case 0x1f:

		case '\\':
			containsEscape = true;
			result.append(begin, i);
			i++;
			switch (*i)
			{
			// Escapes: ", \, /, b, f, n, r, t, uXXXX
			case '"':
				result.append("\"", 1);
				break;
			case '\\':
				result.append("\\", 1);
				break;
			case '/':
				result.append("/", 1);
				break;
			case 'b':
				result.append("\b", 1);
				break;
			case 'f':
				result.append("\f", 1);
				break;
			case 'n':
				result.append("\n", 1);
				break;
			case 'r':
				result.append("\r", 1);
				break;
			case 't':
				result.append("\t", 1);
				break;

			case 'u':

			default:
				break;
			}
			i++;
			begin = i;
			break;
		default:
			i++;
			break;
		}
	}

	result.append(begin, i);

	expectChar(*i, '"');

	i++;
}


static json::value parseValue(const std::string& str, std::string::const_iterator& i)
{
	skipWhiteSpace(str, i);

	switch (*i)
	{
	default:
	case 'n':
		return parseNull(str, i);
	case '"':
		return parseString(str, i);
	case '{':
		return parseObject(str, i);
	case '[':
		return parseArray(str, i);
	case '-':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return parseNumber(str, i);
	case 'f':
	case 't':
		return parseBoolean(str, i);
	}
}


static json::value parse(const std::string& str)
{
	std::string::const_iterator i = str.begin();
	value rval = parser::parseValue(str, i);



	parser::skipWhiteSpace(str, i);

	return rval;
}

/*
std::tuple<lazyjson::result_type, value> parse_new(const std::string& str)
{
	std::tuple<lazyjson::result_type, object*> result(lazyjson::result_type::bad, nullptr);

	auto i = str.begin();
	value rval = parseValue(str, i);

	skipWhiteSpace(str, i);

	bool sucess = (ptrValue != nullptr) && !(i != str.end());



	return std::make_tuple(sucess ? lazyjson::result_type::good : lazyjson::result_type::bad, ptrValue);
}*/



json::string parseString(const std::string& str, std::string::const_iterator& i)
{
	json::string result;
	bool containsEscape;

	parseString(str, i, result, containsEscape);

	return result;
}

json::number parseNumber(const std::string& str, std::string::const_iterator& i)
{
	std::string::const_iterator begin = i;

	if (*i == '-') i++;

	if (*i == '0')
	{
		i++;
	}
	else
	{
		expectChar(*i, charIsDigit);
		do
		{
			i++;
		} while (i != str.end() && charIsDigit(*i));
	}

	if (*i == '.')
	{
		i++;
		expectChar(*i, charIsDigit);
		do
		{
			i++;
		} while (i != str.end() && charIsDigit(*i));
	}

	if (i != str.end() && (*i == 'e' || *i == 'E'))
	{
		i++;
		if (i != str.end() && (*i == '-' || *i == '+'))
		{
			i++;
		}
		expectChar(*i, charIsDigit);
		do
		{
			i++;
		} while (i != str.end() && charIsDigit(*i));
	}

	return number(std::stod(str.substr(begin - str.begin(), i - begin)));
}

json::value parseNull(const std::string& str, std::string::const_iterator& i)
{
	json::value rval;

	static const std::string sNull = std::string("null");

	if (sNull.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
		return rval;
	}
	else
	{
		return nullptr;
	}
}

json::boolean parseBoolean(const std::string& str, std::string::const_iterator& i)
{
	json::boolean rval(true);

	static const std::string sTrue = std::string("true");
	static const std::string sFalse = std::string("false");

	if (sTrue.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
		rval = true;
	}
	else if (sFalse.compare(str.substr(i - str.begin(), 5)) == 0)
	{
		i += 5;
		rval = false;
	}
	else
	{
		// parse error.
		//return nullptr;
	}

	return rval;
}

json::object parseObject(const std::string& str, std::string::const_iterator& i)
{
	json::object rval;

	i++;

	while (*i != '}')
	{

		std::string key;
		bool containsEscape;

		skipWhiteSpace(str, i);

		parseString(str, i, key, containsEscape);

		skipWhiteSpace(str, i);

		expectChar(*i, ':');
		i++;

		rval.insert(std::pair<std::string, json::value>(key, parseValue(str, i)));

		skipWhiteSpace(str, i);

		if (*i == ',')
		{
			i++;
		}
		else
		{
			expectChar(*i, '}');
		}
	}

	i++;

	return rval;
}

json::array parseArray(const std::string& str, std::string::const_iterator& i)
{
	array rval;
	i++;

	while (*i != ']')
	{
		rval.emplace_back(parseValue(str, i));

		skipWhiteSpace(str, i);

		if (*i == ',')
		{
			i++;
		}
		else
		{
			expectChar(*i, ']');
		}
	}

	i++;

	return rval;
}
} // namespace parser

namespace serializer
{
std::string indent(std::int16_t depth)
{
	std::string indent_str((depth ? --depth : 0)  * 2, ' ');
	
	return indent_str;
}

std::string serialize_string(const std::string &str)
{
	std::string str_out = "\"";

	std::string::const_iterator iter = str.begin();

	while (iter != str.end())
	{
		char chr = *iter;

		if (chr == '"' || chr == '\\' || chr == '/')
		{
			str_out += '\\';
			str_out += chr;
		}
		else if (chr == '\b')
		{
			str_out += "\\b";
		}
		else if (chr == '\f')
		{
			str_out += "\\f";
		}
		else if (chr == '\n')
		{
			str_out += "\\n";
		}
		else if (chr == '\r')
		{
			str_out += "\\r";
		}
		else if (chr == '\t')
		{
			str_out += "\\t";
		}
		else if (chr < ' ' || chr > 126)
		{
			str_out += "\\u";
			for (int i = 0; i < 4; i++)
			{
				int value = (chr >> 12) & 0xf;
				if (value >= 0 && value <= 9)
					str_out += (char)('0' + value);
				else if (value >= 10 && value <= 15)
					str_out += (char)('A' + (value - 10));
				chr <<= 4;
			}
		}
		else
		{
			str_out += chr;
		}

		iter++;
	}

	str_out += "\"";
	return str_out;
}


std::stringstream serialize(const json::value& v, std::int16_t indent_depth = 0)
{
	std::stringstream result;

	int16_t const indent_depth1 = indent_depth ? indent_depth + 1 : 0;
	std::string const indent_str = serializer::indent(indent_depth);
	std::string const indent_str1 = serializer::indent(indent_depth1);

	switch (v.type())
	{
	case json::null_type:
			result << "null";
			break;
	case json::string_type:
			result << serializer::serialize_string(v.as_string());

			break;

		case json::boolean_type:
			result << v.as_bool() ? "true" : "false";
			break;

		case json::number_type:
		{
			if (isinf(v.as_number()) || isnan(v.as_number()))
				result << "null";
			else
			{
				std::wstringstream ss;
				result.precision(15);
				result << v.as_number();
			}
			break;
		}

		case json::array_type:
		{
			result << (indent_depth ?  "[\n"  : "[");

			json::array::const_iterator iter = v.as_array().begin();

			while (iter != v.as_array().end())
			{
				result << (indent_depth ?   indent_str1  : "");
				result <<  serializer::serialize(*iter, indent_depth1).str();

				// Not at the end - add a separator
				if (++iter != v.as_array().end())
					result <<  (indent_depth ? ",\n" : ",");
			}
			result << (indent_depth ? "\n" + indent_str + "]" : "]");
			break;
		}

		case json::object_type:
		{
			result << (indent_depth ?  "{\n"  : "{");
			json::object::const_iterator iter = v.as_object().begin();

			while (iter != v.as_object().end())
			{
				result << (indent_depth ?   indent_str1  : "");
				result << serializer::serialize(iter->first).str();
				result << ": ";
				result << serializer::serialize(iter->second, indent_depth1).str();

				// Not at the end - add a separator
				if (++iter != v.as_object().end())
					result <<  (indent_depth ? ",\n" : ",");
			}
			result << (indent_depth ? "\n" + indent_str + "}" : "}");
			break;
		}
	}

	return result;
}

}// namespace


} // namespace json



int test_json(void)
{
	json::value value0;
	json::value value1{10.0};
	json::value value2{"aaap"};
	json::value value3{json::array{1,2,3,4,5,6,7,8}};
	json::value value4{
		json::object{
			std::make_pair<std::string, json::value>(std::string("naam1"), json::value(1)), 
			std::make_pair<std::string, json::value>(std::string("naam2"), json::value(20)),
			std::make_pair<std::string, json::value>(std::string("naam3"), json::value(22)),
			std::make_pair<std::string, json::value>(std::string("naam4"), json::value(21)),
			std::make_pair<std::string, json::value>(std::string("array1"), json::value{json::array{1,2,3,4,5,6,7,8}})
	}};


	auto s8=sizeof(json::value);

	for (auto& i : value3.as_array())
	{
		std::cout << i.as_number() << "\n";
	}
	
	for (auto& i : value4.as_object())
	{
		std::cout << i.first << "=" << i.second.as_number() << "\n";
	}

	json::value value5{value4};

	for (auto& i : value5.as_object())
	{
		std::cout << i.first << "=" << i.second.as_number() << "\n";
	}


	json::value value6{std::move(value5)};

	for (auto& i : value6.as_object())
	{
		std::cout << i.first << "=" << i.second.as_number() << "\n";
	}

	auto value7 = value4;

	json::string ss1{"test1"};
	json::string ss2{"test2"};

	std::swap(ss1, ss2);

	auto parse1 = json::parser::parse("\"a\\\"b\"");
	auto parse2 = json::parser::parse("0.3");
	auto parse3 = json::parser::parse("{ \"xxx\" : 123 }");

	std::cout << json::serializer::serialize(parse3,0).str() << "\n";

	auto parse4 = json::parser::parse(big_JSON());

	std::cout << json::serializer::serialize(parse4, 1).str() << "\n";

	//std::cout << json::serializer::serialize(value4, 1).str() << "\n";
	
	auto parse5 = json::parser::parse(json::serializer::serialize(parse4, 1).str());

	std::cout << json::serializer::serialize(parse5, 0).str() << "\n";

	auto parse6 = json::parser::parse(json::serializer::serialize(parse5, 0).str());

	

	return 0;
}


static const char* big_JSON(void)
{
	return "["
		   "  {"
		   "    \"_id\": \"54eb1e64acabd33e135930ab\","
		   "    \"index\": 0,"
		   "    \"guid\": \"617e83c5-aa74-4cda-9464-fcfbf93f68df\","
		   "    \"isActive\": false,"
		   "    \"balance\": \"$3,929.01\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 28,"
		   "    \"eyeColor\": \"blue\","
		   "    \"name\": \"Mcknight Dunn\","
		   "    \"gender\": \"male\","
		   "    \"company\": \"XIXAN\","
		   "    \"email\": \"mcknightdunn@xixan.com\","
		   "    \"phone\": \"+1 (857) 558-3874\","
		   "    \"address\": \"131 Russell Street, Cherokee, Arkansas, 4580\","
		   "    \"about\": \"Aliqua dolore elit sit pariatur consequat dolor ipsum anim. Aliquip non eiusmod enim aliquip dolore commodo aliquip pariatur velit. Eu deserunt in elit mollit magna ad et dolor qui eiusmod ex. Aliqua qui nisi culpa occaecat proident excepteur. Ipsum velit aliquip Lorem est qui quis. Elit "
		   "aute voluptate cupidatat amet laboris ut proident tempor.\\r\\n\","
		   "    \"registered\": \"2014-11-13T05:07:04 -01:00\","
		   "    \"latitude\": -46.005856,"
		   "    \"longitude\": 86.504883,"
		   "    \"tags\": ["
		   "      \"eiusmod\","
		   "      \"deserunt\","
		   "      \"cupidatat\","
		   "      \"ea\","
		   "      \"ex\","
		   "      \"sunt\","
		   "      \"magna\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Sybil Rosales\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Roseann Glover\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"Cohen Little\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Mcknight Dunn! You have 7 unread messages.\","
		   "    \"favoriteFruit\": \"apple\""
		   "  },"
		   "  {"
		   "    \"_id\": \"54eb1e6496e96cacbef517cc\","
		   "    \"index\": 1,"
		   "    \"guid\": \"8ee6a321-235e-486f-9cec-f2db6b1d3aa0\","
		   "    \"isActive\": true,"
		   "    \"balance\": \"$1,300.06\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 32,"
		   "    \"eyeColor\": \"brown\","
		   "    \"name\": \"Janell Joyner\","
		   "    \"gender\": \"female\","
		   "    \"company\": \"ISOPOP\","
		   "    \"email\": \"janelljoyner@isopop.com\","
		   "    \"phone\": \"+1 (972) 600-2270\","
		   "    \"address\": \"754 Aster Court, Leming, Oregon, 3719\","
		   "    \"about\": \"Culpa nostrud deserunt amet elit sint sint sint adipisicing. Minim ut nostrud nostrud aliquip sint ex veniam anim Lorem cupidatat. Enim officia esse qui pariatur ad consequat Lorem incididunt. Velit commodo laboris culpa non dolore id labore cupidatat cupidatat enim proident. Aliqua "
		   "incididunt dolor ullamco duis esse nisi cupidatat ullamco labore dolor irure. Non eiusmod aute exercitation eu dolor consequat id.\\r\\n\","
		   "    \"registered\": \"2014-02-09T02:17:08 -01:00\","
		   "    \"latitude\": -67.981132,"
		   "    \"longitude\": -52.093976,"
		   "    \"tags\": ["
		   "      \"quis\","
		   "      \"qui\","
		   "      \"qui\","
		   "      \"laboris\","
		   "      \"culpa\","
		   "      \"laborum\","
		   "      \"amet\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Wagner Carson\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Deanne Mayo\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"Bishop Sharpe\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Janell Joyner! You have 7 unread messages.\","
		   "    \"favoriteFruit\": \"strawberry\""
		   "  },"
		   "  {"
		   "    \"_id\": \"54eb1e646253b1ecbc758503\","
		   "    \"index\": 2,"
		   "    \"guid\": \"370a2f60-dfce-47ab-aa29-f3d0f1bb6a01\","
		   "    \"isActive\": true,"
		   "    \"balance\": \"$3,862.54\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 40,"
		   "    \"eyeColor\": \"brown\","
		   "    \"name\": \"Dillard Bates\","
		   "    \"gender\": \"male\","
		   "    \"company\": \"MIXERS\","
		   "    \"email\": \"dillardbates@mixers.com\","
		   "    \"phone\": \"+1 (917) 432-3490\","
		   "    \"address\": \"847 Autumn Avenue, Mammoth, Pennsylvania, 516\","
		   "    \"about\": \"Quis irure nostrud ullamco nostrud et cupidatat veniam fugiat. Deserunt laboris dolor velit eiusmod. Aliqua sit in duis fugiat nulla sint eu aute et mollit ullamco quis cillum. Mollit commodo occaecat eu qui fugiat fugiat occaecat sit adipisicing.\\r\\n\","
		   "    \"registered\": \"2014-01-06T17:39:10 -01:00\","
		   "    \"latitude\": -78.973537,"
		   "    \"longitude\": -65.061173,"
		   "    \"tags\": ["
		   "      \"dolore\","
		   "      \"amet\","
		   "      \"minim\","
		   "      \"sunt\","
		   "      \"exercitation\","
		   "      \"amet\","
		   "      \"sit\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Orr Goodman\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Elvia Gonzalez\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"Harriet Trujillo\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Dillard Bates! You have 6 unread messages.\","
		   "    \"favoriteFruit\": \"apple\""
		   "  },"
		   "  {"
		   "    \"_id\": \"54eb1e645b48b851f11ec1af\","
		   "    \"index\": 3,"
		   "    \"guid\": \"60ebafa9-cbd4-4bcd-897c-9ead8b26d107\","
		   "    \"isActive\": false,"
		   "    \"balance\": \"$3,098.66\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 35,"
		   "    \"eyeColor\": \"brown\","
		   "    \"name\": \"Cantu Clemons\","
		   "    \"gender\": \"male\","
		   "    \"company\": \"SKINSERVE\","
		   "    \"email\": \"cantuclemons@skinserve.com\","
		   "    \"phone\": \"+1 (840) 429-3360\","
		   "    \"address\": \"311 Haring Street, Greer, Connecticut, 6229\","
		   "    \"about\": \"Dolor ut excepteur deserunt minim minim nisi ex elit duis cupidatat proident. Esse exercitation ea aliquip ipsum eu quis labore velit officia ad et est non adipisicing. Nulla ad consectetur aute incididunt enim sint mollit deserunt mollit eiusmod. Sint anim nisi et velit ullamco est irure "
		   "ut. Sunt cillum elit pariatur consectetur.\\r\\n\","
		   "    \"registered\": \"2014-04-29T20:41:41 -02:00\","
		   "    \"latitude\": -36.361223,"
		   "    \"longitude\": 114.415184,"
		   "    \"tags\": ["
		   "      \"cupidatat\","
		   "      \"adipisicing\","
		   "      \"tempor\","
		   "      \"amet\","
		   "      \"tempor\","
		   "      \"irure\","
		   "      \"fugiat\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Pittman Lott\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Jane Woodard\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"Larsen Tucker\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Cantu Clemons! You have 4 unread messages.\","
		   "    \"favoriteFruit\": \"banana\""
		   "  },"
		   "  {"
		   "    \"_id\": \"54eb1e646c5405c98321e89f\","
		   "    \"index\": 4,"
		   "    \"guid\": \"0d5a15d5-7b45-46fc-92ab-9ed9217ca3d1\","
		   "    \"isActive\": true,"
		   "    \"balance\": \"$3,537.92\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 39,"
		   "    \"eyeColor\": \"green\","
		   "    \"name\": \"Lynn Gaines\","
		   "    \"gender\": \"female\","
		   "    \"company\": \"REALMO\","
		   "    \"email\": \"lynngaines@realmo.com\","
		   "    \"phone\": \"+1 (890) 563-3329\","
		   "    \"address\": \"504 Sumner Place, Berlin, Maine, 7999\","
		   "    \"about\": \"Et occaecat quis eu tempor reprehenderit anim eiusmod voluptate laborum eu. Qui deserunt velit qui in aliquip nisi irure non nisi duis non proident. Qui adipisicing elit sint sint ad exercitation deserunt in laborum reprehenderit do voluptate ut.\\r\\n\","
		   "    \"registered\": \"2014-05-18T23:21:08 -02:00\","
		   "    \"latitude\": 29.25769,"
		   "    \"longitude\": 45.335646,"
		   "    \"tags\": ["
		   "      \"nostrud\","
		   "      \"nulla\","
		   "      \"do\","
		   "      \"ea\","
		   "      \"proident\","
		   "      \"magna\","
		   "      \"aliqua\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Angelia Joyce\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Lyons Rosario\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"Christa Torres\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Lynn Gaines! You have 6 unread messages.\","
		   "    \"favoriteFruit\": \"apple\""
		   "  },"
		   "  {"
		   "    \"_id\": \"54eb1e64f1e5557bbc2737f1\","
		   "    \"index\": 5,"
		   "    \"guid\": \"c9efbfeb-68aa-4ec7-8b91-7fac25c74f8f\","
		   "    \"isActive\": true,"
		   "    \"balance\": \"$3,991.01\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 39,"
		   "    \"eyeColor\": \"blue\","
		   "    \"name\": \"Olive Stein\","
		   "    \"gender\": \"female\","
		   "    \"company\": \"ENERSOL\","
		   "    \"email\": \"olivestein@enersol.com\","
		   "    \"phone\": \"+1 (982) 470-3210\","
		   "    \"address\": \"948 Schroeders Avenue, Orick, Utah, 3872\","
		   "    \"about\": \"Nostrud exercitation mollit cillum aute. Amet exercitation adipisicing dolore voluptate nisi pariatur dolor sunt dolor nisi aute dolore officia aliqua. Exercitation dolor esse proident est mollit. Adipisicing magna eiusmod Lorem velit voluptate officia. Ut aliquip cupidatat tempor esse "
		   "amet voluptate aute ad incididunt veniam mollit qui. Eu eu deserunt cupidatat cupidatat aute et do laboris officia cupidatat est nisi deserunt. Quis ad culpa velit sint labore ad sint nostrud ut veniam reprehenderit pariatur.\\r\\n\","
		   "    \"registered\": \"2014-05-21T01:28:24 -02:00\","
		   "    \"latitude\": 15.235882,"
		   "    \"longitude\": -122.289687,"
		   "    \"tags\": ["
		   "      \"dolor\","
		   "      \"ad\","
		   "      \"consequat\","
		   "      \"mollit\","
		   "      \"dolore\","
		   "      \"aliquip\","
		   "      \"eu\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Tanner Mercado\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Dionne Duke\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"Latisha Neal\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Olive Stein! You have 3 unread messages.\","
		   "    \"favoriteFruit\": \"banana\""
		   "  },"
		   "  {"
		   "    \"_id\": \"54eb1e64193013a491ddd233\","
		   "    \"index\": 6,"
		   "    \"guid\": \"bc989f8c-6409-4214-bd44-2d7a22cfafa0\","
		   "    \"isActive\": true,"
		   "    \"balance\": \"$1,289.89\","
		   "    \"picture\": \"http://placehold.it/32x32\","
		   "    \"age\": 24,"
		   "    \"eyeColor\": \"brown\","
		   "    \"name\": \"Shirley Beck\","
		   "    \"gender\": \"female\","
		   "    \"company\": \"UNIWORLD\","
		   "    \"email\": \"shirleybeck@uniworld.com\","
		   "    \"phone\": \"+1 (871) 479-2897\","
		   "    \"address\": \"385 Rost Place, Colton, Colorado, 5876\","
		   "    \"about\": \"Id ea laboris magna officia in enim. Sit qui non commodo ea amet excepteur. Aliquip deserunt velit exercitation aute eu et sint. Enim ut sunt cupidatat in et proident mollit proident. Minim incididunt aliqua anim aute consectetur do consequat mollit officia commodo. Officia labore "
		   "pariatur adipisicing proident exercitation nostrud qui labore ipsum mollit officia dolore voluptate. Incididunt id dolore nostrud ex deserunt.\\r\\n\","
		   "    \"registered\": \"2014-03-23T13:05:57 -01:00\","
		   "    \"latitude\": -5.904744,"
		   "    \"longitude\": 19.535182,"
		   "    \"tags\": ["
		   "      \"excepteur\","
		   "      \"Lorem\","
		   "      \"cillum\","
		   "      \"deserunt\","
		   "      \"enim\","
		   "      \"quis\","
		   "      \"eiusmod\""
		   "    ],"
		   "    \"friends\": ["
		   "      {"
		   "        \"id\": 0,"
		   "        \"name\": \"Marilyn Short\""
		   "      },"
		   "      {"
		   "        \"id\": 1,"
		   "        \"name\": \"Janis Mccoy\""
		   "      },"
		   "      {"
		   "        \"id\": 2,"
		   "        \"name\": \"May Ward\""
		   "      }"
		   "    ],"
		   "    \"greeting\": \"Hello, Shirley Beck! You have 4 unread messages.\","
		   "    \"favoriteFruit\": \"strawberry\""
		   "  }"
		   "]";
}

static const char* small_JSON(void)
{
	return "{"
		   "\"key1\":"
		   "[\"aap\",\"noot\",null],"
		   "\"key2\":"
		   "\"string value\","
		   "\"key3\":"
		   "{"
		   "},"
		   "\"key4\":"
		   "{\"key4a\":"
		   "["
		   "]"
		   "}"
		   "}";
}


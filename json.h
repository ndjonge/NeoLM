//

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <tuple>

namespace json
{

// Forward declarations:
class value;
class null_t;
class string_t;
class number_t;
class boolean_t;
class object_t;
class array_t;


enum result_type
{
	bad,
	good,
	indeterminate
};

class value
{
public:
	virtual bool isNull(void) const { return false; }
	virtual bool isString(void) const { return false; }
	virtual bool isNumber(void) const { return false; }
	virtual bool isBoolean(void) const { return false; }
	virtual bool isObject(void) const { return false; }
	virtual bool isArray(void) const { return false; }

	virtual void toStream(std::ostream& ost) const = 0;

private:
};

class null_t : public value
{
public:
	bool isNull(void) const { return true; }
	virtual void toStream(std::ostream& ost) const { ost << "null"; }
};

class string_t : public value
{
public:
	string_t(const std::string& str)
		: _string(str)
	{
	}
	bool isString(void) const { return true; }
	const std::string& getString(void) const { return _string; }
	virtual void toStream(std::ostream& ost) const { ost << "\"" << _string << "\""; }

private:
	std::string _string;
};

class number_t : public value
{
public:
	number_t(const std::string& value)
		: _value(value)
	{
	}
	bool isNumber(void) const { return true; }
	virtual void toStream(std::ostream& ost) const { ost << _value; }

private:
	std::string _value;
};

class boolean_t : public value
{
public:
	boolean_t(bool value)
		: _value(value)
	{
	}
	bool isBoolean(void) const { return true; }
	virtual void toStream(std::ostream& ost) const { ost << _value; }

private:
	bool _value;
};

class object_t : public value
{
public:
	bool isObject(void) const { return true; }
	void add(const std::string& key, value* value) { _map[key] = value; }
	size_t size(void) const { return _map.size(); }
	value* operator[](const std::string& key)
	{
		std::map<std::string, value*>::const_iterator i = _map.find(key);
		if (i != _map.end())
		{
			return i->second;
		}
		else
		{
			// TODO: Should class Ptr have a NULL?
			static value* ptrNull = nullptr;
			return ptrNull;
		}
	}
	virtual void toStream(std::ostream& ost) const
	{
		ost << "{";
		std::map<std::string, value*>::const_iterator i = _map.begin();
		if (i != _map.end())
		{
			ost << '"' << i->first << '"' << ':';
			i->second->toStream(ost);
			i++;
		}
		while (i != _map.end())
		{
			ost << ',' << '"' << i->first << '"' << ':';
			i->second->toStream(ost);
			i++;
		}
		ost << "}";
	}

private:
	std::map<std::string, value*> _map;
};

class array_t : public value
{
public:
	bool isArray(void) const { return true; }
	void add(value* value) { _array.push_back(value); }
	size_t size(void) const { return _array.size(); }
	value* const& operator[](size_t idx)
	{
		if (idx < _array.size())
		{
			return _array[idx];
		}
		else
		{
			// TODO: Should class Ptr have a NULL?
			static value* ptrNull = nullptr;
			return ptrNull;
		}
	}

	virtual void toStream(std::ostream& ost) const
	{
		ost << "[";
		std::vector<value*>::const_iterator i = _array.begin();
		if (i != _array.end())
		{
			(*i++)->toStream(ost);
		}
		while (i != _array.end())
		{
			ost << ',';
			(*i++)->toStream(ost);
		}
		ost << "]";
	}

private:
	std::vector<value*> _array;
};

namespace parser
{
void skipWhiteSpace(const std::string& str, std::string::const_iterator& i);
static bool charIsDigit(char c);
static null_t* parseNull(const std::string& str, std::string::const_iterator& i);
static string_t* parseString(const std::string& str, std::string::const_iterator& i);
static number_t* parseNumber(const std::string& str, std::string::const_iterator& i);
static boolean_t* parseBoolean(const std::string& str, std::string::const_iterator& i);
static object_t* parseObject(const std::string& str, std::string::const_iterator& i);
static array_t* parseArray(const std::string& str, std::string::const_iterator& i);
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


static value* parseValue(const std::string& str, std::string::const_iterator& i)
{
	skipWhiteSpace(str, i);

	switch (*i)
	{
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


static value* parse(const std::string& str)
{
	std::string::const_iterator i = str.begin();

	value* ptrValue = parser::parseValue(str, i);

	parser::skipWhiteSpace(str, i);

	return ptrValue;
}

std::tuple<json::result_type, value*> parse_new(const std::string& str)
{
	std::tuple<json::result_type, object_t*> result(json::result_type::bad, nullptr);

	auto i = str.begin();
	json::value* ptrValue = parseValue(str, i);

	skipWhiteSpace(str, i);

	bool sucess = (ptrValue != nullptr) && !(i != str.end());



	return std::make_tuple(sucess ? json::result_type::good : json::result_type::bad, ptrValue);
}



string_t* parseString(const std::string& str, std::string::const_iterator& i)
{
	std::string result;
	bool containsEscape;

	parseString(str, i, result, containsEscape);

#ifdef USE_SGM_PTR
	return myScope.newObject<string_t>(result);
#else
	return new string_t(result);
#endif
}

number_t* parseNumber(const std::string& str, std::string::const_iterator& i)
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

#ifdef USE_SGM_PTR
	return myScope.newObject<number_t>(str.substr(begin - str.begin(), i - begin));
#else
	return new number_t(str.substr(begin - str.begin(), i - begin));
#endif
}

null_t* parseNull(const std::string& str, std::string::const_iterator& i)
{
	static const std::string sNull = std::string("null");

	if (sNull.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
#ifdef USE_SGM_PTR
		return myScope.newObject<null_t>();
#else
		return new null_t;
#endif
	}
	else
	{
	}
}

boolean_t* parseBoolean(const std::string& str, std::string::const_iterator& i)
{
	static const std::string sTrue = std::string("true");
	static const std::string sFalse = std::string("false");

	if (sTrue.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
#ifdef USE_SGM_PTR
		return myScope.newObject<boolean_t>(true);
#else
		return new boolean_t(true);
#endif
	}
	else if (sFalse.compare(str.substr(i - str.begin(), 5)) == 0)
	{
		i += 5;
#ifdef USE_SGM_PTR
		return myScope.newObject<boolean_t>(false);
#else
		return new boolean_t(false);
#endif
	}
	else
	{
	}
}

object_t* parseObject(const std::string& str, std::string::const_iterator& i)
{

	i++;

#ifdef USE_SGM_PTR
	object_t* ptrObject = myScope.newObject<object_t>();
#else
	object_t* ptrObject = new object_t;
#endif

	while (*i != '}')
	{

		std::string key;
		bool containsEscape;

		skipWhiteSpace(str, i);

		parseString(str, i, key, containsEscape);

		skipWhiteSpace(str, i);

		expectChar(*i, ':');
		i++;

		ptrObject->add(key, parseValue(str, i));

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

	return ptrObject;
}

array_t* parseArray(const std::string& str, std::string::const_iterator& i)
{

	i++;

	array_t* ptrArray = new array_t;

	while (*i != ']')
	{

		ptrArray->add(parseValue(str, i));

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

	return ptrArray;
}

}; //namespace parser

std::ostream& operator<<(std::ostream& ost, value* const& v)
{
#ifdef USE_SGM_PTR
	if (v.isNull())
#else
	if (!v)
#endif
	{
		ost << "nullPtr<T>";
	}
	else
	{
		v->toStream(ost);
	}
	return ost;
}

std::ostream& operator<<(std::ostream& ost, null_t* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, string_t* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, number_t* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, boolean_t* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, object_t* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, array_t* const& v)
{
	ost << (value*)v;
	return ost;
}

}; //namepace json

static const char* small_JSON(void);
static const char* big_JSON(void);

int mainjson(void)
{
	using namespace json;
	value* ptrValue;

	std::tuple<json::result_type, json::value*> result = json::parser::parse_new("\"a\\\"b\"");

	ptrValue = json::parser::parse("\"a\\\"b\"");

	std::cout << ptrValue << std::endl;

	//	value* pv = value::parse( "12345.6E0123 3" );
	//	std::cout << "pv: " << pv << std::endl;
	//

	// return 0;

	json::parser::parse("0.3");
	json::parser::parse("{ \"xxx\" : 123 }");

	ptrValue = json::parser::parse(small_JSON());

	std::cout << "JSON doc    : " << small_JSON() << std::endl;
	std::cout << "Parsed value: " << ptrValue << std::endl;

	// dynamicCast to subclass is allowed
	object_t* ptrObject;

#ifdef USE_SGM_PTR
	ptrValue.dynamicCast(ptrObject);
	ptrObject = ptrValue.dynamicCast<object_t>();
#else
	ptrObject = dynamic_cast<object_t*>(ptrValue);
#endif

	std::cout << "ptrValue : " << ptrValue << std::endl;
	std::cout << "ptrObject: " << ptrObject << std::endl;

	value* ptrKey1Value = (*ptrObject)["key1"];

	std::cout << "value of key1: " << ptrKey1Value << std::endl;

#ifdef USE_SGM_PTR
	array_t* ptrArray = ptrKey1Value.dynamicCast<array_t>();
#else
	array_t* ptrArray = dynamic_cast<array_t*>(ptrKey1Value);
#endif

	value* ptrArrayElement = (*ptrArray)[0];

	std::cout << "value of element 0 in key1 array: " << ptrArrayElement << std::endl;
	std::cout << "value of element 1 in key1 array: " << (*ptrArray)[1] << std::endl;
	std::cout << "value of element 2 in key1 array: " << (*ptrArray)[2] << std::endl;

	std::cout << "key1: " << (*dynamic_cast<object_t*>(ptrValue))["key1"] << std::endl;

	///////////

	// dynamicCast to non-subclass is not allowed and results in NULL

#ifdef USE_SGM_PTR
	ptrValue.dynamicCast(ptrArray);
	ASSERT(ptrArray.isNull());
#else
	ptrArray = dynamic_cast<array_t*>(ptrValue);
#endif

#ifdef USE_SGM_PTR
	ptrArray = myScope.newObject<array_t>();
#else
	ptrArray = new array_t;
#endif

	// Conversion from subclass to superclass is supported:
#ifdef USE_SGM_PTR
	value* px = myScope.newObject<string_t>(std::string("teun"));
#else
	value* px = new string_t(std::string("teun"));
#endif

	ptrArray->add(px);

#ifdef USE_SGM_PTR
	ptrArray->add(myScope.newObject<string_t>(std::string("vuur")));
	ptrArray->add(myScope.newObject<string_t>(std::string("gijs")));
#else
	ptrArray->add(new string_t(std::string("vuur")));
	ptrArray->add(new string_t(std::string("gijs")));
#endif

	std::cout << "ptrArray: " << ptrArray << std::endl;

#ifdef USE_SGM_PTR
	Sgm::Allocater::deleteObject(ptrArray);
#else
	delete ptrArray;
#endif

	for (size_t i = 0; i < 10; i++)
	{
		ptrValue = json::parser::parse(big_JSON());

		std::cout << "big_JSON: " << ptrValue << std::endl;
	}
	fprintf(stderr, "done\n");

	return 0;
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

#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <variant>

namespace lazyjson
{

// Forward declarations:
class value;
class null;
class string;
class number;
class boolean;
class object;
class array;


enum result_type
{
	bad,
	good,
	indeterminate
};

class value
{
public:
	virtual bool is_null(void) const { return false; }
	virtual bool is_string(void) const { return false; }
	virtual bool is_number(void) const { return false; }
	virtual bool is_boolean(void) const { return false; }
	virtual bool is_object(void) const { return false; }
	virtual bool is_array(void) const { return false; }

	virtual void to_stream(std::ostream& ost) const = 0;

private:
};

class null : public value
{
public:
	bool is_null(void) const { return true; }
	virtual void to_stream(std::ostream& ost) const { ost << "null"; }
};

class string : public value
{
public:
	string(const std::string& str)
		: _string(str)
	{
	}
	bool is_string(void) const { return true; }
	const std::string& get_string(void) const { return _string; }
	virtual void to_stream(std::ostream& ost) const { ost << "\"" << _string << "\""; }

private:
	std::string _string;
};

class number : public value
{
public:
	number(const std::string& value)
		: _value(value)
	{
	}
	bool is_number(void) const { return true; }
	virtual void to_stream(std::ostream& ost) const { ost << _value; }

private:
	std::string _value;
};

class boolean : public value
{
public:
	boolean(bool value)
		: _value(value)
	{
	}
	bool is_boolean(void) const { return true; }
	virtual void to_stream(std::ostream& ost) const { ost << _value; }

private:
	bool _value;
};

class object : public value
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

	virtual void to_stream(std::ostream& ost) const
	{
		ost << "{";
		std::map<std::string, value*>::const_iterator i = _map.begin();
		if (i != _map.end())
		{
			ost << '"' << i->first << '"' << ':';
			i->second->to_stream(ost);
			i++;
		}
		while (i != _map.end())
		{
			ost << ',' << '"' << i->first << '"' << ':';
			i->second->to_stream(ost);
			i++;
		}
		ost << "}";
	}

private:
	std::map<std::string, value*> _map;
};

class array : public value
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

	virtual void to_stream(std::ostream& ost) const
	{
		ost << "[";
		std::vector<value*>::const_iterator i = _array.begin();
		if (i != _array.end())
		{
			(*i++)->to_stream(ost);
		}
		while (i != _array.end())
		{
			ost << ',';
			(*i++)->to_stream(ost);
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
static null* parseNull(const std::string& str, std::string::const_iterator& i);
static string* parseString(const std::string& str, std::string::const_iterator& i);
static number* parseNumber(const std::string& str, std::string::const_iterator& i);
static boolean* parseBoolean(const std::string& str, std::string::const_iterator& i);
static object* parseObject(const std::string& str, std::string::const_iterator& i);
static array* parseArray(const std::string& str, std::string::const_iterator& i);
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


static value* parse(const std::string& str)
{
	std::string::const_iterator i = str.begin();

	value* ptrValue = parser::parseValue(str, i);

	parser::skipWhiteSpace(str, i);

	return ptrValue;
}

std::tuple<lazyjson::result_type, value*> parse_new(const std::string& str)
{
	std::tuple<lazyjson::result_type, object*> result(lazyjson::result_type::bad, nullptr);

	auto i = str.begin();
	lazyjson::value* ptrValue = parseValue(str, i);

	skipWhiteSpace(str, i);

	bool sucess = (ptrValue != nullptr) && !(i != str.end());



	return std::make_tuple(sucess ? lazyjson::result_type::good : lazyjson::result_type::bad, ptrValue);
}



string* parseString(const std::string& str, std::string::const_iterator& i)
{
	std::string result;
	bool containsEscape;

	parseString(str, i, result, containsEscape);

#ifdef USE_SGM_PTR
	return myScope.newObject<string>(result);
#else
	return new string(result);
#endif
}

number* parseNumber(const std::string& str, std::string::const_iterator& i)
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
	return myScope.newObject<number>(str.substr(begin - str.begin(), i - begin));
#else
	return new number(str.substr(begin - str.begin(), i - begin));
#endif
}

null* parseNull(const std::string& str, std::string::const_iterator& i)
{
	static const std::string sNull = std::string("null");

	if (sNull.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
#ifdef USE_SGM_PTR
		return myScope.newObject<null>();
#else
		return new null;
#endif
	}
	else
	{
		return nullptr;
	}
}

boolean* parseBoolean(const std::string& str, std::string::const_iterator& i)
{
	static const std::string sTrue = std::string("true");
	static const std::string sFalse = std::string("false");

	if (sTrue.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
#ifdef USE_SGM_PTR
		return myScope.newObject<boolean>(true);
#else
		return new boolean(true);
#endif
	}
	else if (sFalse.compare(str.substr(i - str.begin(), 5)) == 0)
	{
		i += 5;
#ifdef USE_SGM_PTR
		return myScope.newObject<boolean>(false);
#else
		return new boolean(false);
#endif
	}
	else
	{
		return nullptr;
	}
}

object* parseObject(const std::string& str, std::string::const_iterator& i)
{

	i++;

#ifdef USE_SGM_PTR
	object* ptrObject = myScope.newObject<object>();
#else
	object* ptrObject = new object;
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

array* parseArray(const std::string& str, std::string::const_iterator& i)
{

	i++;

	array* ptrArray = new array;

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
		v->to_stream(ost);
	}
	return ost;
}

std::ostream& operator<<(std::ostream& ost, null* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, string* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, number* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, boolean* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, object* const& v)
{
	ost << (value*)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, array* const& v)
{
	ost << (value*)v;
	return ost;
}

}; //namepace json
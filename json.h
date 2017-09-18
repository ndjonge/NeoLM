#include <map>
#include <string>
#include <vector>

#include <iostream>

// Forward declarations:
/*
class value;
class null;
class string;
class number;
class boolean;
class object;
class array;*/

namespace json
{

template<typename T>
class value
{
public:
	value parse(const std::string& str);

	virtual bool is_null(void) const { return false; }
	virtual bool is_string(void) const { return false; }
	virtual bool is_number(void) const { return false; }
	virtual bool is_boolean(void) const { return false; }
	virtual bool is_object(void) const { return false; }
	virtual bool is_array(void) const { return false; }

	virtual void to_stream(std::ostream& ost) const {};

protected:
	template <typename T>
	value<T> parse(const std::string& str)
	{
		std::string::const_iterator i = str.begin();

		value ptrValue = parse_value(str, i);

		skipWhiteSpace(str, i);

		expect_char(*i, '\0');

		return ptrValue;
	}

	template <typename T>
	value<T> parse_value(const std::string& str, std::string::const_iterator& i)
	{
		skipWhiteSpace(str, i);

		switch (*i)
		{
		case 'n':
			return parse_null(str, i);
		case '"':
			return parse_string(str, i);
		case '{':
			return parse_object(str, i);
		case '[':
			return parse_array(str, i);
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
			return parse_number(str, i);
		case 'f':
		case 't':
			return parse_boolean(str, i);
		default:
			ASSERT(0); // Parse error
		}
	}

	void skip_white_space(const std::string& str, std::string::const_iterator& i)
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

	static bool charIsDigit(char c)
	{
		return !!isdigit((unsigned int)c);
	}

	static void expect_char(char c, char expectedChar)
	{
		if (c != expectedChar)
		{
			//	ASSERT(0); // TODO parse error
		}
	}

	static void expect_char(char c, bool(*fExpectedChars)(char))
	{
		if (!fExpectedChars(c))
		{
			//ASSERT(0); // TODO parse error
		}
	}





	static T parse_value(const std::string& str, std::string::const_iterator& i);
/*	static null parse_null(const std::string& str, std::string::const_iterator& i);
	static string parse_string(const std::string& str, std::string::const_iterator& i);
	static number parse_number(const std::string& str, std::string::const_iterator& i);
	static boolean parse_boolean(const std::string& str, std::string::const_iterator& i);
	static object parse_object(const std::string& str, std::string::const_iterator& i);
	static array parse_array(const std::string& str, std::string::const_iterator& i);*/

	static void parse_string(const std::string& str, std::string::const_iterator& i, std::string& result, bool& containsEscape)
	{
		result = "";
		containsEscape = false;

		ASSERT(*i == '"');
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
				ASSERT(0); // TODO parse error
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
					ASSERT(0); // TODO parse \uXXXX sequence

				default:
					ASSERT(0); // TODO parse error
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

		expect_char(*i, '"');

		i++;
	}

};

class null : public value<null>
{
public:
	bool is_null(void) const { return true; }
	virtual void to_stream(std::ostream& ost) const { ost << "null"; }
};

class string : public value<string>
{
public:
	string(const std::string& str)
		: string_(str)
	{
	}

	bool is_string(void) const { return true; }

	const std::string& getString(void) const { return string_; }
	
	virtual void to_stream(std::ostream& ost) const { ost << "\"" << string_ << "\""; }

private:
	std::string string_;
};

class number : public value<number>
{
public:
	number(const std::string& value)
		: value_(value)
	{
	}
	bool is_number(void) const { return true; }
	virtual void to_stream(std::ostream& ost) const { ost << value_; }

private:
	std::string value_;
};

class boolean : public value<boolean>
{
public:
	boolean(bool value)
		: value_(value)
	{
	}
	bool is_boolean(void) const { return true; }
	virtual void to_stream(std::ostream& ost) const { ost << value_; }

private:
	bool value_;
};

class object : public value<object>
{
public:
	bool is_object(void) const { return true; }

	void add(const std::string& key, const value& value)
	{
		map_[key] = value;
	}
	
	size_t size(void) const { return map_.size(); }

	const value operator[](const std::string& key)
	{
		std::map<std::string, value>::const_iterator i = map_.find(key);
		if (i != map_.end())
		{
			return i->second;
		}
		else
		{
			// TODO: Should class Ptr have a NULL?
			static value null = value();
			return null;
		}
	}
	
	virtual void to_stream(std::ostream& ost) const
	{
		ost << "{";
		std::map<std::string, value>::const_iterator i = map_.begin();
		if (i != map_.end())
		{
			ost << '"' << i->first << '"' << ':';
			i->second.to_stream(ost);
			i++;
		}
		while (i != map_.end())
		{
			ost << ',' << '"' << i->first << '"' << ':';
			i->second.to_stream(ost);
			i++;
		}
		ost << "}";
	}

private:
	std::map<std::string, value> map_;
};

class array : public value<array>
{
public:
	bool is_array(void) const { return true; }
	void add(const value& value)
	{
		array_.push_back(value);
	}
	size_t size(void) const { return array_.size(); }
	const value& operator[](size_t idx)
	{
		if (idx < array_.size())
		{
			return array_[idx];
		}
		else
		{
			// TODO: Should class Ptr have a NULL?
			static value ptrNull = value();
			return ptrNull;
		}
	}

	virtual void to_stream(std::ostream& ost) const
	{
		ost << "[";
		std::vector<value>::const_iterator i = array_.begin();
		if (i != array_.end())
		{
			(*i++).to_stream(ost);
		}
		while (i != array_.end())
		{
			ost << ',';
			(*i++).to_stream(ost);
		}
		ost << "]";
	}

private:
	std::vector<value> array_;
};

template<class T>
std::ostream& operator<<(std::ostream& ost, const value<T>& v)
{
	if (v.is_null())
	{
		ost << "nullPtr<T>";
	}
	else
	{
		v.to_stream(ost);
	}
	return ost;
}

/*
std::ostream& operator<<(std::ostream& ost, const null& v)
{
	ost << (value)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, const string& v)
{
	ost << (value)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, const number& v)
{
	ost << (value)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, const boolean& v)
{
	ost << (value)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, const object& v)
{
	ost << (value)v;
	return ost;
}

std::ostream& operator<<(std::ostream& ost, const array& v)
{
	ost << (value)v;
	return ost;
}
*/



pString value::parse_string(const std::string& str, std::string::const_iterator& i)
{
	std::string result;
	bool containsEscape;

	parse_string(str, i, result, containsEscape);

	return new string(result);
}

pNumber Value::parse_number(const std::string& str, std::string::const_iterator& i)
{
	ASSERT(charIsDigit(*i) || *i == '-');

	std::string::const_iterator begin = i;

	if (*i == '-') i++;

	if (*i == '0')
	{
		i++;
	}
	else
	{
		expect_char(*i, charIsDigit);
		do
		{
			i++;
		} while (charIsDigit(*i));
	}

	if (*i == '.')
	{
		i++;
		expect_char(*i, charIsDigit);
		do
		{
			i++;
		} while (char_is_digit(*i));
	}

	if (*i == 'e' || *i == 'E')
	{
		i++;
		if (*i == '-' || *i == '+')
		{
			i++;
		}
		expect_char(*i, char_is_digit);
		do
		{
			i++;
		} while (char_is_digit(*i));
	}

	return new number(str.substr(begin - str.begin(), i - begin));
}

null value::parse_null(const std::string& str, std::string::const_iterator& i)
{
	static const std::string sNull = std::string("null");

	//ASSERT(*i == 'n');

	if (sNull.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;
		return null();
	}
	else
	{
		//ASSERT(0); // TODO parse error
	}
}

boolean value::parse_boolean(const std::string& str, std::string::const_iterator& i)
{
	static const std::string sTrue = std::string("true");
	static const std::string sFalse = std::string("false");

	//ASSERT(*i == 'f' || *i == 't');

	if (sTrue.compare(str.substr(i - str.begin(), 4)) == 0)
	{
		i += 4;

		return new boolean(true);
	}
	else if (sFalse.compare(str.substr(i - str.begin(), 5)) == 0)
	{
		i += 5;
		return new boolean(false);
	}
	else
	{
		//ASSERT(0); // TODO parse error
	}
}

object value::parse_object(const std::string& str, std::string::const_iterator& i)
{
	//ASSERT(*i == '{');
	i++;

	pObject ptrObject = new object;

	while (*i != '}')
	{

		std::string key;
		bool containsEscape;

		skip_white_space(str, i);

		parse_string(str, i, key, containsEscape);

		skip_white_space(str, i);

		expect_char(*i, ':');
		i++;

		ptrObject->add(key, parse_value(myScope, str, i));

		skipWhiteSpace(str, i);

		if (*i == ',')
		{
			i++;
		}
		else
		{
			expect_char(*i, '}');
		}
	}

	i++;

	return ptrObject;
}

array value::parse_array(const std::string& str, std::string::const_iterator& i)
{
	i++;

	array ptrArray = new array;

	while (*i != ']')
	{

		ptrArray->add(parse_value(str, i));

		skip_white_space(str, i);

		if (*i == ',')
		{
			i++;
		}
		else
		{
			expect_char(*i, ']');
		}
	}

	ASSERT(*i == ']');
	i++;

	return ptrArray;
}

} //namespace json
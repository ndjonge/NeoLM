#include <string>
#include <vector>
#include <map>

namespace json
{

class value
{

	union
	{
		bool bool_value;
		int number_value;
		std::string string_value;
		std::vector<value> array_value;
		std::map<std::string, value> object_value;
	}
}

} // namespace json
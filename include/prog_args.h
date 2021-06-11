#pragma once
#include <functional>
#include <iostream>

#ifdef LOCAL_TESTING
inline void print_version(int x){std::cout << "version: v:" << x << "\n"; };
#endif

namespace cli
{

class argument
{
public:

	using fun_type = std::function<void(const std::string& value)>;
	enum class type
	{
		flag,
		hidden_flag,
		value,
		hidden_value,
		usage,
		version,
		illegal 
	};

	type type_;
	std::string usage_;
	std::string value_;
	std::string def_val_;
	fun_type fun_;

	argument() : type_(argument::type::illegal), usage_("illegal argument"){};

	argument(type type, const std::string& usage = "", const std::string& def = "", fun_type f = fun_type())
		: type_(type)
		, usage_(usage)
		, value_(def)
		, def_val_(def)
		, fun_(f){};
};

using arg_list = std::map<std::string, argument>;

class arguments
{
private:
	int argc;
	const char** argv;
	arg_list cmd_opts;

public:
	arguments(int _argc, const char** _argv, const std::initializer_list<arg_list::value_type>& args)
		: argc(_argc), argv(_argv), cmd_opts()
	{
		for (auto& i : args)
		{
			cmd_opts[i.first] = i.second;
		}
		argument usage(argument::type::usage, "show Usage");
		argument version(argument::type::version, "show program version");
		cmd_opts["?"] = usage;
		cmd_opts["V"] = version;
	}

	bool process_args()
	{
		for (int i = 1; i < argc; ++i)
		{
			auto const& a = cmd_opts.find(std::string(&argv[i][1]));
			if (a == cmd_opts.end())
			{
				std::cerr << " illegal argument " << i << " :" << argv[i] << std::endl;
				usage(argv[0]);
				return (false);
			}
			else if ((a->second.type_ == argument::type::value) && (i < argc) && (argv[i + 1][0] != '-'))
			{
				a->second.value_ = std::string(argv[i + 1]);
				++i;
			}
			else if (a->second.type_ == argument::type::flag)
			{
				a->second.value_ = "true";
			}
			else if ((a->second.type_ == argument::type::hidden_value) && (i < argc) && (argv[i + 1][0] != '-'))
			{
				a->second.value_ = std::string(argv[i + 1]);
				++i;
			}
			else if (a->second.type_ == argument::type::hidden_flag)
			{
				a->second.value_ = "true";
			}
			else if (a->second.type_ == argument::type::usage)
			{
				usage(argv[0]);
				exit(0);
			}
			else if (a->second.type_ == argument::type::version)
			{
				prversion(argv[0]);
				return false;
			}
			else
			{
				return false;
			}
		}
		return true;
	}

	std::string get_val(const std::string& key)
	{
		const auto a = cmd_opts.find(key);
		if (a == cmd_opts.end())
		{
			std::cerr << " illegal argument '" << key << "'" << std::endl;
			return std::string("");
		}
		else
		{
			return a->second.value_;
		}
	}
	bool flag_set(const std::string& key)
	{
		const auto a = cmd_opts.find(key);
		if (a == cmd_opts.end())
		{
			return false;
		}
		else
		{
			return a->second.value_ == "true";
		}
	}
	void usage(const std::string& progname)
	{
		std::cerr << "Usage: " << progname << std::endl;
		for (auto a : cmd_opts)
		{
			if ((a.second.type_ != argument::type::hidden_flag) && (a.second.type_ != argument::type::hidden_value))
			{
				std::cerr << "  -" << a.first << "\r\t\t\t" << a.second.usage_;
				std::cerr << std::endl;
			}
		}

		exit(0);
	}
	void prversion(const std::string&) { ::print_version(1); exit(0);}
};
} // namespace program_arguments

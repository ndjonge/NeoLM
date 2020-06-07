//
//
// something to handle program args in a (not so) fancy C++ way.
//
//
#include <functional>
#include <iostream>

namespace prog_args
{

using fun_arg_t = std::function<void(const std::string& arg_val)>;

typedef enum
{
	flag, // flag true or false
	arg_val, // some string
	fun_argx, // some function with arg
	usage,
	version,
	illegal // illegal
} arg_t;

class argopt
{
public:
	arg_t type;
	std::string usage;
	std::string arg_val;
	std::string def_val;
	fun_arg_t fun;

	argopt() : type(arg_t::illegal), usage("illegal argument"), arg_val(""), def_val(""), fun(){};

	argopt(arg_t _type, const std::string& _usage = "", const std::string& _def = "", fun_arg_t _f = fun_arg_t())
		: type(_type)
		, usage(_usage)
		, arg_val(_def)
		, // set default
		def_val(_def)
		, fun(_f){};
};

using arg_list_t = std::map<std::string, argopt>;

//	static bool process_args( arguments_t& args, int argc, const char **argv );

class arguments_t
{
private:
	int argc;
	const char** argv;
	arg_list_t cmd_opts;

public:
	arguments_t(int _argc, const char** _argv, const std::initializer_list<arg_list_t::value_type>& args)
		: argc(_argc), argv(_argv), cmd_opts()
	{
		for (auto& i : args)
		{
			cmd_opts[i.first] = i.second;
		}
		argopt usage(arg_t::usage, "show Usage");
		argopt version(arg_t::version, "show program version");
		cmd_opts["h"] = usage;
		cmd_opts["H"] = usage;
		cmd_opts["?"] = usage;
		cmd_opts["v"] = version;
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
			else if ((a->second.type == arg_t::arg_val) && (i < argc) && (argv[i + 1][0] != '-'))
			{
				a->second.arg_val = std::string(argv[i + 1]);
				++i;
			}
			else if ((a->second.type == arg_t::fun_argx) && (i < argc) && (argv[i + 1][0] != '-'))
			{
				a->second.arg_val = std::string(argv[i + 1]);
				a->second.fun(a->second.arg_val);
				++i;
			}
			else if (a->second.type == arg_t::flag)
			{
				a->second.arg_val = "true";
			}
			else if (a->second.type == arg_t::usage)
			{
				usage(argv[0]);
			}
#ifdef INFOR
			else if (a->second.type == arg_t::version)
			{
				prversion(argv[0]);
				return false;
			}
#endif
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
			return a->second.arg_val;
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
			return a->second.arg_val == "true";
		}
	}
	void usage(const std::string& progname)
	{
		std::cerr << "Usage for " << progname << std::endl;
		for (auto a : cmd_opts)
		{
			std::cerr << "  -" << a.first << " " << a.second.usage;
			if (a.second.type != arg_t::usage)
			{
				std::cerr << " (default: '" << a.second.def_val << "' )";
			}
			std::cerr << std::endl;
		}
	}
	//void prversion(const std::string& progname) { ::print_version(1); }
};
} // namespace prog_args

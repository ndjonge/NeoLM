
#include <iomanip>
#include <iostream>
#include <string>

#include "nlohmann_json.hpp"
using json = nlohmann::json;

#include "prog_args.h"

#ifdef IPV6STRICT
#undef IPV6STRICT
#endif

#define CURL_STATICLIB
#include <curl/curl.h>

using bs8 = int64_t;

#include "baanlogin.h"
#include "ipclib.h"
#include "samlloginclient.h"
#include "stream.h"
#include "system.h"
#include "version.h"

#ifdef _WIN32
#include "sspisecurity.h"
#include <direct.h>
#include <process.h>
#define HOST_NAME_MAX 256
#endif

#include "pm_curl.h"
#include "safe_ptr.h"

#include "http_basic.h"
#include "http_network.h"

//
// Naming used:
//	- cldls/CLDLS etc: 	Cloud Landscaper
//		the Landscaper
//	- cpm/CPM etc:		Cloud Platform Manager
//

namespace cloud
{

namespace platform
{

namespace landscaper
{
//
// handles the fetching of the configuration for the Could Platform Manager
// by connecting to the Could Landscaper
//

//
// Cloud Platform Manager requests the configuration from the from Cloud Landscaper
//
class configuration_api : public cURL_basic
{
public:
	configuration_api(const std::string& cldls_host, int port, const std::string& path_to_config, const std::string& configuration, int verbose = 0, std::ostream* err = &std::cerr)
		: cURL_basic(err, verbose)
	{

		std::stringstream url;

		url << "http://" << cldls_host << ":" << port << path_to_config << "/" << configuration;
		*err << url.str() << std::endl;

		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
		curl_easy_setopt(hnd, CURLOPT_URL, url.str().c_str());

		set_headers({ "cache-control: no-cache", "accept-encoding: gzip, deflate", "Cache-Control: no-cache", "Accept: application/json", "User-Agent: Platform Manager/1.0" });
	}

	// places the config in argument json_config
	bool exec(json& json_config)
	{
		CURLcode ret = curl_easy_perform(hnd);
		if (ret != CURLE_OK)
		{
			json_config["error"] = { { "error", "some cURL error" }, { "code", ret }, { "curlerror", curl_easy_strerror(ret) } };
			return false;
		}
		else
		{
			// std::cout << buffer.str();
			try
			{
				buffer >> json_config;
			}
			catch (json::exception& e)
			{
				(*err) << "some exception" << e.what() << "\n"
					   << "received :" << buffer.str() << std::endl;
			}

			return true;
		}
	}

	~configuration_api() = default;
};

class registry_api : public cURL_basic
{
	std::string data_str; // must remain alive during cURL transfer
public:
	registry_api(const std::string& cldls_host, int port, const std::string& path_to_register, const std::string& id, const json& data, int verbose = 0, std::ostream* err = &std::cerr)
		: cURL_basic(err, verbose)
		, data_str()
	{

		std::stringstream url;

		url << "http://" << cldls_host << ":" << port << path_to_register << "/" << id;
		*err << url.str() << std::endl;

		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_easy_setopt(hnd, CURLOPT_URL, url.str().c_str());

		set_headers({ "cache-control: no-cache", "accept-encoding: gzip, deflate", "Cache-Control: no-cache", "Accept: application/json", "User-Agent: Platform Manager/1.0", "Connection: close" });

		data_str = data.dump();
		std::cout << data.dump() << std::endl;

		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data_str.c_str());
	}

	// places the config in argument json_register
	bool exec(json& json_register)
	{
		CURLcode ret = curl_easy_perform(hnd);
		if (ret != CURLE_OK)
		{
			json_register["error"] = { { "error", "some cURL error" }, { "code", ret }, { "curlerror", curl_easy_strerror(ret) } };
			return false;
		}
		else
		{
			// std::cout << buffer.str();
			buffer >> json_register;
			return true;
		}
	}

	~registry_api() = default;
};
} // namespace landscaper

class applications;
class application;
class workspace;
class implementer;
class workspaces;

void to_json(json& j, const applications& value);
void from_json(const json& j, applications& value);

void to_json(json& j, const application* value);
void from_json(const json& j, application* value);

void to_json(json& j, const workspace* value);
void from_json(const json& j, workspace* value);

void to_json(json& j, const implementer* v);
void from_json(const json& j, implementer* v);

void to_json(json& j, const workspaces&);
void from_json(const json& j, workspaces&);

class cURL_implementer : cURL_basic
{
private:
	std::string type;
	std::string method;

public:
	cURL_implementer(int port, const std::string& _type, const std::string& _method)
		: cURL_basic(&std::cerr, 1)
		, type(_type)
		, method(_method)
	{
		std::stringstream url;
		url << "http://localhost:" << port << method;

		std::cerr << url.str() << std::endl;

		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, type.c_str());
		curl_easy_setopt(hnd, CURLOPT_URL, url.str().c_str());
		// local calls should be snappy.
		curl_easy_setopt(hnd, CURLOPT_CONNECTTIMEOUT_MS, 100L);
		curl_easy_setopt(hnd, CURLOPT_TIMEOUT_MS, 100L);
		set_headers({ "cache-control: no-cache", "accept-encoding: gzip, deflate", "Cache-Control: no-cache", "Accept: application/json", "User-Agent: Platform Manager/1.0", "Connection: close" });
	}
	bool exec(json& ret_val)
	{
		CURLcode ret = curl_easy_perform(hnd);
		if (ret != CURLE_OK)
		{
			ret_val["error"] = { { "error", "some cURL error" }, { "code", ret }, { "curlerror", curl_easy_strerror(ret) } };
			return false;
		}
		else
		{
			(*err) << buffer.str();
			try
			{
				buffer >> ret_val;
			}
			catch (json::exception& e)
			{
				(*err) << "cURL("
					   << ": some exception" << e.what() << "\n"
					   << "received :" << buffer.str() << std::endl;
			}

			return true;
		}
	}
	cURL_implementer() = default;
};

class implementer_send_shutdown : public cURL_basic
{
public:
	implementer_send_shutdown(int port)
		: cURL_basic(&std::cerr, 1)
	{
		std::stringstream url;
		url << "http://localhost:" << port << "/implementer/shutdown";
		std::cerr << url.str() << std::endl;

		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "DELETE");
		curl_easy_setopt(hnd, CURLOPT_URL, url.str().c_str());
		// local calls should be snappy.
		curl_easy_setopt(hnd, CURLOPT_CONNECTTIMEOUT_MS, 100L);
		curl_easy_setopt(hnd, CURLOPT_TIMEOUT_MS, 100L);
		set_headers({ "cache-control: no-cache", "accept-encoding: gzip, deflate", "Cache-Control: no-cache", "Accept: application/json", "User-Agent: Platform Manager/1.0", "Connection: close" });
	}

	// places the config in argument json_config
	bool exec(json& json_config)
	{
		CURLcode ret = curl_easy_perform(hnd);
		if (ret != CURLE_OK)
		{
			json_config["error"] = { { "error", "some cURL error" }, { "code", ret }, { "curlerror", curl_easy_strerror(ret) } };
			return false;
		}
		else
		{
			(*err) << buffer.str();
			try
			{
				buffer >> json_config;
			}
			catch (json::exception& e)
			{
				(*err) << "Implementer_send_and_shutdown: some exception" << e.what() << "\n"
					   << "received :" << buffer.str() << std::endl;
			}

			return true;
		}
	}
	~implementer_send_shutdown() = default;
};

class implementer_request_status : public cURL_basic
{
public:
	implementer_request_status(int port)
		: cURL_basic(&std::cerr, 1)
	{
		std::stringstream url;
		url << "http://localhost:" << port << "/implementer/status";
		std::cerr << url.str() << std::endl;

		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
		curl_easy_setopt(hnd, CURLOPT_URL, url.str().c_str());
		// local calls should be snappy.
		curl_easy_setopt(hnd, CURLOPT_CONNECTTIMEOUT_MS, 100L);
		curl_easy_setopt(hnd, CURLOPT_TIMEOUT_MS, 100L);
		set_headers({ "cache-control: no-cache", "accept-encoding: gzip, deflate", "Cache-Control: no-cache", "Accept: application/json", "User-Agent: Platform Manager/1.0", "Connection: close" });
	}

	// places the config in argument json_config
	bool exec(json& json_config)
	{
		CURLcode ret = curl_easy_perform(hnd);
		if (ret != CURLE_OK)
		{
			json_config["error"] = { { "error", "some cURL error" }, { "code", ret }, { "curlerror", curl_easy_strerror(ret) } };
			return false;
		}
		else
		{
			(*err) << buffer.str();
			try
			{
				buffer >> json_config;
			}
			catch (json::exception& e)
			{
				(*err) << "implementer_request_status: some exception" << e.what() << "\n"
					   << "received :" << buffer.str() << std::endl;
			}

			return true;
		}
	}
	~implementer_request_status() = default;
};

class implementer_instance
{
private:
	int pid;
	int port;
	int run_status;
	std::string error_code;
	json instance_status;

public:
	implementer_instance()
		: pid(0)
		, port(0)
		, run_status(0)
		, error_code("")
		, instance_status(){};

	~implementer_instance()
	{
		std::stringstream str;
		str << "implementer_instance pid " << pid << " at port " << port << " removed" << std::endl;
		std::cerr << str.str();
	};

	implementer_instance(int _pid, int _port)
		: pid(_pid)
		, port(_port)
		, run_status(1)
		, error_code("")
	{
		std::stringstream str;
		std::cerr << "implementer_instance pid " << pid << " at port " << port << std::endl;
		std::cerr << str.str();
	}
	int get_pid() { return pid; };
	int get_port() { return port; };
	std::string get_status()
	{
		switch (run_status)
		{
		case 0:
			return "initial";
		case 1:
			return "running";
		case 2:
			return "deleted";
		case 3:
			return "error";
		default:
			return "not yet";
		}
	}
	void set_status(int s) { run_status = s; };
	void set_error(const std::string& err)
	{
		std::cerr << "implementer_instance pid " << pid << " at port " << port << " error " << err << std::endl;
		error_code = err;
	};
	std::string get_error(void) { return error_code; };
	json status_report(void)
	{
		json a = json::object();
		a["pid"] = pid;
		a["run_status"] = get_status();
		if (run_status == 3)
		{
			a["error"] = get_error();
		}
		a["port"] = port;
		a["instance_status"] = instance_status;
		return a;
	}
	json get_instance_status(void) { return instance_status; }
	void set_instance_status(const json& j) { instance_status = j; }
};

//
// Implementor
//
class implementer
{
protected:
	std::string implementerName;
	std::string implementerType;
	int count; // TODO: make thread safe
	int current_count; // TODO: make thread safe
	bool valid;

	sf::safe_ptr<std::map<const int, implementer_instance*>> instances;
	sf::safe_ptr<std::vector<std::string>> errors;

public:
	implementer(const std::string& type)
		: implementerName()
		, implementerType(type)
		, count()
		, current_count()
		, valid(false)
		, instances()
		, errors(){};

	virtual ~implementer(){
		// TODO: how to clean up?
	};

	void cleanup(){};

	void add_instance(const json& j)
	{
		int pid;
		int port;
		j.at("pid").get_to(pid);
		j.at("port").get_to(port);

		(*instances)[pid] = new implementer_instance(pid, port);
	}

	void remove_instance(const json& j)
	{
		int pid;
		int port;
		j.at("pid").get_to(pid);
		j.at("port").get_to(port);
		auto instance = instances->find(pid);

		if (instance != instances->end())
		{
			cURL_implementer shutdown(port, "DELETE", "/implementer/shutdown"); // TODO?!
			json ret;
			shutdown.exec(ret);
			instance->second->set_status(2);
			--count; // TODO
		}
	}

public:
	void error_start(const json& j)
	{
		int pid;
		std::string error_code;
		j.at("pid").get_to(pid);
		j.at("error").get_to(error_code);

		json ret;
		if (instances->find(pid) != instances->end())
		{
			(*instances)[pid]->set_status(3);
			(*instances)[pid]->set_error(error_code);
		}
	}

public:
	virtual bool is_valid(void) const { return valid; };
	void set_valid(bool v) { valid = v; };
	int get_count(void) { return count; };
	void set_count(int c) { count = c; };

	const std::string& get_implementerType(void) { return implementerType; }
	const std::string& get_implementerName(void) { return implementerName; }
	void set_implementerName(const std::string& _n) { implementerName = _n; }

	virtual void from_json(const json& j)
	{
		j.at("implementerType").get_to(implementerType);
		j.at("count").get_to(count);
	}
	virtual void to_json_instances(json& j) const
	{
		int nr_instances = 0;
		j = { { "implementerName", implementerName }, { "implementerType", implementerType } };
		j["instances"] = json::array();

		for (auto ii = instances->begin(); ii != instances->end(); ++ii)
		{
			j["instances"].push_back(ii->second->status_report());
			++nr_instances;
		}
		j["count"] = nr_instances;

		j["errors"] = json::array();
		for (auto ee = errors->begin(); ee != errors->end(); ++ee)
		{
			json a = json::object();
			a["code"] = (*ee);
			j["errors"].push_back(a);
		}
	}

	virtual void to_json(json& j) const
	{
		to_json_instances(j);
		j["details"] = json::object();
	}

	virtual void do_start(int, const std::string& ws, const std::string& t, const std::string& n) = 0;
	virtual void set_tenant(const std::string&) = 0;

	void start(int count, std::string& workspace) { do_start(count, workspace, implementerType, implementerName); };

	void remove_instance(implementer_instance* ii)
	{
		cURL_implementer send_shutdown(ii->get_port(), "DELETE", "/implementer/shutdown"); // TODO?!
		json ret;
		send_shutdown.exec(ret); // do a cURL call to delete an implementer
		ii->set_status(2); // mark as deleted
	}

	void request_instance_status(implementer_instance* ii) const
	{
		cURL_implementer get_status(ii->get_port(), "GET", "/implementer/status");
		json ret;
		get_status.exec(ret);
		ii->set_instance_status(ret);
	}

	// remove count instances
	//
	void remove_instances(int count)
	{
		for (auto in = instances->begin(); in != instances->end(); ++in)
		{
			if (count == 0) break; // done
			if (in->second->get_status() == "deleted") continue; // gone already
			remove_instance(in->second);
			--count;
		}
	}

	// remove all
	void remove_all_instances(void)
	{
		for (auto in = instances->begin(); in != instances->end(); ++in)
		{
			remove_instance(in->second);
		}
	}

	void cleanup_all_instances(void)
	{
		for (auto in = instances->begin(); in != instances->end(); ++in)
		{
			implementer_instance* ii = in->second;
			instances->erase(in->first);
			delete ii;
		}
	}

	void remove_deleted_instances(void)
	{
		for (auto in = instances->begin(); in != instances->end(); ++in)
		{
			if (in->second->get_status() == "deleted")
			{
				instances->erase(in->first);
				delete in->second;
			}
		}
	}

	void request_status(void) const
	{
		for (auto in = instances->begin(); in != instances->end(); ++in)
		{
			request_instance_status(in->second);
		}
	}
};

void to_json(json& j, const implementer* v) { v->to_json(j); }

void from_json(const json& j, implementer* v)
{
	v->from_json(j);
	std::cout << "from_json ->>>  reading " << j << " into implementer" << std::endl;
}

// {
//     "implementerType" : "bshell",
//     "count" : 5,
//     "details" : {
// 	"BSE" 		: "%REMOTE_BSE%",
// 	"bse_user"	: "sysadmin",
// 	"os_user" 	: "%OS_USER",
// 	"os_password" 	: "%OS_PASSWORD%",
// 	"program"	: "bshell",
// 	"debug"		: 0,
// 	"startobject"	: "odbtst003"
//     }
// }

class bse_connector
{
};

std::mutex _baanlogin;

class bshell_implementer_instance
{
private:
	std::string bse_user_name;
	std::string os_user_name;
	std::string password;

	std::string hostname;
	std::string remote_bse;
	std::string tenant;

	std::string remote_prog;

	int protocol;
	int blogin_port;

	CryptMethod crypt_method;

	network::socket_t fd;

	int debug;

	std::vector<std::string> arguments;

	std::string ret_code;

	std::stringstream trace;

	ssize_t fd_w_string(const std::string& s)
	{
		trace << " -> '" << s << "'" << std::endl;

		return network::write(fd, s);
	}

	ssize_t fd_r_string(std::string& s)
	{
		char buf[1024];
		ssize_t ret = network::read(fd, network::buffer{ buf, sizeof(buf) });
		s = buf;
		return ret;
	}

	int attach_process(const std::vector<std::string>& argv, std::string& error)
	{

		std::string ipc_boot(remote_bse + "/bin/ipc_boot");
		std::vector<std::string> ipc_boot_args;

		ipc_boot_args.push_back(remote_prog);
		ipc_boot_args.push_back(std::to_string(getpid()));
		ipc_boot_args.push_back(std::to_string(553)); // remote conn + sock + no ruser + client

		char errorStringBuf[BL_MAX_STR_LEN];
		BLReturnCode returnCode = BL_NOERROR;

		fd = BaanLogin(hostname.c_str(), blogin_port, os_user_name.c_str(), password.c_str(), crypt_method, BL_LOGIN_USER, ipc_boot.c_str(), &returnCode, errorStringBuf, sizeof(errorStringBuf));

		if (fd == -1)
		{
			trace << "BaanLogin returned: " << returnCode << " " << errorStringBuf << std::endl;
			error = std::string(errorStringBuf);
			return -1;
		}
		else
		{
			trace << "BaanLogin has a socket!!! " << std::endl;
		}
		if (tenant.empty())
		{
			ipc_boot_args.push_back(remote_bse); // remote bse
		}
		else
		{
			ipc_boot_args.push_back(remote_bse + std::string("/tenants/") + tenant); // remote bse
		}
		ipc_boot_args.push_back(bse_user_name); // bse_user
		ipc_boot_args.push_back(os_user_name); // logon name
		ipc_boot_args.push_back("0"); // suid
		ipc_boot_args.push_back("1"); // inherit logon
		ipc_boot_args.push_back("[" + os_user_name + "]@" + hostname + ":" + std::to_string(getpid()) + "/SOCKET");

		for (auto& a : argv)
		{
			ipc_boot_args.push_back(a);
		}

		SockSetopt(fd, NW_SOCK_SETNODELAY, NULL);
		SockInherit(fd, FALSE);

		if (debug)
		{
			fd_w_string(std::string("debug"));
		}
		fd_w_string(std::to_string(ipc_boot_args.size()));

		ssize_t written = 0;
		int ret = 0;
		// note: ipc_boot excepts arguments in reverse
		for (auto a = ipc_boot_args.rbegin(); a != ipc_boot_args.rend(); ++a)
		{
			written = fd_w_string((*a).c_str());
			if (written != static_cast<ssize_t>((*a).size() + 1))
			{
				trace << " write failed to socket "
					  << " written " << written << " requested " << (*a).size() + 1 << " errno " << errno << std::endl;
				ret = -1;
				break;
			}
		}
		return ret;
	}

	int handle_initial(std::string& error_code)
	{
		std::string buf;
		ssize_t read_bytes = 0;
		// 1. wait for "ipc_boot oke" or an error message
		read_bytes = fd_r_string(buf);
		trace << "received " << buf << std::endl;
		if (buf != "ipc_boot oke")
		{
			error_code = buf;
			network::closesocket(fd);
			fd = network::socket_t{};
			return -1;
		}

		// 2. wait for "server oke" that the bshell has started
		read_bytes = fd_r_string(buf);
		trace << "received " << buf << std::endl;
		if (buf != "server oke")
		{
			error_code = buf;
			network::closesocket(fd);
			fd = network::socket_t{};
			return -1;
		}

		// 3. send attachPath hostname!remote_prog. ls_main() expects this
		fd_w_string(hostname + "!" + remote_prog);

		// 4. receive "O.K." or error message from bshell after startup
		read_bytes = fd_r_string(buf);
		trace << "received " << buf << std::endl;

		fd_w_string("O.K.");
		if (read_bytes == 0)
		{
		};

		return 0;
	}

public:
	bshell_implementer_instance(
		const std::string& _bse_user_name,
		const std::string& _os_user_name,
		const std::string& _password,
		const std::string& _hostname,
		const std::string& _remote_bse,
		const std::string& _tenant,
		const std::string& _remote_prog,
		const std::vector<std::string>& _arguments,
		int _debug,
		CryptMethod _cm = BaanCryptMethod)
		: bse_user_name(_bse_user_name)
		, os_user_name(_os_user_name)
		, password(_password)
		, hostname(_hostname)
		, remote_bse(_remote_bse)
		, tenant(_tenant)
		, remote_prog(_remote_prog)
		, protocol(0)
		, blogin_port(7150)
		, crypt_method(_cm)
		, fd()
		, debug(_debug)
		, arguments(_arguments)
		, ret_code()
	{
	}

	void set_debug(int level) { debug = level; }

	std::string start(void)
	{
		std::stringstream str;
		std::string att_error("");
		int ret = attach_process(arguments, att_error);
		if (ret == -1)
		{
			str << "attach_process for " << remote_prog;
			str << "!" << hostname;
			str << " returned : " << ret;
			str << " nw_error " << nw_geterror();
			str << " " << nw_geterror_text();
			if (att_error != "")
			{
				str << " error from blogin " << att_error;
			}
		}
		else
		{
			std::string initial_error_code("");
			ret = handle_initial(initial_error_code);
			if (ret != 0)
			{
				str << "ret=" << ret << " " << initial_error_code;
			}
		}
		ret_code = str.str();
		return std::string(str.str());
	}

	~bshell_implementer_instance()
	{
		std::cerr << trace.str() << std::endl;
		network::closesocket(fd);
	};

	std::string get_ret_code(void) { return ret_code; }
};

static bshell_implementer_instance* start_eb(bshell_implementer_instance* eb)
{
	eb->start();
	return eb;
}

class implementer_bshell : public implementer
{

private:
	std::string BSE, bse_user, os_user, os_password, program, startobject;
	std::string configfile;
	int port;
	int debug;
	std::string tenant;
	std::vector<std::string> program_args;
	std::vector<std::string> startobject_args;

public:
	implementer_bshell()
		: implementer("bshell")
		, BSE()
		, bse_user()
		, os_user()
		, os_password()
		, program()
		, startobject()
		, program_args()
		, startobject_args()
	{
	}

	virtual void set_tenant(const std::string& t) { tenant = t; };

	virtual ~implementer_bshell(){};

	void from_json(const json& j)
	{
		implementer::from_json(j);
		json d(j.at("details"));
		d.at("BSE").get_to(BSE);
		d.at("bse_user").get_to(bse_user);
		d.at("os_user").get_to(os_user);
		d.at("os_password").get_to(os_password);
		d.at("program").get_to(program);
		d.at("startobject").get_to(startobject);
		d.at("configfile").get_to(configfile);
		port = d.value("port", 7150);
		debug = d.value("debug", 0);
		set_valid(true);
		if (d.find("program_args") != d.end())
		{
			for (auto& a : d.at("program_args"))
			{
				program_args.push_back(a.get<std::string>());
			}
		}
		if (d.find("startobject_args") != d.end())
		{
			for (auto& a : d.at("startobject_args"))
			{
				startobject_args.push_back(a.get<std::string>());
			}
		}
	}

	void to_json(json& j) const
	{
		implementer::to_json(j);
		j["details"].emplace("BSE", BSE);
		j["details"].emplace("port", port);
		j["details"].emplace("debug", debug);
		j["details"].emplace("bse_user", bse_user);
		j["details"].emplace("os_user", os_user);
		j["details"].emplace("os_password", os_password);
		j["details"].emplace("program", program);
		j["details"].emplace("startobject", startobject);
		j["details"].emplace("configfile", configfile);
		if (!program_args.empty())
		{
			j["details"].emplace("program_args", program_args);
		}
		if (!startobject_args.empty())
		{
			j["details"].emplace("startobject_args", startobject_args);
		}
	}

	virtual void to_json_instances(json& j) const
	{
		implementer::request_status();
		implementer::to_json_instances(j);
	}

public:
	void do_start(int new_count, const std::string& workspace_id, const std::string& implementerType, const std::string& implementerName)
	{
		std::string cpm_args(workspace_id + "," + implementerType);
		if (implementerName != "")
		{
			cpm_args += ",named:" + implementerName;
		}

		// must have arguments
		std::vector<std::string> args{
			"-server", "-daemon",			"-cpm_args", cpm_args,
			"-set",	"HTTP_LISTEN_PORT=0"
			//				"-cpm_config", configfile
		};

		for (auto& a : program_args)
			args.push_back(a);
		args.push_back(startobject);
		for (auto& a : startobject_args)
			args.push_back(a);

#define USE_ASYNC
#if defined(USE_ASYNC)

		std::vector<std::future<bshell_implementer_instance*>> fut;

		for (int i = 0; i < new_count; ++i)
		{
			bshell_implementer_instance* eb = new bshell_implementer_instance(bse_user, os_user, os_password, "localhost", BSE, tenant, program, args, debug);
			// create async object and start it parallel
			fut.emplace_back(std::async(std::launch::async, start_eb, eb));
			std::cout << " started implementer " << implementerType << " in workspace "
					  << workspace_id
					  //<< " ret code: " << ret
					  << std::endl;
		}

		std::vector<bshell_implementer_instance*> res;
		for (auto& fu : fut)
		{
			res.emplace_back(fu.get());
		}
		for (auto& eb : res)
		{
			std::string err(eb->get_ret_code());
			std::cout << "ret code : " << err << std::endl;
			if (!err.empty())
			{
				errors->emplace_back(err);
			}
			delete eb; // no longer needed
		}
#else

		for (int i = 0; i < new_count; ++i)
		{
			bshell_implementer_instance* eb = start_1(args);

			std::cout << " started implementer " << implementerType << " in workspace " << workspace_id << " ret code: " << (*eb)() << std::endl;
			delete eb;
		}

#endif
	}
};

class implementer_python : public implementer
{

private:
	std::string rootdir;

public:
	implementer_python()
		: implementer("python")
		, rootdir()
	{
	}

	virtual ~implementer_python(){};

	void from_json(const json& j)
	{
		implementer::from_json(j);
		json d(j.at("details"));
		d.at("PythonRoot").get_to(rootdir);
		set_valid(true);
	}

	void to_json(json& j) const
	{
		implementer::to_json(j);
		j["details"].emplace("PythonRoot", rootdir);
	}

	void do_start(int new_count, const std::string& workspace_id, const std::string& implementerType, const std::string& implementerName) {}
	virtual void set_tenant(const std::string& t){};
};

namespace implementer_creator
{
using implementer_creator_t = implementer* (*)(void);

std::map<std::string, implementer_creator_t> creator = { { "bshell", [] { return (implementer*)(new implementer_bshell()); } },
														 { "ashell", [] { return (implementer*)(new implementer_bshell()); } },
														 { "python", [] { return (implementer*)(new implementer_python()); } } };

implementer* create(const std::string&);

implementer* create(const std::string& type)
{
	auto impl = creator.find(type);
	if (impl == creator.end())
	{
		return nullptr;
	}
	else
	{
		return impl->second();
	}
}
} // namespace implementer_creator

class workspace
{
private:
	std::string workspaceID;
	std::string tenantID;
	std::string description;

	using implementers_id_t = sf::safe_ptr<std::map<const std::string, implementer*>>;
	using named_implementers_id_t = sf::safe_ptr<std::map<const std::string, implementers_id_t>>;

	implementers_id_t anon_implementers;
	named_implementers_id_t named_implementers;

	std::vector<std::string> errors;
	bool deleted;

private:
public:
	workspace()
		: workspaceID()
		, tenantID()
		, description()
		, anon_implementers()
		, named_implementers()
		, errors()
		, deleted(false){};

	~workspace()
	{
		for (auto a = anon_implementers->begin(); a != anon_implementers->end(); ++a)
		{
			delete a->second;
		}
		// TODO
		// for( auto a = named_implementers) {
		// 	//	delete a.second;
		// }
	};

	workspace(const std::string& _wID)
		: workspaceID(_wID)
		, tenantID()
		, description()
		, anon_implementers()
		, named_implementers()
		, errors()
		, deleted(false){};

	const std::string& get_workspaceID(void) const { return workspaceID; };
	void set_workspaceID(const std::string& _ID) { workspaceID = _ID; };
	const std::string& get_description(void) const { return description; };
	const std::string& get_tenantID(void) const { return tenantID; };
	const std::vector<std::string>& get_errors(void) { return errors; };
	void clear_errors(void) { errors.clear(); };

	void mark_for_delete(void) { deleted = true; }
	bool marked_for_delete(void) const { return deleted; }

	json get_errors_json()
	{
		json err = json::array();
		for (auto& i : errors)
		{
			err.push_back(i);
		}
		return err;
	}

public:
	void json_loop_implementers(json& impls, bool total = false) const
	{
		if (!anon_implementers->empty())
		{
			json a;
			a["anonymous"] = json::array();
			for (auto impl = anon_implementers->begin(); impl != anon_implementers->end(); ++impl)
			{
				// std::cout << " HI " << impl.first << std::endl;
				json ji;
				if (total)
				{
					impl->second->to_json(ji);
				}
				else
				{
					impl->second->to_json_instances(ji);
				}
				a["anonymous"].push_back(ji);
			}
			impls.push_back(a);
		}
		if (!named_implementers->empty())
		{
			json n;
			n["named"] = json::array();
			for (auto impl = named_implementers->begin(); impl != named_implementers->end(); ++impl)
			{
				json j = json::object();
				for (auto imp = impl->second->begin(); imp != impl->second->end(); ++imp)
				{
					json ji;
					if (total)
					{
						imp->second->to_json(ji);
					}
					else
					{
						imp->second->to_json_instances(ji);
					}
					j.emplace(impl->first, ji);
				}
				n["named"].push_back(j);
			}
			impls.push_back(n);
		}
	}

	void to_json(json& j) const
	{
		j = json{ { "description", description }, { "tenantID", tenantID }, { "workspaceID", workspaceID } };
		if (deleted)
		{
			j["status"] = json{ { "marked", "deleted" } };
		}
		j["implementers"] = json::array();
		json_loop_implementers(j["implementers"], true);
		// if ( !anon_implementers.empty() ) {
		// 	json a;
		// 	a["anonymous"] = json::array();
		// 	for (auto& impl: anon_implementers) {
		// 		//std::cout << " HI " << impl.first << std::endl;
		// 		json ji (impl.second);
		// 		a["anonymous"].push_back( ji );
		// 	}
		// 	j["implementers"].push_back(a);
		// }
		// if ( !named_implementers.empty() ) {
		// 	json n;
		// 	n["named"] = json::array();
		// 	for (auto& impl: named_implementers) {
		// 		json j = json::object();
		// 		for (auto& imp : impl.second) {
		// 			json ji (imp.second);
		// 			j.emplace( impl.first, ji);
		// 		}
		// 		n["named"].push_back(j);
		// 	}
		// 	j["implementers"].push_back(n);
		// }
	}

public:
	bool register_instance(const json& j)
	{
		try
		{
			implementer* i = find_implementer(j);
			if (i != nullptr)
			{
				i->add_instance(j);
				return true;
			}
			else
			{
				return false;
			}
		}
		catch (json::exception& e)
		{
			std::cerr << " register_instance: " << e.what() << std::endl;
			return false;
		}
	}

public:
	bool unregister_instance(const json& j)
	{
		try
		{
			implementer* i = find_implementer(j);
			if (i != nullptr)
			{
				i->remove_instance(j);
				return true;
			}
			else
			{
				return false;
			}
		}
		catch (json::exception& e)
		{
			std::cerr << " unregister_instance: " << e.what() << std::endl;
			return false;
		}
	}

public:
	bool error_start(const json& j)
	{
		try
		{
			implementer* i = find_implementer(j);
			if (i != nullptr)
			{
				i->error_start(j);
				std::string error;
				j.at("error").get_to(error);
				int pid;
				j.at("pid").get_to(pid);
				if (error != "")
				{
					std::stringstream err;
					err << "pid: " << pid << " " << error;
					errors.push_back(err.str());
				}
				return true;
			}
			else
			{
				return false;
			}
		}
		catch (json::exception& e)
		{
			std::cerr << " error_start: " << e.what() << std::endl;

			return false;
		}
	}

private:
	// create an implementer based on the implementer_creator map
	// this will call the correct constructor for the correct implementer
	//
	implementer* create_implementer(const std::string& type) { return implementer_creator::create(type); }

	implementer* find_implementer(const json& j)
	{
		std::string implementerType;
		j.at("implementerType").get_to(implementerType);

		auto named = j.find("implementerName");

		if (named != j.end())
		{
			std::string implementerName;
			j.at("implementerName").get_to(implementerName);
			const auto nimi = named_implementers->find(implementerName);
			if (nimi != named_implementers->end())
			{
				auto imi = (*nimi).second->find(implementerType);
				return imi != (*nimi).second->end() ? imi->second : nullptr;
			}
			else
			{
				return nullptr;
			}
		}
		else
		{
			auto imi = anon_implementers->find(implementerType);
			return imi != anon_implementers->end() ? (*imi).second : nullptr;
		}
	}

	implementer* json_to_implementer(const std::string& ns, const json& j)
	{
		implementer* e = nullptr;
		try
		{
			json jj = j.at("implementerType");

			std::string impl_type = j.at("implementerType");
			e = create_implementer(impl_type);
			if (ns != "anon") e->set_implementerName(ns);

			if (e)
			{
				e->from_json(j);
				if (e->is_valid())
				{
				}
				else
				{
					delete e;
					e = nullptr;
				}
			}
		}
		catch (const json::exception& excpt)
		{
			errors.push_back(std::string(excpt.what()) + " " + j.dump());
			std::cerr << "json error in " << j << "\n" << excpt.what() << std::endl;
			delete e;
			e = nullptr;
		}
		return e;
	}

	void add_anon_implementers(const json& imp)
	{
		// std::cout << "handle_anon_implementers" << std::endl;
		for (auto& im : imp.items())
		{
			// std::cout << " ---" << im.key() << " " << im.value() << std::endl;
			implementer* e = json_to_implementer("anon", im.value());
			if (e)
			{
				add_implementer(anon_implementers, e);
			}
		}
	}

	void add_named_implementers(const json& imp)
	{
		// std::cout << "handle_named_implementers" << std::endl;
		for (auto& im : imp.items())
		{
			// std::cout << " --- " << im.key() << " " << im.value() << std::endl;
			for (auto& i : im.value().items())
			{
				// std::cout << "  --- " << i.key() << " " << i.value() << std::endl;
				implementer* e = json_to_implementer(i.key(), i.value());
				if (e)
				{
					add_implementer(i.key(), e);
				}
			}
		}
	}

public:
	void add_or_update_implementers(const json& impls)
	{
		// std::cout << "implementors count: " << impls.size() << std::endl;
		for (auto& imp : impls.items())
		{
			auto val = imp.value();
			auto anon = val.find("anonymous");
			if (anon != val.end())
			{
				// std::cout << *anon  << std::endl;
				add_anon_implementers(*anon);
			}
			auto named = val.find("named");

			if (named != val.end())
			{
				// std::cout << *named  << std::endl;
				add_named_implementers(*named);
			}
		}
	}

private:
	void remove_anon_implementers(const json& imp)
	{
		std::cout << "remove_anon_implementers" << std::endl;
		for (auto& im : imp.items())
		{
			std::cout << " ---" << im.key() << " " << im.value() << std::endl;
			std::string implementerType;
			int count;
			json j = im.value();
			j.at("implementerType").get_to(implementerType);
			j.at("count").get_to(count);
			const auto imi = anon_implementers->find(implementerType);
			if (imi != anon_implementers->end())
			{
				imi->second->remove_instances(count);
			}
		}
	}

	void remove_named_implementers(const json& imp)
	{
		std::cout << "remove_named_implementers" << std::endl;
		for (auto& im : imp.items())
		{
			std::cout << " --- " << im.key() << " " << im.value() << std::endl;
			for (auto& i : im.value().items())
			{
				std::cout << "  --- " << i.key() << " " << i.value() << std::endl;
				std::string implementerType;
				std::string implementerName = i.key();
				int count;
				json j = i.value();
				j.at("implementerType").get_to(implementerType);
				j.at("count").get_to(count);

				const auto nimi = named_implementers->find(implementerName);
				if (nimi != named_implementers->end())
				{
					const auto& imi = (*nimi).second->find(implementerType);
					if (imi != (*nimi).second->end())
					{
						imi->second->remove_instances(count);
					}
				}
			}
		}
	}

public:
	void remove_all_implementers()
	{
		for (auto im = anon_implementers->begin(); im != anon_implementers->end(); ++im)
			im->second->remove_all_instances();
		for (auto imi = named_implementers->begin(); imi != named_implementers->end(); ++imi)
		{
			for (auto im = imi->second->begin(); im != imi->second->end(); ++im)
				im->second->remove_all_instances();
		}
	}

private:
	void cleanup_all_implementers()
	{
		for (auto im = anon_implementers->begin(); im != anon_implementers->end(); ++im)
			im->second->cleanup_all_instances();
		for (auto imi = named_implementers->begin(); imi != named_implementers->end(); ++imi)
		{
			for (auto im = imi->second->begin(); im != imi->second->end(); ++im)
				im->second->cleanup_all_instances();
		}
	}

public:
	void remove_deleted_instances()
	{
		for (auto im = anon_implementers->begin(); im != anon_implementers->end(); ++im)
			im->second->remove_deleted_instances();
		for (auto imi = named_implementers->begin(); imi != named_implementers->end(); ++imi)
		{
			for (auto im = imi->second->begin(); im != imi->second->end(); ++im)
				im->second->remove_deleted_instances();
		}
	}

public:
	void remove_implementers(const json& impls)
	{
		// std::cout << "implementors count: " << impls.size() << std::endl;
		for (auto& imp : impls.items())
		{
			auto val = imp.value();
			auto anon = val.find("anonymous");
			if (anon != val.end())
			{
				// std::cout << *anon  << std::endl;
				remove_anon_implementers(*anon);
			}
			auto named = val.find("named");

			if (named != val.end())
			{
				// std::cout << *named  << std::endl;
				remove_named_implementers(*named);
			}
		}
	}

public:
	void from_json(const json& j)
	{
		j.at("description").get_to(description);
		j.at("tenantID").get_to(tenantID);

		if (j.find("implementers") != j.end())
		{
			json impls = j.at("implementers");
			add_or_update_implementers(impls);
		}
	}

private:
	bool add_implementer(implementers_id_t& implementers, implementer* i)
	{
		auto imi = implementers->find(i->get_implementerType());
		bool ret;
		int count = i->get_count();
		if (imi == implementers->end())
		{
			(*implementers)[i->get_implementerType()] = i;
			i->set_tenant(tenantID); // set tenant before start()
			i->start(count, workspaceID); // start
			ret = true; // implementer added
		}
		else
		{
			int new_count = i->get_count();
			int cur_count = imi->second->get_count();
			imi->second->set_count(cur_count + new_count);
			imi->second->start(new_count, workspaceID);
			// errors.push_back( i->get_implementerType() + " already exists");
			delete i;
			ret = false;
		}

		return ret;
	}

public:
	bool add_implementer(const std::string& name, implementer* i)
	{
		auto& nimi = (*named_implementers)[name];
		return add_implementer(nimi, i);
	}

	json show_implementers(void)
	{
		json root;
		remove_deleted_instances();
		json_loop_implementers(root);

		return root;
	}
};

void to_json(json& j, const workspace* w) { w->to_json(j); }

// void from_json( const json& j, workspace* w)
// {
// 	std::vector<std::string> errors;
// 	try {
// 		w->from_json(j );
// 	}
// 	catch ( json::exception& e ){
// 		std::cout << __FUNCTION__ << std::endl;
// 		throw(e);
// 	}
// }

class workspaces
{
private:
	using workspaces_id_t = sf::safe_ptr<std::map<const std::string, workspace*>>;
	workspaces_id_t spaces;

public:
	workspaces(const workspaces& ws)
		: spaces(ws.spaces)
	{
	}

	workspaces()
		: spaces(){};

private:
	workspaces& operator=(const workspaces& ws);
	workspaces& operator=(workspaces&& ws);

public:
	bool add_workspace(workspace* wp)
	{
		auto wpi = spaces->find(wp->get_workspaceID());
		if (wpi == spaces->end())
		{
			(*spaces)[wp->get_workspaceID()] = wp;
			return true;
		}
		else
		{
			if (wpi->second->marked_for_delete())
			{
				spaces->erase(wpi);
				delete wpi->second;
				(*spaces)[wp->get_workspaceID()] = wp;
				return true;
			}
			return false;
		}
	}

	workspace* get_workspace(const std::string& id)
	{
		auto wpi = spaces->find(id);
		if (wpi == spaces->end())
		{
			return nullptr;
		}
		else
		{
			return (*wpi).second;
		}
	}

	bool remove_workspace(const std::string& key)
	{
		auto wpi = spaces->find(key);
		if (wpi == spaces->end())
		{
			return false;
		}
		else
		{
			// spaces.erase(wpi);
			wpi->second->remove_all_implementers();
			wpi->second->mark_for_delete();
			// delete wpi->second;
			return true;
		}
	}

	json show_workspaces(void)
	{
		json root; // = json::object();
		for (auto w = spaces->begin(); w != spaces->end(); ++w)
		{
			w->second->remove_deleted_instances();
			json j{ w->second->get_workspaceID(), json(w->second) };
			root.emplace_back(j);
		}

		return root;
	}

	void delete_all_workspaces(void)
	{
		for (auto w = spaces->begin(); w != spaces->end(); ++w)
		{
			remove_workspace(w->first);
		}
	}

	void to_json(json& j) const
	{
		for (auto w = spaces->begin(); w != spaces->end(); ++w)
		{
			j["workspaces"][w->first] = w->second;
		}
	}

	void from_json(const json& j)
	{
		for (auto& el : j.items())
		{
			try
			{
				// std::cout << " WS: key   >> " << el.key() << std::endl;
				// std::cout << " WS: value >> " << std::setw(2) << el.value() << std::endl;
				workspace* w = new workspace(el.key());
				add_workspace(w);

				w->from_json(el.value());

				for (auto& error : w->get_errors())
				{
					std::cout << error << std::endl;
				}
			}

			catch (json::exception)
			{
				// std::cout << "invalid workspace in " << el.key() << std::endl
				// 	  << "===>   " << e.what() << std::endl
				// 	  << "===>   " << std::setw(1) << el.value() << std::endl;
			}
		}
	}

	void implementers_post(const std::string& id, const json& j) {}
	bool register_instance(const std::string& w_id, const json& j)
	{
		workspace* w = get_workspace(w_id);
		if (w != nullptr)
		{
			return w->register_instance(j);
		}
		else
		{
			return false;
		}
	}
	bool unregister_instance(const std::string& w_id, const json& j)
	{
		workspace* w = get_workspace(w_id);
		if (w != nullptr)
		{
			return w->unregister_instance(j);
		}
		else
		{
			return false;
		}
	}
	bool error_start(const std::string& w_id, const json& j)
	{
		workspace* w = get_workspace(w_id);
		if (w != nullptr)
		{
			return w->error_start(j);
		}
		else
		{
			return false;
		}
	}
};

void to_json(json& j, const workspaces& ws) { ws.to_json(j); }

void from_json(const json& j, workspaces& ws) { ws.from_json(j); }

class application
{
private:
	std::string executable;
	std::string args;
	std::string description;
	std::string id;
	// exit action
	// exit delay

public:
	application(){};
	~application(){};
	application(const application& a){

	};

	application& operator=(const application& a) { return *this; };

	application(application&&) = delete;
	application& operator=(application&&) = delete;

	int start(void);

	int shutdown(void);

	void from_json(const json& j)
	{
		j.at("application").get_to(executable);
		j.at("arguments").get_to(args);
		j.at("description").get_to(description);
		j.at("id").get_to(id);
	}
	std::string get_id(void) { return id; }
};

void to_json(json& j, const application* value) {}

void from_json(const json& j, application* value)
{
	try
	{
		std::cout << j << std::endl;
	}
	catch (json::exception& e)
	{
		std::cerr << "error in application json pobject: " << e.what() << std::endl;
	}
}

using applications_id_t = sf::safe_ptr<std::map<const std::string, application*>>;

class applications
{
private:
	applications_id_t apps;

public:
	applications(){};
	~applications(){};

	applications(const applications&) = delete;
	applications operator=(const applications&) = delete;

	applications(applications&& as)
		: apps(as.apps){};

private:
	applications& operator=(applications&& as);

public:
	void from_json(const json& a)
	{

		// json startup;
		// json shutdown;

		// for (auto &el : a.items() ) {
		// 	application *app = new application();
		// 	app->from_json( el.value() );

		// }
	}

public:
	bool add_application(application* ap)
	{
		auto api = apps->find(ap->get_id());
		if (api == apps->end())
		{
			(*apps)[ap->get_id()] = ap;
			return true;
		}
		else
		{
			return false;
		}
	}
};

void to_json(json& j, const applications& as) {}

void from_json(const json& j, applications& as) {}

static workspaces ws;
static applications as;

class manager : public http::basic::threaded::server
{
public:
	class config
	{

	private:
		std::string cldls_hostname;
		std::string configuration;
		std::string cldls_base; // base path of CldLS for http services
		std::string url_config; // relative to cldls_base: get configuration from CldLS using this api
		std::string url_register; // relative to cldls_base: register this CPM to the CldLS
		std::string url_unregister; // relative to cldls_base: unregister this CPM to the CldLS
		std::string shutdown_url; // to which url should the CldLs send the shutdown request
		int port;
		bool remote_config;

		json httpconfig;
		json apipaths;
		int verbose;

	public:
		config(int port_, int _verbose = 0)
			: cldls_hostname()
			, configuration()
			, url_config()
			, url_register()
			, url_unregister()
			, shutdown_url()
			, port(port_)
			, remote_config(false)
			, httpconfig()
			, apipaths()
			, verbose(_verbose)
		{
		}

		~config() {}

		const json& get_httpconfig(void) { return httpconfig; }
		std::string get_apipaths(const char* key, const char* default_val) { return std::string(apipaths.value(key, default_val)); }

		std::string find_config(const std::string& filename, json& conf)
		{
			std::ifstream config(filename);

			if (!config)
			{
				return std::string(" cannot open config file '" + filename + "' in " + getcwd(nullptr, 0));
			}
			json cpm_conf;
			try
			{
				config >> cpm_conf;
				std::cout << std::setw(2) << cpm_conf;
			}
			catch (json::exception& e)
			{
				return std::string("parse of main config file '" + filename + "'\n" + "message: " + e.what());
			}
			auto local = cpm_conf.find("local");
			auto remote = cpm_conf.find("remote");

			if (local == cpm_conf.end() && remote == cpm_conf.end())
			{
				return std::string("config file must have at least a local or a remote config");
			}
			// first try remote config by sending a GET to the Cloud Platform Manager
			// if that fails try the local config setting
			bool conf_ok(false);

			if (remote != cpm_conf.end())
			{ // try remote config first
				try
				{
					json remote_conf(*remote);
					remote_conf.at("hostname").get_to(cldls_hostname);
					remote_conf.at("port").get_to(port);
					remote_conf.at("cldls_base").get_to(cldls_base), remote_conf.at("url_config").get_to(url_config);
					remote_conf.at("url_register").get_to(url_register);
					remote_conf.at("url_unregister").get_to(url_unregister);
					remote_conf.at("configuration").get_to(configuration);
					conf_ok = true;
				}
				catch (json::exception& e)
				{
					std::cerr << " Error on remote config: " << e.what() << "\n" << std::endl;
					conf_ok = false;
				}
				if (conf_ok)
				{
					cloud::platform::landscaper::configuration_api CldLS(cldls_hostname, port, cldls_base + url_config, configuration, verbose);

					if (CldLS.exec(conf) == true)
					{
						std::cout << "============\n"
								  << "-- REMOTE --\n"
								  << "============\n";
						conf_ok = true;
						remote_config = true;
					}
				}
			}
			if ((conf_ok != true) && (local != cpm_conf.end()))
			{
				try
				{
					std::string filename;
					json local_conf(*local);

					local_conf.at("filename").get_to(filename);

					std::ifstream config(filename);
					if (!config)
					{
						std::cerr << "cannot open local config file '" << filename << "'\n";
						conf_ok = false;
					}
					else
					{
						config >> conf;
						std::cout << "\n"
								  << "============\n"
								  << "-- LOCAL  --\n"
								  << "============\n";
						conf_ok = true;
					}
				}
				catch (json::exception& e)
				{
					return std::string(" Error in local config: " + std::string(e.what()) + "\n");
				}
			}

			if ((cpm_conf.find("httpconfig") == cpm_conf.end()) || (cpm_conf.find("apipaths") == cpm_conf.end()))
			{
				return std::string(" Error: missing httpconfig section\n");
			}

			httpconfig = cpm_conf.at("httpconfig");
			apipaths = cpm_conf.at("apipaths");

			return std::string("");
		}

		std::string get_hostname(void)
		{
			char host[HOST_NAME_MAX];

			int ret = gethostname(host, sizeof(host));
			if (ret != 0)
			{
				return std::string("illegal host");
			}
			else
			{
				return std::string(host);
			}
		}

	private:
		bool execute_CPM_cmd(const std::string& ID, const json& reg_data, int verbose = 0)
		{
			cloud::platform::landscaper::registry_api reg(cldls_hostname, port, cldls_base + url_register, ID, reg_data, verbose);

			json reg_return;
			if (reg.exec(reg_return))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

	public:
		bool register_CPM(const std::string& ID, int verbose = 0)
		{
			if (remote_config)
			{
				json reg_data{ { "hostname", get_hostname() },
							   { "port", port }, // TODO: make dynamic
							   { "state", "started" },
							   { "shutdown_url", "/es_server/internal/configuration/shutdown" } };

				return execute_CPM_cmd(ID, reg_data, verbose);
			}
			else
			{
				return true; //
			}
		}

		bool unregister_CPM(const std::string& ID, int verbose = 0)
		{
			if (remote_config)
			{
				json reg_data{ { "hostname", get_hostname() },
							   { "port", port }, // TODO make dynamic
							   { "state", "stopped" } };

				return execute_CPM_cmd(ID, reg_data, verbose);
			}
			else
			{
				return true;
			}
		}
	};

private:
	std::promise<int> shutdown_promise;
	std::future<int> shutdown_future;
	manager::config* cpm_conf;

public:
	manager(http::configuration& configuration, const std::string& base_path_config, const std::string& base_path_workspaces, manager::config* _conf)
		: http::basic::threaded::server(configuration)
		, shutdown_promise()
		, shutdown_future()
		, cpm_conf(_conf)
	{
		router_.on_get("/status", [this](http::session_handler& session) {
			http::basic::threaded::server::manager().server_information(configuration_.to_string());
			http::basic::threaded::server::manager().router_information(router_.to_string());
			session.response().body() = http::basic::threaded::server::manager().to_string();
			session.response().type("text");
			session.response().status(http::status::ok);
		});

		setup_config(base_path_config);
		setup_workspaces(base_path_workspaces);
	}

	virtual ~manager() {}

	virtual void start_server() { http::basic::threaded::server::start_server(); }

	virtual void stop_server() { http::basic::threaded::server::deactivate(); }

private:
	void setup_config(const std::string& base_path)
	{
		router_.on_get(base_path + "/configuration", [this](http::session_handler& session) {
			session.response().status(http::status::ok);
			std::cout << session.request().body() << std::endl;
			session.response().type("text");
			session.response().body() = std::string("OK") + session.request().body();
		});

		router_.on_put(base_path + "/configuration/shutdown/{secs}", [this](http::session_handler& session) {
			auto& ID = session.params().get("secs");

			// TODO: shutdown all workspaces

			int shutdown = std::stoi(ID);
			std::cerr << "Received shutdown " << shutdown << " s\n";
			std::cerr << session.request().header_to_string();
			std::cerr << session.request().body();
			send_json_response(session, http::status::ok, json{ { "time", shutdown } });

			ws.delete_all_workspaces();
			shutdown_promise.set_value(shutdown);
		});

		// registers an implementer instance
		// expects implementer ID and pid of processs
		router_.on_put(base_path + "/configuration/workspace/{ID}/register", [this](http::session_handler& session) {
			auto& id = session.params().get("ID");
			try
			{
				std::stringstream str;
				str << session.request().body();
				json j;
				str >> j;
				ws.register_instance(id, j);
				std::cout << " register " << id << "\n" << str.str() << std::endl;
				session.response().status(http::status::ok);
			}
			catch (json::exception& e)
			{
				set_json_response_catch(session, e);
			}
			catch (...)
			{
				session.response().status(http::status::bad_request);
			}
		});
		// unregisters an implementer instance
		router_.on_put(base_path + "/configuration/workspace/{ID}/unregister", [this](http::session_handler& session) {
			auto& ID = session.params().get("ID");
			try
			{
				std::stringstream str;
				str << session.request().body();
				json j;
				str >> j;
				ws.unregister_instance(ID, j);
				std::cout << " unregister " << ID << "\n" << str.str() << std::endl;
				session.response().status(http::status::ok);
			}
			catch (json::exception& e)
			{
				set_json_response_catch(session, e);
			}
			catch (...)
			{
				session.response().status(http::status::bad_request);
			}
		});
		// unregisters an implementer instance
		router_.on_put(base_path + "/configuration/workspace/{ID}/error/start", [this](http::session_handler& session) {
			auto& ID = session.params().get("ID");
			try
			{
				std::stringstream str;
				str << session.request().body();
				json j;
				str >> j;
				ws.error_start(ID, j);
				std::cout << " error during start " << ID << "\n" << str.str() << std::endl;
				session.response().status(http::status::ok);
			}
			catch (json::exception& e)
			{
				set_json_response_catch(session, e);
			}
			catch (...)
			{
				session.response().status(http::status::bad_request);
			}
		});
	}

	void setup_workspaces(const std::string& base_path)
	{
		router_.on_get(base_path + "/workspaces", [this](http::session_handler& session) {
			json items;
			items["items"] = ws.show_workspaces();
			send_json_response(session, http::status::ok, items);
		});

		router_.on_post(base_path + "/workspaces", [this](http::session_handler& session) {
			try
			{
				std::stringstream str;
				str << session.request().body();
				json j;
				str >> j;
				// std::cout << " got: \n"
				// 	  << str.str()
				// 	  << "\n"
				// 	  << j
				// 	  << std::endl;
				std::string workspaceID;
				j.at("workspaceID").get_to(workspaceID);

				// check if workspaceID is already there
				workspace* wo = ws.get_workspace(workspaceID);
				if ((wo == nullptr) || (wo->marked_for_delete()))
				{
					// wo will be deleted in add_workspace
					workspace* w = new workspace(workspaceID);
					w->from_json(j);
					ws.add_workspace(w);
					session.response().status(http::status::created);
				}
				else
				{
					set_error_response(session, http::status::bad_request, "null", "workspace " + workspaceID + " already present");
				}
			}
			catch (json::exception& e)
			{
				set_json_response_catch(session, e);
			}
			catch (...)
			{
				session.response().status(http::status::bad_request);
			}
		});

		router_.on_get(base_path + "/workspaces/{workspaceID}", [this](http::session_handler& session) {
			auto& w_id = session.params().get("workspaceID");
			if (w_id.empty())
			{
				set_error_response(session, http::status::not_found, "null", "empty workspaceID");
			}
			else
			{
				workspace* w = ws.get_workspace(w_id);
				if (w != nullptr)
				{
					w->remove_deleted_instances();
					json j(w);
					send_json_response(session, http::status::ok, json(w));
				}
				else
				{
					set_error_response(session, http::status::not_found, "null", "workspaceID " + w_id + " not found");
				}
			}
		});

		router_.on_delete(base_path + "/workspaces/{workspaceID}", [this](http::session_handler& session) {
			auto& w_id = session.params().get("workspaceID");
			if (w_id.empty())
			{
				session.response().status(http::status::bad_request);
			}
			else if (ws.remove_workspace(w_id))
			{
				json res{ { "code", 0 } };
				send_json_response(session, http::status::ok, res);
			}
			else
			{
				set_error_response(session, http::status::not_found, "null", "workspace " + w_id + " not found");
			}
		});

		// increase workspace
		router_.on_post(base_path + "/workspaces/{workspaceID}/implementers", [this](http::session_handler& session) {
			auto& workspaceID = session.params().get("workspaceID");

			if (workspaceID.empty())
			{
			}
			else
			{
				workspace* w = ws.get_workspace(workspaceID);
				if ((w == nullptr) || (w->marked_for_delete()))
				{
					set_error_response(session, http::status::bad_request, "null", "workspace " + workspaceID + " not found");
				}
				else
				{
					try
					{
						std::stringstream str;
						str << session.request().body();
						json im;
						std::cout << str.str() << std::endl;
						str >> im;
						std::cout << std::setw(2) << im << std::endl;
						json impl = im.at("implementers");
						w->add_or_update_implementers(impl);
						w->remove_deleted_instances();
						json items;
						items["items"] = w->get_errors_json();
						send_json_response(session, http::status::created, items);
					}
					catch (json::exception& e)
					{
						set_json_response_catch(session, e);
					}
				}
			}
		});

		// decrease workspace
		router_.on_delete(base_path + "/workspaces/{workspaceID}/implementers", [this](http::session_handler& session) {
			//	auto& w_id = session.params().get("workspaceID");

			auto& workspaceID = session.params().get("workspaceID");

			if (workspaceID.empty())
			{
			}
			else
			{
				workspace* w;
				if ((w = ws.get_workspace(workspaceID)) == nullptr)
				{
					set_error_response(session, http::status::bad_request, "null", "workspace " + workspaceID + " not found");
				}
				else
				{
					try
					{
						std::stringstream str;
						str << session.request().body();
						json im;
						std::cout << str.str() << std::endl;
						str >> im;
						std::cout << std::setw(2) << im << std::endl;
						json impl = im.at("implementers");
						w->remove_implementers(impl);
						json items;
						items["items"] = w->get_errors_json();
						send_json_response(session, http::status::created, items);
					}
					catch (json::exception& e)
					{
						set_json_response_catch(session, e);
					}
				}
			}
		});

		router_.on_get(base_path + "/workspaces/{workspaceID}/implementers", [this](http::session_handler& session) {
			auto& w_id = session.params().get("workspaceID");

			if (w_id.empty())
			{
				session.response().status(http::status::not_found);
			}
			else
			{
				workspace* w = ws.get_workspace(w_id);
				if (w)
				{
					json items;
					items["items"] = json::array();
					items["items"] = w->show_implementers();
					send_json_response(session, http::status::ok, items);
				}
				else
				{
					set_error_response(session, http::status::bad_request, "null", "workspace " + w_id + " not found");
				}
			}
		});

		router_.on_get(base_path + "/not_yet", [this](http::session_handler& session) {
			session.response().type("text");
			session.response().body() = std::string("NOT YET....");
			session.response().status(http::status::ok);
		});
	}

public:
	virtual void set_error_response(http::session_handler& session, http::status::status_t status, const std::string& code, const std::string& message)
	{

		session.response().status(status);
		session.response().type("application/json");
		json error{
			{ "code", status },
		};
		error["error"].emplace_back(json{ { "code", code }, { "message", message } });

		session.response().body() = error.dump();
	}

	virtual void set_json_response_catch(http::session_handler& session, const json::type_error& error)
	{
		set_error_response(session, http::status::bad_request, std::to_string(error.id), error.what());
	}
	virtual void set_json_response_catch(http::session_handler& session, const json::exception& error)
	{
		set_error_response(session, http::status::bad_request, std::to_string(error.id), error.what());
	}

	virtual void send_json_response(http::session_handler& session, http::status::status_t status, json j)
	{
		session.response().status(status);
		session.response().type("application/json");
		// j["etags"] = json::array();
		j["etags"].emplace_back(json{ { "id", "some id" }, { "etag", "some etag" } });
		session.response().body() = j.dump();
	}

	virtual void wait4shutdown(void)
	{
		shutdown_future = shutdown_promise.get_future();
		int shutdown = shutdown_future.get();
		sleep(shutdown);
		deactivate();
	}
};

static manager* cpm_server;

} // namespace platform
} // namespace cloud

class cURL_global
{
public:
	cURL_global() { curl_global_init(CURL_GLOBAL_ALL); }

	~cURL_global() { curl_global_cleanup(); }
};

int main(int argc, const char** argv)
{

	cURL_global g; // initialize cURL global stuff

	prog_args::arguments_t cmd_args(
		argc, argv,
		{ { "workdir", { prog_args::arg_t::arg_val, " <workdir>: Working directory for Platform Manager ", "." } },
		  { "configfile", { prog_args::arg_t::arg_val, " <config>: filename for the config file", "pm.json" } },
		  { "curldebug", { prog_args::arg_t::flag, " enables cURL tracing ", "false" } },
		  { "http_port", { prog_args::arg_t::arg_val, "port number to use", "4000" } },
		  { "port", { prog_args::arg_t::arg_val, "port number to use", "5000" } } });

	if (cmd_args.process_args() == false)
	{
		std::cerr << " error in arguments\n";
		exit(1);
	}

	if (chdir(cmd_args.get_val("workdir").c_str()))
	{
		std::cerr << "cannot chdir to " << cmd_args.get_val("workdir") << std::endl;
		exit(1);
	}

	// first try remote config by sending a GET to the Cloud Platform Manager
	// if that fails try the local config setting
	json conf;

	int port = std::stoi(cmd_args.get_val("port"));
	cloud::platform::manager::config CPMconf(port, cmd_args.flag_set("curldebug"));
	;

	bool conf_ok(false);

	std::string cpm_config(cmd_args.get_val("configfile"));

	//
	// start Cloud Manager http rest server
	//

	static http::configuration* configuration = new http::configuration(std::initializer_list<http::field<std::string>>{
		{ "server", "Platform Manager" }, { "http_listen_port_begin", cmd_args.get_val("http_port") }, { "http_listen_port_end", cmd_args.get_val("http_port") }, { "https_enabled", "false" },
		// {"https_listen_port_begin", "4100"},
		// {"https_listen_port_end", "4100"},
		// {"keepalive_count", "1024"},
		// {"keepalive_timeout", "5"},
		// {"doc_root", "/temp/docroot"},
		// {"ssl_certificate", "server.crt"},
		// {"ssl_certificate_key", "server.key"}
	});

	for (auto& c : CPMconf.get_httpconfig().items())
	{
		configuration->set(c.key(), c.value());
	}

	std::string err;
	if ((err = CPMconf.find_config(cpm_config, conf)) == "")
	{
		cloud::platform::cpm_server
			= new cloud::platform::manager(*configuration, CPMconf.get_apipaths("internal", "/es_server/internal"), CPMconf.get_apipaths("public", "/es_server/rest"), &CPMconf);

		cloud::platform::cpm_server->start_server();

		try
		{
			// parse the remote or the local config
			std::cout << std::setw(2) << conf << std::endl;

			cloud::platform::as.from_json(conf.at("application")); // TODO: optional
			cloud::platform::ws.from_json(conf.at("workspaces"));
			conf_ok = true;
		}
		catch (json::exception& e)
		{
			std::cerr << "Bad Config: message: " << e.what() << std::endl;
			conf_ok = false;
		}
		if (conf_ok == false)
		{
			std::cerr << " no valid config found: don't start Cloud Platform Manager" << std::endl;
		}
		else
		{
			CPMconf.register_CPM("nlbaldev6.infor.com", cmd_args.flag_set("curldebug"));

			cloud::platform::cpm_server->wait4shutdown();

			CPMconf.unregister_CPM("nlbaldev6.infor.com", cmd_args.flag_set("curldebug"));
		}
		cloud::platform::cpm_server->stop_server();
		delete cloud::platform::cpm_server;
	}
	else
	{
		std::cerr << " Configuration failed: " << err << std::endl;
	}

	return 0;
}

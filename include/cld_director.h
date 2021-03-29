#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>

// wireshark:
// portrange 8000-8032 or port 4000

#define CURL_STATICLIB

#ifndef LOCAL_TESTING
#include "nlohmann_json.hpp"
#include "baanlogin.h"
#include "bdaemon.h"
#include <curl/curl.h>

#ifdef _WIN32
#include "sspisecurity.h"
#include <direct.h>
#include <process.h>
#define HOST_NAME_MAX 256
#else
#include <unistd.h>
#endif

#else
#define get_version_ex(PORT_SET, NULL) "1.0"
#define BAAN_WINSTATION_NAME "baan"
#define BAAN_DESKTOP_NAME "desktop"
#define PORT_SET "9.4x"
#include "nlohmann/json.hpp"
#endif

#include "http_async.h"
#include "http_basic.h"
#include "http_network.h"
#include "prog_args.h"

using json = nlohmann::json;

namespace bse_utils
{

#ifdef LOCAL_TESTING

namespace local_testing
{
std::mutex m;

template <typename S> struct test_sockets
{
public:
	std::map<std::string, std::set<S>> available_sockets_;
	std::mutex m_;

	test_sockets(const std::vector<std::string>& workspaces, S b, size_t nr) // 8000 64
	{
		for (auto& workspace : workspaces)
		{
			std::lock_guard<std::mutex> g{ m_ };
			for (S i = 0; i < nr; i++)
				available_sockets_[workspace].emplace(b + i);
		}
	}

	S aquire(const std::string& workspace_id)
	{
		std::lock_guard<std::mutex> g{ m_ };

		auto port = *(available_sockets_[workspace_id].begin());
		available_sockets_[workspace_id].erase(port);
		return port;
	}

	S aquire(const std::string& workspace_id, S port)
	{
		std::lock_guard<std::mutex> g{ m_ };

		available_sockets_[workspace_id].erase(port);

		return port;
	}

	void release(const std::string& workspace_id, const std::string& url)
	{
		std::lock_guard<std::mutex> g{ m_ };
		auto port = url.substr(1 + url.find_last_of(':'));

		available_sockets_[workspace_id].emplace(stoul(port));
	}
};

static test_sockets<std::uint32_t> _test_sockets{
	{ "workspace_000", "workspace_001", "workspace_002", "workspace_003", "workspace_100", "workspace_101",
	  "workspace_102", "workspace_103", "workspace_104", "workspace_105", "workspace_106", "workspace_107",
	  "workspace_108", "workspace_109", "workspace_110", "workspace_111", "workspace_112", "workspace_113",
	  "workspace_114", "workspace_115", "workspace_116", "workspace_117",  "workspace_118", "workspace_119",
	  "workspace_120", "workspace_121", "workspace_122", "workspace_123", "workspace_124", "workspace_125",
	  "workspace_126", "workspace_127", "workspace_128", "workspace_129", "workspace_130", "workspace_131",
	  "workspace_132", "workspace_133", "workspace_134", "workspace_135", "workspace_136", "workspace_137",
	  "workspace_138", "workspace_139", "workspace_140", "workspace_141", "workspace_142", "workspace_143",
	  "workspace_144", "workspace_145", "workspace_146", "workspace_147", "workspace_148", "workspace_149",
	  "workspace_150", "workspace_151", "workspace_152", "workspace_153", "workspace_154", "workspace_155",
	  "workspace_156", "workspace_157", "workspace_158", "workspace_159", "workspace_160", "workspace_161",
	  "workspace_162", "workspace_163" },
		8000,
		64 
	};

} // namespace local_testing

static bool create_bse_process_as_user(
	const std::string&,
	const std::string&,
	const std::string&,
	const std::string&,
	const std::string& parameters, // for local testing retreive the level this way :(
	std::uint32_t& pid,
	std::string& ec)
{
	bool result = true;

	auto parameters_as_configuration = http::configuration({}, parameters);

	auto worker_id = parameters_as_configuration.get("cld_worker_id");
	auto worker_label = parameters_as_configuration.get("cld_worker_label");
	auto worker_workspace = parameters_as_configuration.get("cld_manager_workspace");
	auto worker_workgroup = parameters_as_configuration.get("cld_manager_workgroup");

	pid = local_testing::_test_sockets.aquire(worker_workspace);

	ec = "";

	std::thread([pid, worker_workspace, worker_label, worker_workgroup, worker_id]() {
		std::lock_guard<std::mutex> g{ local_testing::m };
		json put_new_instance_json = json::object();
		std::string ec;
		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["worker_label"] = worker_label;
		put_new_instance_json["base_url"] = "http://localhost:" + std::to_string(pid);
		put_new_instance_json["version"] = "test_bshell";


		auto response = http::client::request<http::method::put>(
			"http://localhost:4000/internal/platform/manager/workspaces/" + worker_workspace + "/workgroups/"
				+ worker_workgroup + "/workers/" + worker_id,
			ec,
			{},
			put_new_instance_json.dump()); //,std::cerr, true);

		if (ec.empty())
		{
			if (response.status() != http::status::ok && response.status() != http::status::created
				&& response.status() != http::status::no_content)
			{
				throw std::runtime_error{ "error sending \"worker\" registration" };
			}
			// else
			//	std::cout <<
			//"http://localhost:5000/internal/platform/manager/workspaces/workspace_000/workgroups/untitled/bshells/"
			//"workers/ send\n";
		}
		else
			throw std::runtime_error{ "error sending \"worker\" registration" };
	}).detach();

	pid = pid + 1;
	return result;
}

#else
static bool create_bse_process_as_user(
	const std::string& bse,
	const std::string& bse_bin,
	const std::string& tenand_id,
	const std::string& user,
	const std::string& password,
	const std::string& command,
	std::uint32_t& pid,
	std::string& ec)
{
	bool result = false;
#ifndef _WIN32
	// If user is empty then start process as same user
	auto user_ok = user == "" || CheckUserInfo(user.data(), password.data(), NULL, 0, NULL, 0);
#else
	HANDLE requested_user_token = 0;
	auto user_ok = CheckUserInfo(
		user.data(), password.data(), NULL, 0, NULL, 0, &requested_user_token, eWindowsLogonType_Default);
	if (!user_ok)
	{
		// TODO more info about failure.
		ec = "login as user: " + user + " failed";
		result = false;
	}
	else
	{
		char desktop[MAX_PATH];
		const char* required_environment_vars[]
			= { "ALLUSERSPROFILE", "CLASSPATH",	 "CLASSPATH", "SLMHOME", "SLM_RUNTIME",
				"SystemDrive",	   "SystemRoot", "WINDIR",	  "TMP",	 "TEMP" };

		std::string environment_block;
		std::stringstream ss;

		ss << "BSE=" << bse << char{ 0 };
		ss << "BSE_BIN=" << bse_bin << char{ 0 };
		ss << "BSE_SHLIB=" << bse_bin << "\\..\\shlib" << char{ 0 };
		ss << "TENAND_ID=" << tenand_id << char{ 0 };

		for (auto var : required_environment_vars)
		{
			if (getenv(var))
			{
				ss << var << "=" << getenv(var) << char{ 0 };
			}
		}
		ss << char{ 0 };

		PROCESS_INFORMATION piProcInfo = { 0 };
		STARTUPINFO siStartInfo{ 0 };
		siStartInfo.cb = sizeof(STARTUPINFO);

		snprintf(desktop, sizeof(desktop), "%s\\%s", BAAN_WINSTATION_NAME, BAAN_DESKTOP_NAME);

		siStartInfo.lpDesktop = desktop;
		auto error = GetLastError();

		std::string command_cpy = command;
		if (0)
		{
			command_cpy = "C:\\Windows\\System32\\notepad.exe";
		}

		error = 0;
		result = CreateProcessAsUser(
			requested_user_token, /* Handle to logged-on user */
			NULL, /* module name */
			const_cast<LPSTR>(command_cpy.data()), /* command line */
			NULL, /* process security attributes */
			NULL, /* thread security attributes */
			FALSE, /* inherits handles */
			CREATE_NEW_PROCESS_GROUP | /* New root process */
				DETACHED_PROCESS | /* Create NO console!! */
				CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
			const_cast<LPSTR>(ss.str().data()), /* new environment block */
			bse.data(), /* current working directory name */
			&siStartInfo,
			&piProcInfo /* Returns thread */
		);

		char buf[256];
		FormatMessage(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			buf,
			(sizeof(buf) / sizeof(char)),
			NULL);

		ec.assign(buf, std::strlen(buf));

		if (result) pid = piProcInfo.dwProcessId;

		CloseHandle(piProcInfo.hThread);
		CloseHandle(piProcInfo.hProcess);
		RevertToSelf();
		CloseHandle(requested_user_token);
	}
#endif

#ifndef _WIN32
	if (!user_ok)
	{
		// TODO more info about failure.
		ec = "login as user: " + user + " failed";
		result = false;
	}
	else
	{
		auto argv = split_string(command.data());

		// TODO required_environment_vars not needed to start process in (tenant) jail.
		const char* required_environment_vars[] = { "PATH",		 "CLASSPATH",	 "CLASSPATH", "SLMHOME", "SLM_RUNTIME",
													"SLM_DEBUG", "SLM_DEBUFILE", "HOSTNAME",  "TMP",	 "TEMP" };

		std::vector<char*> envp;

		std::string environment_block;
		std::stringstream ss;

		if (bse != "")
		{
			ss << "BSE=" << bse << char{ 0 };
			envp.push_back(strdup(ss.str().data()));
			std::stringstream().swap(ss);
		}

		if (bse_bin != "")
		{
			ss << "BSE_BIN=" << bse_bin << char{ 0 };
			envp.push_back(strdup(ss.str().data()));
			std::stringstream().swap(ss);

			ss << "BSE_SHLIB=" << bse_bin << "/../shlib" << char{ 0 };
			envp.push_back(strdup(ss.str().data()));
			std::stringstream().swap(ss);

			ss << "SYSTEMLIBDIR64=" << bse_bin << "/../shlib:" << getenv("SYSTEMLIBDIR64") << char{ 0 };
			envp.push_back(strdup(ss.str().data()));
			std::stringstream().swap(ss);
		}

		for (auto var : required_environment_vars)
		{
			if (getenv(var))
			{
				ss << var << "=" << getenv(var) << char{ 0 };
				envp.push_back(strdup(ss.str().data()));
				std::stringstream().swap(ss);
			}
		}
		envp.push_back(strdup(ss.str().data()));
		envp.push_back(nullptr);

		signal(SIGCHLD, SIG_IGN);

		pid = fork();

		if (pid == 0)
		{
			// close all fd in the forked child.
			int fdlimit = (int)sysconf(_SC_OPEN_MAX);
			for (int i = STDERR_FILENO + 1; i < fdlimit; i++)
				close(i);

			if (user != "")
			{
				if (ImpersonateUser(user.data(), NULL, 0, NULL) == -1)
				{
					printf("error on impersonating user %s, error :%d\n", user.data(), errno);
					_exit(1);
				}
			}

			if (execve(*argv, argv, envp.data()) == -1)
			{
				printf("error on execve: %d\n", errno);
				_exit(1);
			}
		}
		else
		{
			for (auto env_var : envp)
			{
				free(env_var);
			}
			result = true;
		}
	}
#endif
	return result;
}
#endif

} // namespace bse_utils

namespace cloud
{

namespace platform
{

class workspace;
class workgroups;
class workspaces;

namespace output_formating
{

enum class options
{
	complete,
	essential
};

}
void to_json(json& j, const workspace& value);
void from_json(const json& j, workspace& value);

void to_json(json& j, const workgroups& v);
void from_json(const json& j, workgroups& v);

void to_json(json& j, const workspaces&);
void from_json(const json& j, workspaces&);

class worker
{
public:
	enum class status
	{
		recover,
		starting,
		up,
		drain,
		down
	};

	static std::string to_string(worker::status status)
	{
		switch (status)
		{
			case status::recover:
				return "recover";
			case status::starting:
				return "starting";
			case status::down:
				return "down";
			case status::up:
				return "up";
			case status::drain:
				return "drain";
			default:
				return "-";
		}
	}

private:
	std::string worker_id_{};
	std::string worker_label_{};
	std::string base_url_{};
	std::string version_{};
	std::int32_t process_id_;
	std::chrono::steady_clock::time_point startup_t0_;
	std::chrono::steady_clock::time_point startup_t1_{};

	std::atomic<status> status_{ status::down };
	json worker_metrics_{};
	http::async::upstreams::upstream* upstream_{ nullptr };

public:
	worker(
		std::string worker_id,
		std::string worker_label,
		std::string base_url = "",
		std::string version = "",
		std::int32_t process_id = 0)
		: worker_id_(worker_id)
		, worker_label_(worker_label)
		, base_url_(base_url)
		, version_(version)
		, process_id_(process_id)
		, startup_t0_(std::chrono::steady_clock::now())
		, status_(worker::status::starting)
	{
	}

	worker(const worker& worker)
		: worker_id_(worker.worker_id_)
		, worker_label_(worker.worker_label_)
		, base_url_(worker.base_url_)
		, version_(worker.version_)
		, process_id_(worker.process_id_)
		, startup_t0_(worker.startup_t0_)
		, status_(worker.status_.load())
	{
	}

	virtual ~worker() { worker_metrics_.clear(); }

	void upstream(http::async::upstreams::upstream& upstream) { upstream_ = &upstream; }
	const http::async::upstreams::upstream& upstream() const { return *upstream_; }

	const std::string& get_base_url() const { return base_url_; }
	const std::string& worker_label() const { return worker_label_; }

	void worker_label(const std::string& level) { worker_label_ = level; }

	int get_process_id() const { return process_id_; };

	status get_status() const { return status_; }
	void set_status(status s)
	{
		if (status_ == status::starting && (s == status::up || s == status::recover))
		{
			startup_t1_ = std::chrono::steady_clock::now();
		}
		else if (s == status::drain)
		{
			upstream_->set_state(http::async::upstreams::upstream::state::drain);
		}

		status_ = s;
	};

	void from_json(const json& worker_json)
	{
		process_id_ = worker_json.value("process_id", 0);
		base_url_ = worker_json.value("base_url", "");
		version_ = worker_json.value("version", "");
		worker_label_ = worker_json.value("worker_label", "");
	}

	void to_json(json& worker_json, output_formating::options) const
	{
		if (!base_url_.empty())
		{
			worker_json["link_to_status_url"] = base_url_ + "/internal/platform/worker/status";
			worker_json["base_url"] = base_url_;
			worker_json["version"] = version_;

			if (worker_metrics_.is_null() == false && worker_metrics_.size())
				for (auto metric = std::begin(worker_metrics_["metrics"]);
					 metric != std::end(worker_metrics_["metrics"]);
					 metric++)
					worker_json["metrics"][metric.key()] = metric.value();
		}
		worker_json["status"] = worker::to_string(get_status());
		worker_json["process_id"] = process_id_;
		worker_json["worker_id"] = worker_id_;
		worker_json["worker_label"] = worker_label_;

		if (status_ != status::down)
		{
			worker_json["startup_latency"]
				= std::chrono::duration_cast<std::chrono::milliseconds>(startup_t1_ - startup_t0_).count();

			worker_json["runtime"]
				= std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - startup_t1_)
					  .count();
		}
	}

	int runtime() const
	{
		auto ret
			= std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - startup_t1_).count();

		return ret;
	}

	json get_worker_metrics(void) { return worker_metrics_; }
	void set_worker_metrics(json& j) { worker_metrics_ = std::move(j); }
};

//
// Implementor
//
class workgroups
{
public:
	class limits;
	using container_type = std::map<const std::string, worker>;
	using iterator = container_type::iterator;
	using const_iterator = container_type::const_iterator;

	workgroups(const std::string& workspace_id, const std::string& type)
		: workspace_id_(workspace_id), type_(type)
	{
	}

	virtual ~workgroups() = default;

	iterator begin() { return workers_.begin(); }
	iterator end() { return workers_.end(); }
	const_iterator cbegin() const { return workers_.cbegin(); }
	const_iterator cend() const { return workers_.cend(); }

	void cleanup(){};

	http::async::upstreams upstreams_;

	bool has_workers_available() { return limits_.workers_actual() > 0; }

	iterator find_worker(const std::string& worker_id)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		return workers_.find(worker_id);
	}

	void add_pending_worker(const std::string& worker_id, const std::string& worker_label_selected)
	{
		workers_.emplace(std::pair<const std::string, worker>(worker_id, worker{ worker_id, worker_label_selected }));
	}

	void add_worker(
		const std::string& worker_id, const std::string& worker_label, const json& j, asio::io_context& io_context)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		std::int32_t process_id;
		std::string base_url;
		std::string version;

		process_id = j.value("process_id", 0);
		base_url = j.value("base_url", "");
		version = j.value("version", "");

		auto new_worker = workers_.emplace(std::pair<const std::string, worker>(
			worker_id, worker{ worker_id, worker_label, base_url, version, process_id }));

		if (new_worker.second == false) new_worker.first->second.from_json(j);

		if (base_url.empty() == false)
		{
			limits_.workers_actual_upd(1);
			auto& upstream = upstreams_.add_upstream(
				io_context, base_url, "/" + name_ + "/" + type_ + "/" + worker_id + "_" + worker_label);

			new_worker.first->second.upstream(upstream);
			new_worker.first->second.set_status(worker::status::up);
		}
	}

	bool delete_worker(const std::string& id)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		bool result = false;

		auto worker = workers_.find(id);
		if (worker != workers_.end())
		{
			if (worker->second.get_base_url().empty() == false)
			{
				worker->second.set_status(worker::status::drain);

				if (worker->second.upstream().connections_busy_.load() == 0)
					worker->second.set_status(worker::status::down);

				//				upstreams_.erase_upstream(worker->second.get_base_url());
				//				limits_.workers_actual_upd(-1);
			}
			//			worker = workers_.erase(worker);
			result = true;
		}

		return result;
	}

	bool delete_worker_process(const std::string& id)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		bool result = false;

		auto worker = workers_.find(id);

		if (worker != workers_.end())
		{
			std::string ec;
			auto response = http::client::request<http::method::delete_>(
				worker->second.get_base_url() + "/internal/platform/worker/process", ec, {});

			if (response.status() == http::status::no_content)
			{
				worker->second.set_status(worker::status::down);
				result = true;
			}
		}
		return result;
	}
public:

	using route_methods_type = std::vector<http::method::method_t>;
	using route_path_type = std::vector<std::string>;
	using route_headers_type = std::vector<http::field<std::string>>;

private:
	route_methods_type methods_;
	route_path_type paths_;
	route_headers_type headers_;

public:
	const route_path_type& paths() const { return paths_; }
	const route_headers_type& headers() const { return headers_; }
	const route_methods_type& methods() const { return methods_; }

	const std::string& get_type(void) const { return type_; }
	const std::string& get_name(void) const { return name_; }


	virtual void from_json(const json& j)
	{
		name_ = j.value("name", "anonymous");


        //"routes" : {
        //    "headers" : [ {"X-Infor-Tenant-Id" : "tenant100_tst"} ],
        //    "paths": [ "/api", "/internal" ]
        //},

		if (j.contains("routes"))
		{
			if (j["routes"].contains("headers"))
			{
				for (auto& header : j["routes"]["headers"].items())
				{
					for (auto& header_value : header.value())
						headers_.emplace_back(header.key(), header_value);
				}
			}

			if (j["routes"].contains("paths"))
			{
				for (auto& path : j["routes"]["paths"].items())
					paths_.emplace_back(path.value());
			}

			if (j["routes"].contains("methods"))
			{
				for (auto& method : j["routes"]["methods"].items())
					methods_.emplace_back(http::method::to_method(util::to_upper(method.value())));
			}

		}
		

		if (j.contains("limits")) limits_.from_json(j["limits"]);
	}

	virtual void from_json(const json& j, const std::string& detail) = 0;
	virtual void to_json(json& j, const std::string& detail) const = 0;

	virtual void to_json(json& j, output_formating::options options) const
	{
		j["name"] = name_;
		j["type"] = type_;

		json limits_json;
		limits_.to_json(limits_json, options);
		j["limits"] = limits_json;
		j["workers"] = json::array();

		if (paths_.empty() == false)
		{
			for (const auto& paths : paths_)
				j["routes"]["paths"].emplace_back(paths);
		}

		if (headers_.empty() == false)
		{
			for (const auto& header : headers_)
				j["routes"]["headers"][header.name].emplace_back(header.value);
		}

		if (methods_.empty() == false)
		{
			for (const auto& method : methods_)
				j["routes"]["methods"].emplace_back(http::method::to_string(method));
		}

		// if (options == output_formating::options::complete)
		{
			std::lock_guard<std::mutex> g{ workers_mutex_ };
			for (auto worker = workers_.cbegin(); worker != workers_.cend(); ++worker)
			{
				json worker_json;

				worker->second.to_json(worker_json, options);

				j["workers"].emplace_back(worker_json);
			}
		}
	}

	virtual bool create_worker_process(
		const std::string& manager_endpoint,
		const std::string& workspace_id,
		const std::string& worker_type,
		const std::string& worker_name,
		std::uint32_t& pid,
		std::string& worker_id,
		const std::string& worker_label,
		std::string& ec)
		= 0;

	void cleanup_all_workers(void)
	{
		for (auto in = workers_.begin(); in != workers_.end();)
		{
			in = workers_.erase(in);
		}
	}

	void remove_deleted_workers(void)
	{
		for (auto in = workers_.begin(); in != workers_.end();)
		{
			if (in->second.get_status() == worker::status::drain)
			{
				in = workers_.erase(in);
			}
			else
				in++;
		}
	}

	class limits
	{
	public:
		std::int16_t workers_pending() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_pending_;
		}
		std::int16_t workers_required() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_required_;
		}
		std::int16_t workers_required_to_add() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_required_ - (workers_actual_ + workers_pending_);
		}
		std::int16_t workers_actual() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_actual_;
		}
		std::int16_t workers_start_at_once_max()
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_start_at_once_max_;
		}
		std::int16_t workers_min() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_min_;
		}

		std::int16_t workers_runtime_max() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_runtime_max_;
		}

		std::int16_t workers_requests_max() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_requests_max_;
		}

		std::int16_t workers_max() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_max_;
		}
		const std::string& workers_label_actual() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_label_actual_;
		}
		const std::string& workers_label_required() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_label_required_;
		}

		void workers_pending_upd(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_pending_ += value;
		}

		void workers_required(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_required_ = value;
		}
		void workers_required_upd(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_required_ += value;
		}
		void workers_actual(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_actual_ = value;
		}
		void workers_actual_upd(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			if (value > 0 && workers_pending_) workers_pending_ -= value;

			workers_actual_ += value;
		}
		void workers_min(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_min_ = value;
		}
		void workers_max(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_max_ = value;
		}

		void workers_label_required(const std::string& value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_label_required_ = value;
		}
		void workers_label_actual(const std::string& value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_label_actual_ = value;
		}

		void workers_not_on_label_required(std::int16_t value) { workers_not_on_label_required_ = value; }

		void workers_start_at_once_max(std::int16_t value)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			workers_start_at_once_max_ = value;
		}

		enum class from_json_operation
		{
			ignore,
			add,
			set
		};

		void from_json(
			const json& j, const std::string& limit_name = "", from_json_operation method = from_json_operation::set)
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			if (method == from_json_operation::set)
			{
				if (limit_name.empty() || limit_name == "workers_required")
					workers_required_ = j.value("workers_required", workers_min_);

				if (limit_name.empty() || limit_name == "workers_min")
					workers_min_ = j.value("workers_min", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_max")
					workers_max_ = j.value("workers_max", workers_min_);

				if (limit_name.empty() || limit_name == "workers_runtime_max")
					workers_runtime_max_ = j.value("workers_runtime_max", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_requests_max")
					workers_requests_max_ = j.value("workers_requests_max", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_label_required")
					workers_label_required_ = j.value("workers_label_required", "unknown");

				if (limit_name.empty() || limit_name == "workers_start_at_once_max")
					workers_start_at_once_max_ = j.value("workers_start_at_once_max", std::int16_t{ 4 });
			}
			else
			{
				if (limit_name.empty() || limit_name == "workers_required")
					workers_required_ += j.value("workers_required", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_min")
					workers_min_ += j.value("workers_min", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_max")
					workers_max_ += j.value("workers_max", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_runtime_max")
					workers_runtime_max_ += j.value("workers_runtime_max", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_requests_max")
					workers_requests_max_ += j.value("workers_requests_max", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_label_required")
					workers_label_required_ = j.value("workers_label_required", "unknown");

				if (limit_name.empty() || limit_name == "workers_start_at_once_max")
					workers_start_at_once_max_ += j.value("workers_start_at_once_max", std::int16_t{ 4 });
			}

			if (workers_min_ > workers_max_) workers_min_ = workers_max_;
			if (workers_max_ < workers_min_) workers_max_ = workers_min_;
			if (workers_required_ > workers_max_) workers_required_ = workers_max_;
			if (workers_required_ < workers_min_) workers_required_ = workers_min_;
		}

		void to_json(json& j, output_formating::options options, const std::string& limit_name = "") const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };

			if (limit_name.empty() || limit_name == "workers_required")
			{
				j["workers_required"] = workers_required_;
			}
			if (limit_name.empty() || limit_name == "workers_min")
			{
				j["workers_min"] = workers_min_;
			}
			if (limit_name.empty() || limit_name == "workers_max")
			{
				j["workers_max"] = workers_max_;
			}
			if (limit_name.empty() || limit_name == "workers_runtime_max")
			{
				j["workers_runtime_max"] = workers_runtime_max_;
			}
			if (limit_name.empty() || limit_name == "workers_requests_max")
			{
				j["workers_requests_max"] = workers_requests_max_;
			}
			if (limit_name.empty() || limit_name == "workers_start_at_once_max")
			{
				j["workers_start_at_once_max"] = workers_start_at_once_max_;
			}
			if (limit_name.empty() || limit_name == "workers_label_required")
			{
				j["workers_label_required"] = workers_label_required_;
			}

			if (options != output_formating::options::essential)
			{
				if (limit_name.empty() || limit_name == "workers_actual")
				{
					j["workers_actual"] = workers_actual_;
				}
				if (limit_name.empty() || limit_name == "workers_label_actual")
				{
					j["workers_label_actual"] = workers_label_actual_;
				}

				if (limit_name.empty() || limit_name == "workers_pending")
				{
					j["workers_pending"] = workers_pending_;
				}
				if (limit_name.empty() || limit_name == "workers_not_at_label_required")
				{
					j["workers_not_at_label_required"] = workers_not_on_label_required_;
				}
			}
		}

	private:
		std::int16_t workers_pending_{ 0 };
		std::int16_t workers_required_{ 0 };
		std::int16_t workers_actual_{ 0 };
		std::int16_t workers_not_on_label_required_{ 0 };

		std::int16_t workers_min_{ 0 };
		std::int16_t workers_max_{ 0 };

		std::string workers_label_required_{};
		std::string workers_label_actual_{};

		std::int16_t workers_runtime_max_{ 0 };
		std::int16_t workers_requests_max_{ 0 };

		std::int16_t workers_start_at_once_max_{ 4 };
		mutable std::mutex limits_mutex_;
	};

	limits& workgroups_limits() { return limits_; }

	virtual void direct_workers(
		asio::io_context& io_context,
		const http::configuration& configuration,
		lgr::logger& logger,
		const std::string& = std::string{},
		const json& limits_adjustments = json{},
		workgroups::limits::from_json_operation = workgroups::limits::from_json_operation::ignore)
		= 0;

protected:
	std::string name_;
	std::string workspace_id_;
	std::string type_;

	limits limits_;

	container_type workers_;
	mutable std::mutex workers_mutex_;
};

class bshell_workgroups : public workgroups
{

private:
	std::string bse_;
	std::string bse_bin_;
	std::string bse_user_;
	std::string os_user_;
	std::string os_password_;
	std::string program_;
	std::string cli_options_;
	std::string http_options_;

public:
	bshell_workgroups(const std::string& workspace_id, const json& worker_type_json)
		: workgroups(workspace_id, worker_type_json["type"])
	{
		from_json(worker_type_json);
	}

	virtual void direct_workers(
		asio::io_context& io_context,
		const http::configuration& configuration,
		lgr::logger& logger,
		const std::string& limit_name,
		const json& limits_adjustments,
		workgroups::limits::from_json_operation operation) override
	{
		bool rescan{ false };
		std::string ec{};
		std::string server_endpoint
			= configuration.get<std::string>("http_this_server_local_url", "http://localhost:4000");

		server_endpoint += "/internal/platform/manager/workspaces";

		std::unique_lock<std::mutex> lock{ workers_mutex_ };

		if (limits_adjustments.contains("limits") == true)
		{
			auto workers_required = limits_.workers_required();
			auto workers_min = limits_.workers_min();

			limits_.from_json(limits_adjustments["limits"], limit_name, operation);

			if (limits_.workers_required() - workers_required > 4) return;

			if (limits_.workers_min() - workers_min > 4) return;
		}

		do
		{
			auto workers_required_to_add = limits_.workers_required_to_add();
			auto workers_label_required = limits_.workers_label_required();
			auto workers_runtime_max = limits_.workers_runtime_max();
			auto workers_requests_max = limits_.workers_requests_max();

			if (limits_.workers_required() > 0)
			{
				logger.api(
					"/{s}/{s}/{s} actual: {d}, pending: {d}, required: {d}, min: {d}, max: {d}, label_actual: {s}, "
					"label_required: {s}\n",
					workspace_id_,
					type_,
					name_,
					limits_.workers_actual(),
					limits_.workers_pending(),
					limits_.workers_required(),
					limits_.workers_min(),
					limits_.workers_max(),
					limits_.workers_label_actual(),
					workers_label_required);
			}

			if (rescan) rescan = false;

			for (std::int16_t n = 0; n < workers_required_to_add; n++)
			{
				std::uint32_t process_id = 0;
				std::string worker_id;
				lock.unlock();
				bool success = create_worker_process(
					server_endpoint, workspace_id_, type_, name_, process_id, worker_id, workers_label_required, ec);

				lock.lock();
				if (!success) // todo
				{
					logger.api(
						"/{s}/{s}/{s} new worker process ({d}/{d}), failed to start proces: {s}\n",
						workspace_id_,
						type_,
						name_,
						1 + n,
						workers_required_to_add,
						ec);
				}
				else
				{
					logger.api(
						"/{s}/{s}/{s} new worker process ({d}/{d}), processid: {d}, worker_id: {s}\n",
						workspace_id_,
						type_,
						name_,
						1 + n,
						workers_required_to_add,
						static_cast<int>(process_id),
						worker_id);

					add_pending_worker(worker_id, workers_label_required);

					limits_.workers_pending_upd(1);
				}
			}

			if (workers_required_to_add < 0)
			{
				for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
				{
					if (worker_it->second.get_base_url().empty()
						|| worker_it->second.get_status() == worker::status::recover)
					{
						++worker_it;
						continue;
					}
					auto& worker = worker_it->second;
					auto worker_label = worker_it->second.worker_label();
					auto worker_runtime = worker_it->second.runtime();
					auto worker_requests = worker_it->second.upstream().responses_tot_.load();

					if ((worker_label != workers_label_required)
						|| ((workers_requests_max > 1) && (worker_requests >= workers_requests_max))
						|| ((workers_runtime_max > 1) && (worker_runtime >= workers_runtime_max))
						|| (worker_it == workers_.begin()))
					{
						http::headers watchdog_headers{ { "Host", "localhost" } };

						std::string base_url = worker_it->second.get_base_url();

						http::client::async_request<http::method::delete_>(
							upstreams_,
							worker_it->second.get_base_url(),
							"/internal/platform/worker/process",
							watchdog_headers,
							std::string{},
							[this, base_url, &logger](http::response_message& response, asio::error_code& error_code) {
								if (!error_code
									&& (response.status() == http::status::ok
										|| response.status() == http::status::no_content
#ifdef LOCAL_TESTING
										|| response.status() == http::status::method_not_allowed) // nginx test setup returns this
#endif //  LOCAL_TESTING
								)
								{
									logger.api(
										"/{s}/{s}/{s}: process deleted for {s}\n",
										workspace_id_,
										type_,
										name_,
										base_url);
								}
								else if (
									error_code
									|| (response.status() != http::status::ok
										&& response.status() != http::status::no_content))
								{
									logger.api(
										"/{s}/{s}/{s}: failed to delete process {s}\n",
										workspace_id_,
										type_,
										name_,
										base_url);
								}

								return;
							});

						worker.set_status(worker::status::drain);
						workers_required_to_add++;

						if (workers_required_to_add == 0)
						{
							break;
						}
					}
					++worker_it;
				}
			}

			if (limits_adjustments.contains("limits") == false)
			{
				std::int16_t workers_watchdogs_feeded = 0;
				std::int16_t workers_on_label_required = 0;
				std::int16_t workers_not_on_label_required = 0;
				std::int16_t workers_runtime_max_reached = 0;
				std::int16_t workers_responses_max_reached = 0;

				for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
				{
					if (worker_it->second.get_base_url().empty())
					{
						++worker_it;
						continue;
					}

					auto& worker = worker_it->second;

					auto worker_label = worker_it->second.worker_label();

					if (worker_it->second.get_status() == worker::status::up
						|| worker_it->second.get_status() == worker::status::starting)
					{
						if (worker_label != workers_label_required)
						{
							workers_not_on_label_required++;
						}
						else
						{
							workers_on_label_required++;

							if (worker.upstream().responses_tot_.load() >= workers_requests_max)
							{
								workers_responses_max_reached++;
							}
							else if (worker.runtime() >= workers_runtime_max)
							{
								workers_runtime_max_reached++;
							}
						}

						if (worker_label != limits_.workers_label_actual()) limits_.workers_label_actual(worker_label);
					}

					if (worker_it->second.get_status() == worker::status::recover)
					{
						auto& upstream = upstreams_.add_upstream(
							io_context,
							worker_it->second.get_base_url(),
							"/" + name_ + "/" + type_ + "/" + worker_it->first + "/"
								+ worker_it->second.worker_label());

						worker_it->second.upstream(upstream);

						worker_it->second.set_status(worker::status::up);
					}

					if (worker_it->second.get_status() == worker::status::up)
					{
						auto workers_feed_watchdog = workers_watchdogs_feeded++ < limits_.workers_min();

						http::headers watchdog_headers{
							{ "Host", "localhost" }, { "X-Feed-Watchdog", workers_feed_watchdog ? "true" : "false" }
						};

						http::client::async_request<http::method::post>(
							upstreams_,
							worker_it->second.get_base_url(),
							"/internal/platform/worker/watchdog",
							watchdog_headers,
							std::string{},
							[this, &worker, &logger](http::response_message& response, asio::error_code& error_code) {
								if (!error_code
									&& (response.status() == http::status::ok
										|| response.status() == http::status::no_content)
									&& worker.get_status() != worker::status::up)
								{
									worker.set_status(worker::status::up);
								}
								else if (
									error_code
									|| (response.status() != http::status::ok
										&& response.status() != http::status::no_content))
								{
									worker.set_status(worker::status::drain);
									logger.api(
										"/{s}/{s}/{s}: failed health check for worker {s}\n",
										workspace_id_,
										type_,
										name_,
										worker.get_base_url());
								}

								return;
							});
					}

					++worker_it;
				}

				auto workers_to_start = workers_not_on_label_required;
				limits_.workers_not_on_label_required(workers_not_on_label_required);

				if (workers_on_label_required + limits_.workers_pending() != limits_.workers_required())
				{
					workers_to_start = workers_not_on_label_required;
				}
				else if (workers_requests_max > 0 && workers_responses_max_reached > 0)
				{
					workers_to_start = workers_responses_max_reached;
				}
				else if (workers_runtime_max_reached > 0 && workers_runtime_max_reached > 0)
				{
					workers_to_start = workers_runtime_max_reached;
				}

				if (workers_to_start > limits_.workers_start_at_once_max())
					workers_to_start = limits_.workers_start_at_once_max();

				for (std::int16_t n = 0; n < workers_to_start; n++)
				{
					std::uint32_t process_id = 0;
					std::string worker_id;
					lock.unlock();
					bool success = create_worker_process(
						server_endpoint,
						workspace_id_,
						type_,
						name_,
						process_id,
						worker_id,
						workers_label_required,
						ec);

					lock.lock();
					if (!success) // todo
					{
						logger.api(
							"/{s}/{s}/{s} new worker process ({d}/{d}), failed to start proces: {s}\n",
							workspace_id_,
							type_,
							name_,
							1 + n,
							workers_required_to_add,
							ec);
					}
					else
					{
						logger.api(
							"/{s}/{s}/{s} new worker process ({d}/{d}), processid: {d}, worker_id: {s}\n",
							workspace_id_,
							type_,
							name_,
							1 + n,
							workers_required_to_add,
							static_cast<int>(process_id),
							worker_id);

						add_pending_worker(worker_id, workers_label_required);
					}
				}

				for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
				{
					if (worker_it->second.get_status() == worker::status::drain)
					{
						if (worker_it->second.upstream().connections_busy_.load() == 0)
							worker_it->second.set_status(worker::status::down);
					}

					if (worker_it->second.get_status() == worker::status::down)
					{
						logger.api(
							"/{s}/{s}/{s} delete {s} {s}\n",
							workspace_id_,
							type_,
							name_,
							worker_it->first,
							worker_it->second.get_base_url());

						upstreams_.erase_upstream(worker_it->second.get_base_url());
#ifdef LOCAL_TESTING
						bse_utils::local_testing::_test_sockets.release(workspace_id_, worker_it->second.get_base_url());
#endif
						worker_it = workers_.erase(workers_.find(worker_it->first));

						limits_.workers_actual_upd(-1);
					}
					else
						worker_it++;
				}
			}

		} while (rescan);
	};

	void from_json(const json& j) override
	{
		std::unique_lock<std::mutex> guard(workgroups::workers_mutex_);

		workgroups::from_json(j);
		try
		{ // TODO optional parameters bse, bse_bin, bse_user, os_user and os_password.
			j["parameters"].at("bse").get_to(bse_);
			j["parameters"].at("bse_bin").get_to(bse_bin_);
			j["parameters"].at("bse_user").get_to(bse_user_);
			j["parameters"].at("os_user").get_to(os_user_);
			j["parameters"].at("os_password").get_to(os_password_);
			j["parameters"].at("cli_options").get_to(cli_options_);
			j["parameters"].at("http_options").get_to(http_options_);
			j["parameters"].at("program").get_to(program_);
		}
		catch (json::exception&)
		{
		}

		std::int16_t workers_added = 0;

		if (j.contains("workers"))
		{
			for (const auto& worker_json : j["workers"].items())
			{
				auto worker_id = worker_json.value().value("worker_id", "");

				if (worker_id.empty() == false)
				{
					auto id = util::split(worker_id, "_");
					worker_ids_begin(std::atoi(id[1].c_str()));
				}

				auto worker_label = worker_json.value().value("worker_label", "");
				auto process_id = worker_json.value().value("process_id", 1234);
				auto base_url = worker_json.value().value("base_url", "");

#if defined(LOCAL_TESTING)
				if (base_url.empty() == false)
				{
					auto base_url_split = util::split(base_url, ":");
					auto port = std::atoi(base_url_split[2].c_str());

					bse_utils::local_testing::_test_sockets.aquire(workspace_id_, port);
				}
#endif

				auto version = worker_json.value().value("version", "");
				auto status = worker_json.value().value("status", "");

				if (status == "up")
				{
					auto new_worker = workers_.emplace(std::pair<const std::string, worker>(
						worker_id, worker{ worker_id, worker_label, base_url, version, process_id }));

					if (new_worker.second) new_worker.first->second.set_status(worker::status::recover);

					workers_added++;
				}
			}
		}

		limits_.workers_actual_upd(workers_added);
	}

	void from_json(const json& j, const std::string& detail) override
	{
		std::unique_lock<std::mutex> guard(workgroups::workers_mutex_);
		if (detail.empty() || (detail == "bse")) bse_ = j["parameters"].value("bse", "");
		if (detail.empty() || (detail == "bse_bin")) bse_bin_ = j["parameters"].value("bse_bin", "");
		if (detail.empty() || (detail == "bse_user")) bse_user_ = j["parameters"].value("bse_user", "");
		if (detail.empty() || (detail == "os_user")) os_user_ = j["parameters"].value("ose_user", "");
		if (detail.empty() || (detail == "os_password")) os_password_ = j["parameters"].value("os_password", "");
		if (detail.empty() || (detail == "program")) program_ = j["parameters"].value("program", "");
		if (detail.empty() || (detail == "cli_options")) cli_options_ = j["parameters"].value("cli_options", "");
		if (detail.empty() || (detail == "http_options")) http_options_ = j["parameters"].value("http_options", "");
	}

	void to_json(json& j, const std::string& detail) const override
	{
		std::unique_lock<std::mutex> guard(workgroups::workers_mutex_);
		if (detail.empty() || ((detail == "bse") && (bse_.empty() == false))) j["parameters"].emplace("bse", bse_);

		if (detail.empty() || ((detail == "bse_user") && (bse_bin_.empty() == false)))
			j["parameters"].emplace("bse_bin", bse_bin_);

		if (detail.empty() || ((detail == "bse_user") && (bse_user_.empty() == false)))
			j["parameters"].emplace("bse_user", bse_user_);

		if (detail.empty() || ((detail == "os_user") && (os_user_.empty() == false)))
			j["parameters"].emplace("os_user", os_user_);

		if (detail.empty() || ((detail == "os_password") && (os_password_.empty() == false)))
			j["parameters"].emplace("os_password", os_password_);

		if (detail.empty() || detail == "program") j["parameters"].emplace("program", program_);

		if (detail.empty() || detail == "cli_options") j["parameters"].emplace("cli_options", cli_options_);

		if (detail.empty() || detail == "http_options") j["parameters"].emplace("http_options", http_options_);
	}

	void to_json(json& j, output_formating::options options) const override
	{
		workgroups::to_json(j, options);

		std::unique_lock<std::mutex> guard(workgroups::workers_mutex_);
		if (bse_.empty() == false) j["parameters"].emplace("bse", bse_);

		if (bse_bin_.empty() == false) j["parameters"].emplace("bse_bin", bse_bin_);

		if (bse_user_.empty() == false) j["parameters"].emplace("bse_user", bse_user_);

		if (os_user_.empty() == false) j["parameters"].emplace("os_user", os_user_);

		if (os_password_.empty() == false) j["parameters"].emplace("os_password", os_password_);

		j["parameters"].emplace("program", program_);
		j["parameters"].emplace("cli_options", cli_options_);
		j["parameters"].emplace("http_options", http_options_);
	}

	std::atomic<std::uint32_t> worker_ids_{ 0 };

	void worker_ids_begin(std::uint32_t id) { worker_ids_ = worker_ids_.load() <= id ? id + 1 : worker_ids_.load(); }

public:
	bool create_worker_process(
		const std::string& manager_endpoint,
		const std::string& workspace_id,
		const std::string& worker_type,
		const std::string& worker_name,
		std::uint32_t& pid,
		std::string& worker_id,
		const std::string& worker_label,
		std::string& ec) override
	{
		std::unique_lock<std::mutex> guard(workgroups::workers_mutex_);
		std::stringstream parameters;

		worker_id = "worker_" + std::to_string(worker_ids_++);

		parameters << "-httpserver_options cld_manager_endpoint:" << manager_endpoint
				   << ",cld_workgroup_membership_type:worker,cld_manager_workspace:" << workspace_id
				   << ",cld_worker_id:" << worker_id << ",cld_worker_label:" << worker_label
				   << ",cld_manager_workgroup:" << worker_name << "/" << worker_type;

		if (!http_options_.empty())
			parameters << "," << http_options_ << " ";
		else if (!cli_options_.empty())
			parameters << " ";

		parameters << cli_options_;

		return bse_utils::create_bse_process_as_user(
			bse_,
			bse_bin_,
			os_user_,
			os_password_,
			bse_bin_ + (bse_bin_ != "" ? "/" : "") + program_ + std::string{ " " } + parameters.str(),
			pid,
			ec);
	}
};

class python_workgroups : public workgroups
{
private:
	std::string rootdir;

public:
	python_workgroups(const std::string& workspace_id, const json& worker_type_json)
		: workgroups(workspace_id, "python"), rootdir()
	{
		from_json(worker_type_json);
	}

	virtual ~python_workgroups(){};

	void from_json(const json& j) override
	{
		workgroups::from_json(j);
		json d(j.at("parameters"));
		d.at("python_root").get_to(rootdir);
	}

	void from_json(const json& j, const std::string& detail) override
	{
		if (detail.empty() || detail == "python_root") rootdir = j["parameters"].value("python_root", "");
	};

	void to_json(json& j, const std::string& detail) const override
	{
		if (detail.empty() || detail == "python_root") j["parameters"].emplace("python_root", rootdir);
	}

	void to_json(json& j, output_formating::options options) const override
	{
		workgroups::to_json(j, options);
		j["parameters"].emplace("python_root", rootdir);
	}

	virtual void direct_workers(
		asio::io_context&,
		const http::configuration&,
		lgr::logger&,
		const std::string&,
		const json&,
		workgroups::limits::from_json_operation) override{};

	virtual bool create_worker_process(
		const std::string&,
		const std::string&, // workspace_id,
		const std::string&, // worker_type,
		const std::string&, // worker_name,
		std::uint32_t&, // pid,
		std::string&,
		const std::string&,
		std::string&) override
	{
		return false;
	};
};

class workspace
{
public:
	using key_type = std::pair<std::string, std::string>;
	using value_type = std::unique_ptr<workgroups>;
	using container_type = std::map<key_type, value_type>;
	using iterator_type = container_type::iterator;
	using const_iterator_type = container_type::const_iterator;
	using route_methods_type = std::vector<http::method::method_t>;
	using route_path_type = std::vector<std::string>;
	using route_headers_type = std::vector<http::field<std::string>>;

private:
	std::string server_endpoint_;
	std::string workspace_id_{};
	std::string tenant_id_{};
	std::string description_{};

	route_methods_type methods_;
	route_path_type paths_;
	route_headers_type headers_;

public:
	const route_path_type& paths() const { return paths_; }
	const route_headers_type& headers() const { return headers_; }
	const route_methods_type& methods() const { return methods_; }

	container_type workgroups_;

public:
	workspace(const std::string workspace_id, const json& json_workspace) : workspace_id_(workspace_id)
	{
		from_json(json_workspace);
	}

	workspace(const workspace&) = delete;

	const std::string& get_workspace_id(void) const { return workspace_id_; };
	void set_workspace_id(const std::string& workspace_id) { workspace_id_ = workspace_id; };

	const std::string& get_description(void) const { return description_; };
	const std::string& get_tenant_id(void) const { return tenant_id_; };

public:
	void to_json(json& workspace, output_formating::options options = output_formating::options::complete) const
	{
		workspace["id"] = workspace_id_;
		workspace["description"] = description_;

		if (paths_.empty() == false)
		{
			for (const auto& paths : paths_)
				workspace["routes"]["paths"].emplace_back(paths);
		}

		if (methods_.empty() == false)
		{
			for (const auto& method : methods_)
				workspace["routes"]["methods"].emplace_back(http::method::to_string(method));
		}

		if (headers_.empty() == false)
		{
			for (auto& header : headers_)
				workspace["routes"]["headers"][header.name].emplace_back(header.value);
		}

		json workgroups_json;

		for (auto& named_worker : workgroups_)
		{
			json named_worker_json = json::object();

			named_worker.second->to_json(named_worker_json, options);

			workgroups_json.emplace_back(named_worker_json);
		}
		workspace["workgroups"] = workgroups_json;
	}

private:
	std::unique_ptr<workgroups>
	create_workgroups_from_json(const std::string& type, const json& worker_type_json)
	{
		if (type == "bshells")
			return std::unique_ptr<workgroups>{ new bshell_workgroups{ workspace_id_, worker_type_json } };
		if (type == "ashells")
			return std::unique_ptr<workgroups>{ new bshell_workgroups{ workspace_id_, worker_type_json } };
		if (type == "python-scripts")
			return std::unique_ptr<workgroups>{ new python_workgroups{ workspace_id_, worker_type_json } };
		else
			return nullptr;
	}

public:
	iterator_type find_workgroups(const json& j)
	{
		std::string workgroups_name{};
		std::string workgroups_type{};

		j.at("type").get_to(workgroups_type);

		if (j.find("name") != j.end())
		{
			j.at("name").get_to(workgroups_name);

			return find_workgroups(workgroups_name, workgroups_type);
		}

		return end();
	}

	iterator_type end() { return workgroups_.end(); };
	iterator_type begin() { return workgroups_.begin(); }
	const_iterator_type cend() const { return workgroups_.cend(); };
	const_iterator_type cbegin() const { return workgroups_.cbegin(); }

	iterator_type find_workgroups(const std::string& workgroups_name, const std::string& workgroups_type)
	{
		return workgroups_.find(key_type{ workgroups_name, workgroups_type });
	}

	iterator_type find_workgroups(const http::session_handler session)
	{

		auto result = workgroups_.end();

		for (auto workgroup = workgroups_.begin(); workgroup != workgroups_.end(); workgroup++)
		{
			bool methods_match = false;
			bool header_match = false;
			bool path_match = false;

			if (workgroup->second->methods().empty() == false)
			{
				for (const auto& method : methods_)
				{
					if (session.request().method() == method)
					{
						methods_match = true;
						break;
					}
				}
			}
			else
			{
				methods_match = true;
			}

			if (methods_match && workgroup->second->headers().empty() == false)
			{
				for (const auto& header : workgroup->second->headers())
				{
					bool found = false;
					if (session.request().get<std::string>(header.name, found, "") == header.value && found == true)
					{
						header_match = true;
						break;
					}
				}
			}
			else
			{
				header_match = methods_match;
			}

			if (header_match && workgroup->second->paths().empty() == false)
			{
				for (const auto& workspace_path : paths_)
				{
					for (const auto& workgroup_path : workgroup->second->paths())
					{
						if (session.request().url_requested().find(workspace_path + workgroup_path) == 0)
						{
							path_match = true;
							break;
						}
					}
				}
			}
			else
			{
				path_match = header_match && methods_match;
			}

			if (methods_match && header_match && path_match)
			{
				result = workgroup;
				break;
			}
		}

		return result;
	}

	void add_workgroups(const std::string& name, std::string type, json& workgroups_json)
	{
		for (auto workgroups = workgroups_json.begin(); workgroups != workgroups_json.end(); workgroups++)
		{
			(*workgroups)["name"] = name;

			if (!type.empty()) (*workgroups)["type"] = type;

			auto new_workgroups = create_workgroups_from_json((*workgroups)["type"], *workgroups);
			if (new_workgroups)
			{
				this->workgroups_[key_type{ (*workgroups)["name"], (*workgroups)["type"] }] = std::move(new_workgroups);
			}
		}
	}

	iterator_type delete_workgroups(const std::string& name, std::string type)
	{
		return this->workgroups_.erase(this->workgroups_.find(key_type{ name, type }));
	}

	void from_json(const json& j)
	{
		description_ = j.value("description", "");

		if (j.contains("routes"))
		{
			if (j["routes"].contains("headers"))
			{
				for (auto& header : j["routes"]["headers"].items())
				{
					auto key = header.key();
					for (auto& header_value : header.value())
						headers_.emplace_back(header.key(), header_value);
				}
			}

			if (j["routes"].contains("paths"))
			{
				for (auto& path : j["routes"]["paths"].items())
					paths_.emplace_back(path.value());
			}

			if (j["routes"].contains("methods"))
			{
				for (auto& method : j["routes"]["methods"].items())
					methods_.emplace_back(http::method::to_method(util::to_upper(method.value())));
			}
		}

		if (j.find("workgroups") != j.end())
		{
			json json_workgroups = j.at("workgroups");

			for (auto workgroups = json_workgroups.cbegin(); workgroups != json_workgroups.cend(); workgroups++)
			{
				if (workgroups.value().size())
				{
					auto new_workgroups
						= create_workgroups_from_json(workgroups.value()["type"], *workgroups);

					if (new_workgroups)
					{
						this->workgroups_[key_type{ workgroups.value()["name"], workgroups.value()["type"] }]
							= std::move(new_workgroups);
					}
				}
			}
		}
	}
};

inline void to_json(json& j, const workspace& w) { w.to_json(j); }

class workspaces
{
public:
	using value_type = std::unique_ptr<workspace>;
	using container_type = std::map<const std::string, value_type>;

	using iterator = container_type::iterator;
	using const_iterator = container_type::const_iterator;
	using mutex_type = std14::shared_mutex;

private:
	container_type workspaces_;

	std::string port;
	std::string base_path;
	std::string manager_workspace;

	std::atomic<bool> is_changed_{ true };
	mutable std14::shared_mutex workspaces_mutex_;

public:
	iterator end() { return workspaces_.end(); }
	iterator begin() { return workspaces_.begin(); }
	const_iterator cend() const { return workspaces_.cend(); }
	const_iterator cbegin() const { return workspaces_.cbegin(); }

	std::atomic<bool>& is_changed() { return is_changed_; }

	void direct_workspaces(asio::io_context& io_context, const http::configuration& configuration, lgr::logger& logger)
	{
		auto t0 = std::chrono::steady_clock::now();
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };
		for (auto& workspace : workspaces_)
		{
			json empty_limits_adjustments = json::object();
			for (auto& workgroup : *workspace.second)
				workgroup.second->direct_workers(io_context, configuration, logger);
		}
		auto t1 = std::chrono::steady_clock::now();

		auto elapsed = t1 - t0;
		logger.api("{u} workspaces took {d}msec\n", workspaces_.size(), elapsed.count() / 1000000);
	}

public:
	bool add_workspace(const std::string id, const json::value_type& j)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		bool result = false;
		auto i = workspaces_.find(id);

		if (i == workspaces_.end())
		{
			auto new_workspace = workspaces_.insert(container_type::value_type{ id, new workspace{ id, j } });

			result = new_workspace.second; // add_workspace returns true when an inserted happend.
		}

		return result;
	}

	bool delete_workspace(const std::string id)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };
		auto i = workspaces_.find(id);

		if (i == workspaces_.end())
		{
			return false;
		}
		else
		{
			workspaces_.erase(i);
			return true;
		}
	}

	const_iterator get_workspace_(const std::string& id) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };
		return workspaces_.find(id);
	}


	const_iterator find_workspace(const http::session_handler& session) const
	{
		std14::shared_lock<mutex_type> l{ workspaces_mutex_ };
		auto result = workspaces_.cend();

		for (auto workspace = workspaces_.cbegin(); workspace != workspaces_.cend(); workspace++)
		{
			bool methods_match = false;
			bool header_match = false;
			bool path_match = false;

			if (workspace->second->methods().empty() == false)
			{
				for (const auto& method : workspace->second->methods())
				{
					if (session.request().method() == method)
					{
						methods_match = true;
						break;
					}
				}
			}
			else
			{
				methods_match = true;
			}

			if (methods_match && workspace->second->headers().empty() == false)
			{
				for (const auto& header : workspace->second->headers())
				{
					bool found = false;
					if (session.request().get<std::string>(header.name, found, "") == header.value && found == true)
					{
						header_match = true;
						break;
					}
				}
			}
			else
			{
				header_match = methods_match;
			}


			if (header_match && workspace->second->paths().empty() == false)
			{
				for (const auto& workspace_path : workspace->second->paths())
				{
					if (session.request().url_requested().find(workspace_path) == 0)
					{
						path_match = true;
						break;
					}
				}
			}
			else
			{
				path_match = header_match;
			}

			if (methods_match && header_match && path_match)
			{
				result = workspace;
				break;
			}
		}

		return result;
	}

	iterator get_workspace(const std::string& id) { return workspaces_.find(id); }

	void to_json(json& j, output_formating::options options = output_formating::options::complete) const
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };

		j = json::array();

		for (auto& workspace : workspaces_)
		{
			auto workspace_json = json{};
			workspace.second->to_json(workspace_json, options);
			j.emplace_back(workspace_json);
		}
	}

	void from_json(const json& j)
	{
		for (auto& el : j.items())
		{
			add_workspace(el.value()["id"], el.value());
		}
	}
};

inline void to_json(json& j, const workspaces& ws) { ws.to_json(j); }
inline void from_json(const json& j, workspaces& ws) { ws.from_json(j); }

template <typename S> class manager : public S
{
protected:
	using server_base = S;

private:
	workspaces workspaces_;
	std::thread director_thread_;

	std::string configuration_file_;

public:
	manager(http::configuration& http_configuration, const std::string& configuration_file)
		: http::async::server(http_configuration), configuration_file_(configuration_file)
	{
		std::ifstream configuration_stream{ configuration_file_ };

		auto configfile_available = configuration_stream.fail() == false;

		if (configfile_available)
		{
			try
			{
				json manager_configuration_json = json::parse(configuration_stream);
				if (manager_configuration_json.contains("workspaces") == true)
					workspaces_.from_json(manager_configuration_json.at("workspaces"));
			}
			catch (json::exception& e)
			{
				server_base::logger_.api(
					"error when reading configuration ({s}) : {s}\n", configuration_file_, e.what());
				std::cout << "error when reading configuration (" << configuration_file_ << ") : " << e.what()
						  << std::endl;
				exit(-1);
			}
		}
		else
		{
			workspaces_.from_json(json::object());
		}

		server_base::router_.on_get(
			http::server::configuration_.get<std::string>("health_check", "/private/health_check"),
			[this](http::session_handler& session) {
				session.response().assign(http::status::ok, "OK");
				server_base::manager().update_health_check_metrics();
			});

		server_base::router_.on_post("/internal/platform/manager/mirror", [](http::session_handler& session) {
			session.response().status(http::status::ok);
			session.response().type(session.response().get<std::string>("Content-Type", "text/plain"));
			session.response().body() = session.request().body();
		});

		server_base::router_.on_post(
			"/internal/platform/manager/access_log_level", [this](http::session_handler& session) {
				server_base::logger_.set_access_log_level(session.request().body());
				auto new_level = server_base::logger_.current_access_log_level_to_string();
				http::server::configuration_.set("access_log_level", new_level);
				session.response().body() = server_base::logger_.current_access_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_get(
			"/internal/platform/manager/access_log_level", [this](http::session_handler& session) {
				session.response().body() = server_base::logger_.current_access_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_post(
			"/internal/platform/manager/extended_log_level", [this](http::session_handler& session) {
				server_base::logger_.set_extended_log_level(session.request().body());
				auto new_level = server_base::logger_.current_extended_log_level_to_string();
				http::server::configuration_.set("extended_log_level", new_level);
				session.response().body() = server_base::logger_.current_extended_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_get(
			"/internal/platform/manager/extended_log_level", [this](http::session_handler& session) {
				session.response().body() = server_base::logger_.current_extended_log_level_to_string();
				session.response().status(http::status::ok);
			});

		server_base::router_.on_get("/internal/platform/manager/status", [this](http::session_handler& session) {
			const auto& format = session.request().get<std::string>("Accept", "application/json");
			const auto& format_from_query_parameter = session.request().query().get<std::string>("format", "text");

			if (format.find("application/json") != std::string::npos || format_from_query_parameter == "json")
			{
				session.response().assign(
					http::status::ok,
					server_base::manager().to_json(http::server::server_manager::json_status_options::full).dump(),
					"json");
			}
			else
			{
				server_base::manager().server_information(http::server::configuration_.to_string());
				server_base::manager().router_information(server_base::router_.to_string());
				session.response().body() = server_base::manager().to_string();
				session.response().type("text");
			}

			session.response().status(http::status::ok);
		});

		server_base::router_.on_get(
			"/internal/platform/manager/status/{section}", [this](http::session_handler& session) {
				const auto& format = session.request().get<std::string>("Accept", "application/json");
				const auto& format_from_query_parameter = session.request().query().get<std::string>("format", "text");
				const auto& section = session.params().get("section");

				if (section == "metrics")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::server_metrics)
							.dump(),
						"json");
				}
				else if (section == "configuration")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::config)
							.dump(),
						"json");
				}
				else if (section == "router")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::router)
							.dump(),
						"json");
				}
				else if (section == "access_log")
				{
					session.response().assign(
						http::status::ok,
						server_base::manager()
							.to_json(http::server::server_manager::json_status_options::access_log)
							.dump(),
						"json");
				}
				else if (section == "version")
				{
					std::string version = std::string{ "cld_platform_mgr " } + get_version_ex(PORT_SET, NULL)
										  + std::string{ "/" } + get_version_ex(PORT_NO, NULL);

					if (format.find("application/json") != std::string::npos || format_from_query_parameter == "json")
					{
						auto result = json::object();
						result["version"] = version;

						session.response().assign(http::status::ok, result.dump(), "json");
					}
					else
					{
						session.response().assign(http::status::ok, std::move(version), "text");
					}
				}
				else
				{
					session.response().assign(http::status::not_found);
				}
			});

		server_base::router_.on_get("/internal/platform/manager/workspaces", [this](http::session_handler& session) {
			json workspaces_json{};
			workspaces_.to_json(workspaces_json);

			json result_json = json::object();
			result_json["workspaces"] = workspaces_json;

			session.response().assign(http::status::ok, result_json.dump(), "application/json");
		});

		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}", [this](http::session_handler& session) {
				auto& id = session.params().get("workspace_id");
				auto w = workspaces_.get_workspace(id);

				if (w != workspaces_.end())
				{
					json result_json;
					result_json["workspace"] = (*(w->second));
					session.response().assign(http::status::ok, result_json.dump(), "application/json");
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_post("/internal/platform/manager/workspaces", [this](http::session_handler& session) {
			// Json body: { "id" : <str:workspace_id>, ... }
			try
			{
				json workspace_json = json::parse(session.request().body());

				auto& workspace_id = workspace_json.at("id");

				if (workspaces_.get_workspace(workspace_id) != workspaces_.end())
				{
					session.response().assign(http::status::conflict);
					return;
				}

				if (workspaces_.add_workspace(workspace_id, workspace_json) == true)
				{
					session.response().assign(http::status::created);
				}
				else
				{
					session.response().assign(http::status::internal_server_error);
				}
			}
			catch (const json::exception& ex)
			{
				session.response().assign(http::status::bad_request);
				server_base::logger_.error(
					"error when handling on_post for /private/infra/workspaces: {s}\n", ex.what());
			}
		});

		server_base::router_.on_delete(
			"/internal/platform/manager/workspaces/{workspace_id}", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				if (workspaces_.delete_workspace(workspace_id))
				{
					workspaces_.is_changed().store(true);
					session.response().assign(http::status::no_content);
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");

				auto w = workspaces_.get_workspace(workspace_id);

				if (w != workspaces_.end())
				{
					json result;
					result["workgroups"] = json::array();

					for (auto i = w->second->cbegin(); i != w->second->cend(); ++i)
					{
						json workgroups_json;
						i->second->to_json(workgroups_json, output_formating::options::complete);

						result["workgroups"].emplace_back(workgroups_json);
					}
					workspaces_.is_changed().store(true);

					session.response().assign(http::status::ok, result.dump(), "application/json");
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");

					json result_json = json::object();
					result_json["workgroups"] = json::array();

					for (auto i = workspace->second->cbegin(); i != workspace->second->cend(); ++i)
					{
						json workgroups_json;
						i->second->to_json(workgroups_json, output_formating::options::complete);

						if ((name == i->first.first)) result_json["workgroups"].emplace_back(workgroups_json);
					}
					session.response().assign(http::status::ok, result_json.dump(), "application/json");
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_post(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");

				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");

					for (auto i = workspace->second->cbegin(); i != workspace->second->cend(); ++i)
					{
						if ((name == i->first.first))
						{
							session.response().assign(http::status::conflict);
							return;
						}
					}

					json workgroups_json = json::parse(session.request().body());
					workspace->second->add_workgroups(name, "", workgroups_json["workgroups"]);
					workspaces_.is_changed().store(true);

					session.response().assign(http::status::ok);
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_delete(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");

				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					bool deleted_somthing = false;

					for (auto i = workspace->second->begin(); i != workspace->second->end();)
					{
						if ((name == i->first.first))
						{
							i = workspace->second->delete_workgroups(name, i->first.second);
							deleted_somthing = true;
						}
						else
							++i;
					}
					if (deleted_somthing)
					{
						workspaces_.is_changed().store(true);
						session.response().assign(http::status::accepted);
					}
					else
						session.response().assign(http::status::not_found);
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					json result_json = json::object();
					result_json["workgroups"] = json::array();

					for (auto i = workspace->second->cbegin(); i != workspace->second->cend(); ++i)
					{
						json workgroups_json;
						i->second->to_json(workgroups_json, output_formating::options::complete);

						if ((name == i->first.first) && (type == i->first.second))
							result_json["workgroups"].emplace_back(workgroups_json);
					}
					workspaces_.is_changed().store(true);
					session.response().assign(http::status::ok, result_json.dump(), "application/json");
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_post(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");

				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					for (auto i = workspace->second->cbegin(); i != workspace->second->cend(); ++i)
					{
						if ((name == i->first.first) && (type == i->first.second))
						{
							session.response().assign(http::status::conflict);
							return;
						}
					}

					json workgroups_json = json::parse(session.request().body());
					workspace->second->add_workgroups(name, type, workgroups_json["workgroups"]);
					workspaces_.is_changed().store(true);

					session.response().assign(http::status::ok);
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_delete(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");

				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					bool deleted_somthing = false;

					for (auto i = workspace->second->begin(); i != workspace->second->end();)
					{
						if ((name == i->first.first) && (type == i->first.second))
						{
							i = workspace->second->delete_workgroups(name, i->first.second);
							deleted_somthing = true;
						}
						else
							++i;
					}
					if (deleted_somthing)
					{
						workspaces_.is_changed().store(true);
						session.response().assign(http::status::accepted);
					}
					else
						session.response().assign(http::status::not_found);
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// get info for specific worker {TYPE} in workspace {workspace_id}
		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/parameters/{detail}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					auto& detail = session.params().get("detail");

					json result = json::object();

					if (workgroups != workspace->second->end())
					{

						workgroups->second->to_json(result, detail);

						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
						session.response().assign(
							http::status::not_found,
							error_json("404", "workspace_id " + workspace_id + " not found").dump(),
							"application/json");
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// get info for specific worker {TYPE} in workspace {workspace_id}
		server_base::router_.on_put(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/parameters/{detail}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					auto& detail = session.params().get("detail");

					json result = json::object();

					if (workgroups != workspace->second->end())
					{
						json parameters_json = json::parse(session.request().body());

						workgroups->second->from_json(parameters_json, detail);

						workgroups->second->to_json(result, detail);
						workspaces_.is_changed().store(true);

						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
						session.response().assign(
							http::status::not_found,
							error_json("404", "workspace_id " + workspace_id + " not found").dump(),
							"application/json");
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// get info for specific worker id for a worker with {name} and {type} in workspace {workspace_id}
		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					if (workgroups != workspace->second->end())
					{
						json worker_json;
						auto& worker_id = session.params().get("worker_id");

						auto worker = workgroups->second->find_worker(worker_id);

						if (worker != workgroups->second->end())
							worker->second.to_json(worker_json, output_formating::options::complete);

						json result;
						result["worker"] = worker_json;
						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// get info for specific worker {TYPE} in workspace {workspace_id}
		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					json result;
					result["workers"] = json::array();

					if (workgroups != workspace->second->end())
					{

						for (const auto& worker : *workgroups->second)
						{
							json worker_json;
							worker.second.to_json(worker_json, output_formating::options::complete);

							result["workers"].emplace_back(worker_json);
						}
						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
						session.response().assign(
							http::status::not_found,
							error_json("404", "workspace_id " + workspace_id + " not found").dump(),
							"application/json");
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// put specific worker {worker_id} of worker {name} and {type} in workspace {workspace_id}
		server_base::router_.on_put(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");
					auto& worker_id = session.params().get("worker_id");

					auto i = workspace->second->find_workgroups(name, type);

					if (i != workspace->second->end())
					{
						json worker_json = json::parse(session.request().body());
						const std::string& worker_label = worker_json["worker_label"];

						auto workgroups = workspace->second->find_workgroups(name, type);

						if (workgroups != workspace->second->end())
						{
							workgroups->second->add_worker(
								worker_id, worker_label, worker_json, server_base::get_io_context());
						}

						workspaces_.is_changed().store(true);

						session.response().assign(http::status::no_content);
					}
					else
					{
						session.response().assign(http::status::not_found);
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// remove specific worker {worker_id} of worker {type} in workspace {workspace_id}
		server_base::router_.on_delete(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto i = workspace->second->find_workgroups(name, type);

					if (i != workspace->second->end())
					{

						i->second->cleanup_all_workers();
						session.response().assign(http::status::accepted);
						workspaces_.is_changed().store(true);
					}
					else
					{
						session.response().assign(http::status::not_found);
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// remove specific worker {worker_id} of worker {type} in workspace {workspace_id}
		server_base::router_.on_delete(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto i = workspace->second->find_workgroups(name, type);

					if (i != workspace->second->end())
					{
						auto& worker_id = session.params().get("worker_id");

						if (session.request().body().empty() == false)
						{
							json ii;
							try
							{
								json worker_json = json::parse(session.request().body());

								if (worker_json.contains("limits") == true)
								{
									i->second->workgroups_limits().from_json(
										worker_json["limits"],
										"workers_required",
										workgroups::limits::from_json_operation::add);
								}
							}
							catch (json::exception&)
							{
								session.response().assign(http::status::not_found);
								return;
							}
						}

						if (i->second->delete_worker(worker_id) == false)
						{
							session.response().assign(http::status::not_found);
						}
						else
						{
							session.response().assign(http::status::no_content);
							workspaces_.is_changed().store(true);
						}
					}
					else
					{
						session.response().assign(http::status::not_found);
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_put(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}/label",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto i = workspace->second->find_workgroups(name, type);

					if (i != workspace->second->end())
					{
						auto& worker_id = session.params().get("worker_id");

						auto worker = i->second->find_worker(worker_id);

						if (worker != i->second->end())
						{
							// worker->second.set_status(worker::status::drain);
							worker->second.worker_label("");
							workspaces_.is_changed().store(true);
							session.response().assign(http::status::no_content);
						}
						else
						{
							session.response().assign(http::status::not_found);
						}
					}
					else
					{
						session.response().assign(http::status::not_found);
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_delete(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}/process",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto i = workspace->second->find_workgroups(name, type);

					if (i != workspace->second->end())
					{
						auto& worker_id = session.params().get("worker_id");

						if (i->second->delete_worker_process(worker_id) == false)
						{
							session.response().assign(http::status::not_found);
						}
						else
						{
							workspaces_.is_changed().store(true);
							session.response().assign(http::status::no_content);
						}
					}
					else
					{
						session.response().assign(http::status::not_found);
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/limits",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					if (workgroups != workspace->second->end())
					{
						json result;
						json limits;
						workgroups->second->workgroups_limits().to_json(limits, output_formating::options::complete);
						result["limits"] = limits;
						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_get(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/limits/{limit_name}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");
					auto& limit_name = session.params().get("limit_name");

					auto workgroups = workspace->second->find_workgroups(name, type);

					if (workgroups != workspace->second->end())
					{

						json result;
						json limits;
						workgroups->second->workgroups_limits().to_json(
							limits, output_formating::options::complete, limit_name);
						result = limits;
						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_put(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/limits",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					if (workgroups != workspace->second->end())
					{
						json limits = json::parse(session.request().body());

						workgroups->second->workgroups_limits().from_json(limits["limits"]);

						workspaces_.is_changed().store(true);
						session.response().assign(http::status::no_content);
					}
					else
					{
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		// get info for specific worker id for a worker with {name} and {type} in workspace {workspace_id}
		server_base::router_.on_put(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/limits/{limit_name}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");
					auto& limit_name = session.params().get("limit_name");

					auto workgroups = workspace->second->find_workgroups(name, type);

					if (workgroups != workspace->second->end())
					{

						json result;
						json limits = json::parse(session.request().body());
						// TODO split function below:
						workgroups->second->direct_workers(
							server_base::get_io_context(),
							server_base::configuration_,
							server_base::logger_,
							limit_name,
							limits,
							workgroups::limits::from_json_operation::set);
						workgroups->second->workgroups_limits().to_json(
							limits["limits"], output_formating::options::complete);

						result = limits;
						workspaces_.is_changed().store(true);
						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_patch(
			"/internal/platform/manager/workspaces/{workspace_id}/workgroups/{name}/{type}/limits/{limit_name}",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");
					auto& limit_name = session.params().get("limit_name");

					auto workgroups = workspace->second->find_workgroups(name, type);

					if (workgroups != workspace->second->end())
					{

						json result;
						json limits = json::parse(session.request().body());

						workgroups->second->direct_workers(
							server_base::get_io_context(),
							server_base::configuration_,
							server_base::logger_,
							limit_name,
							limits,
							workgroups::limits::from_json_operation::add);

						workgroups->second->workgroups_limits().to_json(
							limits["limits"], output_formating::options::complete);

						result = limits;
						workspaces_.is_changed().store(true);

						session.response().assign(http::status::ok, result.dump(), "application/json");
					}
					else
					{
					}
				}
				else
				{
					session.response().assign(
						http::status::not_found,
						error_json("404", "workspace_id " + workspace_id + " not found").dump(),
						"application/json");
				}
			});

		server_base::router_.on_get("/internal/platform/manager/upstreams", [this](http::session_handler& session) {
			auto include_connections = session.request().query().get<bool>("connections", false);
			const auto& format = session.request().get<std::string>("Accept", "application/text");

			if (format.find("application/json") != std::string::npos)
			{
				json result = json::array();
				for (const auto& workspace : workspaces_)
				{
					for (const auto& workgroup : *workspace.second)
					{
						json upstream_json = json::object();

						workgroup.second->upstreams_.to_json(
							workspace.first,
							workspace.second->get_tenant_id(),
							http::async::upstreams::options::upstreams_only,
							upstream_json);

						result.emplace_back(upstream_json);
					}
				}
				session.response().assign(http::status::ok, result.dump(), "application/json");
			}
			else
			{
				for (const auto& workspace : workspaces_)
				{
					std::stringstream ss;
					for (const auto& workgroup : *workspace.second)
					{
						ss.str(std::string());
						if (include_connections)
							ss << workgroup.second->upstreams_.to_string(
								workspace.first,
								workspace.second->get_tenant_id(),
								http::async::upstreams::options::include_connections);
						else
							ss << workgroup.second->upstreams_.to_string(
								workspace.first,
								workspace.second->get_tenant_id(),
								http::async::upstreams::options::upstreams_only);

						session.response().body() += ss.str();
					}
				}
				session.response().type("text");
				session.response().status(http::status::ok);
			}
		});

		server_base::router_.on_proxy_pass("/", [this](http::session_handler& session) {

			session.response().status(http::status::not_found);

			auto workspace = workspaces_.find_workspace(session);

			if (workspace != workspaces_.cend())
			{
				auto workgroup = workspace->second->find_workgroups(session);

				if (workgroup != workspace->second->end())
				{
					if (workgroup->second->has_workers_available())
					{
						if (session.protocol() == http::protocol::https)
						{
							session.request().set("X-Forwarded-Proto", "https");

							session.request().set(
								"X-Forwarded-Host",
								session.request().get<std::string>(
									"X-Forwarded-Host",
									server_base::configuration_.template get<std::string>(
										"https_this_server_base_host", "")));
						}

						session.request().set_attribute<http::async::upstreams*>(
							"proxy_pass", &workgroup->second->upstreams_);
					}
					else
					{
						workgroup->second->workgroups_limits().workers_required_upd(1);
						session.response().status(http::status::service_unavailable);
					}
				}
			}
		});

		server_base::router_.on_internal_error([this](http::session_handler& session, std::exception& e) {
			server_base::logger().info(
				"api-error with requested url: \"{s}\", error: \"{s}\", and request body:\n \"{s}\"",
				session.request().url_requested(),
				e.what(),
				http::to_string(session.request()));

			session.response().assign(http::status::internal_server_error, e.what());
		});
	}

	virtual ~manager() {}

	http::server::state start() override
	{
		try
		{
			auto ret = server_base::start();
			director_thread_ = std::thread{ [this]() { director_handler(); } };

			return ret;
		}
		catch (std::runtime_error& e)
		{
			std::cerr << e.what() << std::endl;
			_exit(-1);
		}
	}

	enum class json_options
	{
		complete,
		essential
	};

	void to_json(json& j, output_formating::options options = output_formating::options::complete) const
	{
		json workspaces_json;
		workspaces_.to_json(workspaces_json, options);

		j["workspaces"] = workspaces_json;
	}

	void from_json(json&) const {}

private:
	void director_handler()
	{
		while (!server_base::is_active() && !server_base::is_activating())
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		while (server_base::is_active() || server_base::is_activating())
		{
			if (server_base::is_active())
			{
				workspaces_.direct_workspaces(
					server_base::get_io_context(), server_base::configuration_, server_base::logger_);

				if (workspaces_.is_changed())
				{
					json manager_json = json::object();
					to_json(manager_json, output_formating::options::essential);
					std::ifstream prev_configuration_file{ configuration_file_, std::ios::binary };
					std::ofstream bak_config_file{ configuration_file_ + ".bak", std::ios::binary };

					bak_config_file << prev_configuration_file.rdbuf();
					prev_configuration_file.close();

					std::ofstream new_config_file{ configuration_file_ };

					new_config_file << std::setw(4) << manager_json;

					if (new_config_file.fail() == false)
						server_base::logger_.api("config saved to: \"{s}\"\n", configuration_file_);

					workspaces_.is_changed().store(false);
				}
			}

			std::this_thread::sleep_for(std::chrono::seconds(5));
		}
	}

public:
	static json error_json(const std::string& code, const std::string& message)
	{
		json error_json;
		error_json["error"].emplace_back(json{ { "code", code }, { "message", message } });

		return error_json;
	}
};

static std::unique_ptr<manager<http::async::server>> cpm_server_;

} // namespace platform
} // namespace cloud

inline int start_cld_manager_server(std::string config_file, std::string config_options, bool run_as_daemon)
{
	std::string server_version = std::string{ "ln-cld-mgr" };

	if (run_as_daemon) util::daemonize("/tmp", "/var/lock/" + server_version + ".pid");

	http::configuration http_configuration{
		{ { "server", server_version },
		  { "http_listen_port_begin", "4000" },
		  { "private_base", "/internal/platform/manager" },
		  { "health_check", "/internal/platform/manager/healthcheck" },
		  { "private_ip_white_list", "::/0" },
		  { "public_ip_white_list", "::/0" },
		  { "access_log_level", "access_log" },
		  { "access_log_file", "access_log.txt" },
		  { "extended_log_level", "api" },
		  { "extended_log_file", "console" },
		  { "https_enabled", "false" },
		  { "http_enabled", "true" },
		  { "http_use_portsharding", "false" } },
		config_options //,
		//[](const std::string name, const std::string value, const std::string default_value) {
		//	// std::ofstream configuration_dump{ "C:\\tmp\\options.txt", std::ios_base::app };

		//	// configuration_dump << "name: '" << name << "', value: '" << value << "', default_value: '" <<
		//	// default_value
		//	//				   << "'\n";
		//	// configuration_dump.flush();
		//}
	};

	cloud::platform::cpm_server_ = std::unique_ptr<cloud::platform::manager<http::async::server>>(
		new cloud::platform::manager<http::async::server>(http_configuration, config_file));

	cloud::platform::cpm_server_->start();

	return 0;
}

inline int start_cld_manager_server(int argc, const char** argv)
{
	prog_args::arguments_t cmd_args(
		argc,
		argv,
		{ { "cld_config",
			{ prog_args::arg_t::arg_val, " <config>: filename for the workspace config file or url", "config.json" } },
		  { "cld_options", { prog_args::arg_t::arg_val, "see doc.", "" } },
		  { "daemonize", { prog_args::arg_t::flag, "run daemonized" } } });

	if (cmd_args.process_args() == false)
	{
		std::cout << "error in arguments \n";
		exit(1);
	}

	return start_cld_manager_server(
		cmd_args.get_val("cld_config"), cmd_args.get_val("cld_options"), cmd_args.get_val("daemonize") == "true");
}

inline void run_cld_manager_server()
{
	while (cloud::platform::cpm_server_->is_active())
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

inline int stop_cld_manager_server()
{
	cloud::platform::cpm_server_->stop();
	cloud::platform::cpm_server_.release();

	return 0;
}

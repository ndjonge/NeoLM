#include <cstring>
#include <iomanip>
#include <iostream>
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

namespace os
{
inline void run_as_service()
{
#ifdef _WIN32

#else
	pid_t pid;

	int devnull = open("/dev/null", O_RDWR);
	if (devnull > 0)
	{
		close(fileno(stdin));
		close(fileno(stdout));
		close(fileno(stderr));
		dup(devnull);
		dup(devnull);
		dup(devnull);
		close(devnull);
	}

	if ((pid = fork()) < 0)
	{
		return;
	}
	else if (pid != 0)
	{
		exit(0); /* Parent goes bye-bye. */
	}

	/* Child continues. */
	setsid(); /* Become session leader. */
	chdir("/");
	umask(0); /* Clear file mode creation mask. */
#endif
}
} // namespace os

namespace bse_utils
{

#ifdef LOCAL_TESTING
namespace local_testing
{
std::mutex m;

template <typename S> struct test_sockets
{
public:
	std::queue<S> available_sockets_;
	std::mutex m_;

	test_sockets(S b, size_t nr)
	{
		std::lock_guard<std::mutex> g{ m_ };
		for (S i = 0; i < nr; i++)
			available_sockets_.push(b + i);
	}

	S aquire()
	{
		std::lock_guard<std::mutex> g{ m_ };
		S s = available_sockets_.front();
		available_sockets_.pop();

		return s;
	}

	void release(const std::string& url)
	{
		// scheme
		// host
		// port
		// resource

		// std::tie<> http::util::url_split(url, )

		auto port = url.substr(1 + url.find_last_of(':'));

		std::lock_guard<std::mutex> g{ m_ };
		available_sockets_.push(stoul(port));
	}

	void release(S s)
	{
		std::lock_guard<std::mutex> g{ m_ };
		available_sockets_.push(s);
	}
};

static test_sockets<std::uint32_t> _test_sockets{ 8000, 16 };
} // namespace local_testing

static bool create_bse_process_as_user(
	const std::string&,
	const std::string&,
	const std::string&,
	const std::string&,
	const std::string&,
	const std::string&,
	std::uint32_t& pid,
	std::string& ec)
{
	static std::atomic<std::uint32_t> worker_ids{ 0 };

	bool result = true;

	pid = local_testing::_test_sockets.aquire();

	ec = "";

	std::thread([pid]() {
		std::lock_guard<std::mutex> g{ local_testing::m };
		json put_new_instance_json = json::object();
		std::string ec;
		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["base_url"] = "http://localhost:" + std::to_string(pid);
		put_new_instance_json["version"] = "test_bshell";

		auto response = http::client::request<http::method::put>(
			"http://localhost:4000/private/infra/workspaces/workspace_000/workgroups/untitled/bshells/workers/worker_"
				+ std::to_string(worker_ids++),
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
			//	std::cout << "http://localhost:5000/private/infra/workspaces/workspace_000/workgroups/untitled/bshells/"
			//				 "workers/ send\n";
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

class applications;
class application;
class workspace;
class workgroups;
class workspaces;

void to_json(json& j, const applications& value);
void from_json(const json& j, applications& value);

void to_json(json& j, const application& value);
void from_json(const json& j, application& value);

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
		starting,
		up,
		drain,
		down
	};

	static std::string to_string(worker::status status)
	{
		switch (status)
		{
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
	std::string base_url_{};
	std::string version_{};
	std::int32_t process_id_;
	std::chrono::steady_clock::time_point startup_t0_;
	std::chrono::steady_clock::time_point startup_t1_{};

	status status_{ status::down };
	json worker_metrics_{};

public:
	worker(
		std::string worker_id,
		std::string base_url = "",
		std::string version = "",
		std::int32_t process_id = 0)
		: worker_id_(worker_id)
		, base_url_(base_url)
		, version_(version)
		, process_id_(process_id)
		, startup_t0_(std::chrono::steady_clock::now())
		, status_(worker::status::starting)
	{
	}

	worker(const worker& worker)
		: worker_id_(worker.worker_id_)
		, base_url_(worker.base_url_)
		, version_(worker.version_)
		, process_id_(worker.process_id_)
		, startup_t0_(worker.startup_t0_)
		, status_(worker.status_)
	{
	}

	virtual ~worker() { worker_metrics_.clear(); };

	const std::string& get_base_url() const { return base_url_; };
	int get_process_id() const { return process_id_; };

	status get_status() const { return status_; }

	void set_status(status s)
	{
		if (s == status::up && status_ == status::starting) 
		{
			startup_t1_ = std::chrono::steady_clock::now();
		}
		status_ = s;
	};


	void from_json(const json& worker_json)
	{
		process_id_ = worker_json.value("process_id", 0);
		base_url_ = worker_json.value("base_url", "");
		version_ = worker_json.value("version", "");
	}

	void to_json(json& worker_json) const
	{
		if (!base_url_.empty())
		{
			worker_json["link_to_status_url"] = base_url_ + "/private/infra/worker/status";
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

		if (status_ != status::down)
		{
			worker_json["startup_latency"]
				= std::chrono::duration_cast<std::chrono::milliseconds>(startup_t1_ - startup_t0_).count();

			worker_json["runtime"]
				= std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - startup_t1_)
					  .count();
		}
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

	workgroups(const std::string& workspace_id, const std::string& tenant_id, const std::string& type)
		: workspace_id_(workspace_id), type_(type), tenant_id_(tenant_id)
	{
	}

	virtual ~workgroups() = default;

	iterator begin() { return workers_.begin(); }
	iterator end() { return workers_.end(); }
	const_iterator cbegin() const { return workers_.cbegin(); }
	const_iterator cend() const { return workers_.cend(); }

	void cleanup(){};

	http::basic::async::upstreams upstreams_;

	bool has_workers_available() { return limits_.workers_actual() > 0; }

	iterator find_worker(const std::string& worker_id)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		return workers_.find(worker_id);
	}

	void add_pending_worker(const std::string& worker_id) 
	{
		workers_.emplace(
			std::pair<const std::string, worker>(worker_id, worker{ worker_id }));
	}

	void add_worker(const std::string& worker_id, const json& j, asio::io_context& io_context)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		std::int32_t process_id;
		std::string base_url;
		std::string version;

		process_id = j.value("process_id", 0);
		base_url = j.value("base_url", "");
		version = j.value("version", "");

		auto new_worker = workers_.emplace(std::pair<const std::string, worker>(
			worker_id, worker{ worker_id, base_url, version, process_id }));
		
		if (new_worker.second == false)
			new_worker.first->second.from_json(j);

		if (base_url.empty() == false)
		{
			limits_.workers_actual_upd(1);
			upstreams_.add_upstream(io_context, base_url, worker_id);
			new_worker.first->second.set_status(worker::status::up);
		}
	}

	bool delete_worker(const std::string& pid)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		bool result = false;

		auto worker = workers_.find(pid);

		if (worker != workers_.end())
		{
			if (worker->second.get_base_url().empty() == false)
			{
				upstreams_.erase_upstream(worker->second.get_base_url());
				limits_.workers_actual_upd(-1);
			}
			worker = workers_.erase(worker);
			result = true;
		}
		return result;
	}

	bool shutdown_worker_by_pid(const std::string& pid)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		bool result = false;

		auto worker = workers_.find(pid);

		if (worker != workers_.end())
		{
			std::string ec;
			auto response = http::client::request<http::method::delete_>(
				worker->second.get_base_url() + "/private/infra/worker/shutdown", ec, {});

			worker->second.set_status(worker::status::down);
		}
		return result;
	}

public:
	const std::string& get_type(void) const { return type_; }
	const std::string& get_name(void) const { return name_; }

	virtual void from_json(const json& j)
	{
		name_ = j.value("name", "anonymous");
		limits_.from_json(j["limits"]);
		// TODO workers....
	}

	virtual void to_json(json& j) const
	{
		j["name"] = name_;
		j["type"] = type_;

		json limits_json;
		limits_.to_json(limits_json);
		j["limits"] = limits_json;
		j["workers"] = json::array();
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		for (auto worker = workers_.cbegin(); worker != workers_.cend(); ++worker)
		{
			json worker_json;

			worker->second.to_json(worker_json);

			j["workers"].emplace_back(worker_json);
		}
	}

	virtual bool create_worker_process(
		const std::string& manager_endpoint,
		const std::string& workspace_id,
		const std::string& worker_type,
		const std::string& worker_name,
		std::uint32_t& pid,
		std::string& worker_id,
		std::string& ec)
		= 0;

	void remove_worker(worker& worker)
	{
		std::lock_guard<std::mutex> g{ workers_mutex_ };
		std::string ec;
		auto response = http::client::request<http::method::delete_>(
			worker.get_base_url() + "/private/infra/worker/shutdown", ec, {});

		worker.set_status(worker::status::drain);
	}

	// remove all
	void remove_all_workers(void)
	{
		for (auto in = workers_.begin(); in != workers_.end(); ++in)
		{
			remove_worker(in->second);
		}
	}

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
		std::int16_t workers_min() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_min_;
		}
		std::int16_t workers_max() const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			return workers_max_;
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
			if (value > 0) workers_pending_ -= value;
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
			}
			else
			{
				if (limit_name.empty() || limit_name == "workers_required")
					workers_required_ += j.value("workers_required", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_min")
					workers_min_ += j.value("workers_min", std::int16_t{ 0 });

				if (limit_name.empty() || limit_name == "workers_max")
					workers_max_ += j.value("workers_max", std::int16_t{ 0 });
			}

			if (workers_min_ > workers_max_) workers_min_ = workers_max_;
			if (workers_max_ < workers_min_) workers_max_ = workers_min_;
			if (workers_required_ > workers_max_) workers_required_ = workers_max_;
			if (workers_required_ < workers_min_) workers_required_ = workers_min_;
		}

		void to_json(json& j, const std::string& limit_name = "") const
		{
			std::lock_guard<std::mutex> m{ limits_mutex_ };
			if (limit_name.empty() || limit_name == "workers_required")
			{
				j["workers_required"] = workers_required_;
			}
			if (limit_name.empty() || limit_name == "workers_actual")
			{
				j["workers_actual"] = workers_actual_;
			}
			if (limit_name.empty() || limit_name == "workers_min")
			{
				j["workers_min"] = workers_min_;
			}
			if (limit_name.empty() || limit_name == "workers_max")
			{
				j["workers_max"] = workers_max_;
			}
			if (limit_name.empty() || limit_name == "workers_pending")
			{
				j["workers_pending"] = workers_pending_;
			}
		}

	private:
		std::int16_t workers_pending_{ 0 };
		std::int16_t workers_required_{ 0 };
		std::int16_t workers_actual_{ 0 };
		std::int16_t workers_min_{ 0 };
		std::int16_t workers_max_{ 0 };

		mutable std::mutex limits_mutex_;
	};

	limits& workgroups_limits() { return limits_; }

	virtual void direct_workers(
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
	std::string tenant_id_;

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
	bshell_workgroups(const std::string& workspace_id, const std::string& tenant_id, const json& worker_type_json)
		: workgroups(workspace_id, tenant_id, worker_type_json["type"])
	{
		from_json(worker_type_json);
	}

	virtual void set_tenant(const std::string& t) { tenant_id_ = t; };

	virtual void direct_workers(
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

		server_endpoint += "/private/infra/workspaces";

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
			logger.api(
				"managing: /{s}/{s}/{s} actual: {d}, pending: {d}, required: {d}, min: {d}, max: {d}\n",
				workspace_id_,
				type_,
				name_,
				limits_.workers_actual(),
				limits_.workers_pending(),
				limits_.workers_required(),
				limits_.workers_min(),
				limits_.workers_max());

			auto workers_required_to_add = limits_.workers_required_to_add();

			if (rescan) rescan = false;

			for (std::int16_t n = 0; n < workers_required_to_add; n++)
			{
				std::uint32_t process_id = 0;
				std::string worker_id;
				lock.unlock();
				bool success
					= create_worker_process(server_endpoint, workspace_id_, type_, name_, process_id, worker_id, ec);
				lock.lock();
				if (!success) // todo
				{
					logger.api(
						"managing: /{s}/{s}/{s} new worker process ({d}/{d}), failed to start proces: {s}\n",
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
						"managing: /{s}/{s}/{s} new worker process ({d}/{d}), processid: {d}, worker_id: {s}\n",
						workspace_id_,
						type_,
						name_,
						1 + n,
						workers_required_to_add,
						static_cast<int>(process_id),
						worker_id);

					add_pending_worker(worker_id);

					limits_.workers_pending_upd(1);
				}
			}

			if (limits_.workers_required_to_add() < 0)
			{
				// todo: scale down.
				// for now let the idle watchdog handle it.
			}

			if (limits_adjustments.contains("limits") == false)
			{
				std::int16_t watchdogs_feeded = 0;

				for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
				{
					if (worker_it->second.get_base_url().empty()) // TODO change to status?
					{
						++worker_it;
						continue;
					}

					auto& worker = worker_it->second;

					if (worker_it->second.get_status() == worker::status::up)
					{
						auto feed_Watchdog = watchdogs_feeded++ < limits_.workers_min();

						http::headers watchdog_headers{ { "Host", "localhost" },
														{ "X-Feed-Watchdog", feed_Watchdog ? "true" : "false" } };

						http::client::async_request<http::method::post>(
							upstreams_.get_upstream(worker_it->second.get_base_url()),
							"/private/infra/worker/watchdog",
							watchdog_headers,
							std::string{},
							[this, &worker, &logger](http::response_message& response, asio::error_code& error_code) {
								if (!error_code && response.status() == http::status::ok
									&& worker.get_status() != worker::status::up)
								{
									worker.set_status(worker::status::up);
								}
								else if (error_code || response.status() != http::status::ok)
								{
									worker.set_status(worker::status::drain);
									logger.api(
										"managing: /{s}/{s}/{s}: failed health check for worker {s}\n",
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

				for (auto worker_it = workers_.begin(); worker_it != workers_.end();)
				{
					if ((worker_it->second.get_status() == worker::status::drain)
						|| worker_it->second.get_status() == worker::status::down)
					{
						logger.api(
							"managing: /{s}/{s}/{s}: delete {s}\n",
							workspace_id_,
							type_,
							name_,
							worker_it->second.get_base_url());

						upstreams_.erase_upstream(worker_it->second.get_base_url());
#ifdef LOCAL_TESTING
						bse_utils::local_testing::_test_sockets.release(worker_it->second.get_base_url());
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
		workgroups::from_json(j);
		try
		{ // TODO optional parameters bse, bse_bin, bse_user, os_user and os_password.
			j["details"].at("bse").get_to(bse_);
			j["details"].at("bse_bin").get_to(bse_bin_);
			j["details"].at("bse_user").get_to(bse_user_);
			j["details"].at("os_user").get_to(os_user_);
			j["details"].at("os_password").get_to(os_password_);
		}
		catch (json::exception&)
		{
		}

		j["details"].at("program").get_to(program_);
		j["details"].at("cli_options").get_to(cli_options_);
		j["details"].at("http_options").get_to(http_options_);
	}

	void to_json(json& j) const override
	{
		workgroups::to_json(j);

		if (bse_.empty() == false) j["details"].emplace("bse", bse_);

		if (bse_bin_.empty() == false) j["details"].emplace("bse_bin", bse_bin_);

		if (bse_user_.empty() == false) j["details"].emplace("bse_user", bse_user_);

		if (os_user_.empty() == false) j["details"].emplace("os_user", os_user_);

		if (os_password_.empty() == false) j["details"].emplace("os_password", os_password_);

		j["details"].emplace("program", program_);
		j["details"].emplace("cli_options", cli_options_);
		j["details"].emplace("http_options", http_options_);
	}

public:
	bool create_worker_process(
		const std::string& manager_endpoint,
		const std::string& workspace_id,
		const std::string& worker_type,
		const std::string& worker_name,
		std::uint32_t& pid,
		std::string& worker_id,
		std::string& ec) override
	{
		static std::atomic<std::uint32_t> worker_ids{ 0 };
		std::stringstream parameters;

		worker_id = "worker_" + std::to_string(worker_ids++);

		parameters << "-httpserver_options cld_manager_endpoint:" << manager_endpoint
				   << ",cld_workgroup_membership_type:worker,cld_manager_workspace:" << workspace_id
				   << ",cld_worker_id:" << worker_id
				   << ",cld_manager_workgroup:" << worker_name << "/" << worker_type;

		if (!http_options_.empty())
			parameters << "," << http_options_ << " ";
		else
			parameters << " ";

		parameters << cli_options_;

		return bse_utils::create_bse_process_as_user(
			bse_,
			bse_bin_,
			tenant_id_,
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
	python_workgroups(const std::string& workspace_id, const std::string& tenant_id, const json& worker_type_json)
		: workgroups(workspace_id, tenant_id, "python"), rootdir()
	{
		from_json(worker_type_json);
	}

	virtual ~python_workgroups(){};

	void from_json(const json& j) override
	{
		workgroups::from_json(j);
		json d(j.at("details"));
		d.at("PythonRoot").get_to(rootdir);
	}

	void to_json(json& j) const override
	{
		workgroups::to_json(j);
		j["details"].emplace("PythonRoot", rootdir);
	}

	virtual void direct_workers(
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

private:
	std::string server_endpoint_;
	std::string workspace_id_{};
	std::string tenant_id_{};
	std::string description_{};
	std::vector<std::string> errors;
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
	const std::vector<std::string>& get_errors(void) { return errors; };
	void clear_errors(void) { errors.clear(); };

public:
	void to_json(json& workspace) const
	{
		workspace["id"] = workspace_id_;
		workspace["tenant_id"] = tenant_id_;
		workspace["description"] = description_;

		json workgroups_json;

		for (auto& named_worker : workgroups_)
		{
			json named_worker_json = json::object();

			named_worker.second->to_json(named_worker_json);

			workgroups_json.emplace_back(named_worker_json);
		}
		workspace["workgroups"] = workgroups_json;
	}

private:
	std::unique_ptr<workgroups>
	create_workgroups_from_json(const std::string& type, const std::string& tenant_id, const json& worker_type_json)
	{
		if (type == "bshells")
			return std::unique_ptr<workgroups>{ new bshell_workgroups{ workspace_id_, tenant_id, worker_type_json } };
		if (type == "ashells")
			return std::unique_ptr<workgroups>{ new bshell_workgroups{ workspace_id_, tenant_id, worker_type_json } };
		if (type == "python-scripts")
			return std::unique_ptr<workgroups>{ new python_workgroups{ workspace_id_, tenant_id, worker_type_json } };
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

	void add_workgroups(const std::string& name, std::string type, json& workgroups_json)
	{
		for (auto workgroups = workgroups_json.begin(); workgroups != workgroups_json.end(); workgroups++)
		{
			(*workgroups)["name"] = name;

			if (!type.empty()) (*workgroups)["type"] = type;

			auto new_workgroups = create_workgroups_from_json((*workgroups)["type"], tenant_id_, *workgroups);
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
		j.at("description").get_to(description_);
		j.at("tenant_id").get_to(tenant_id_);

		if (j.find("workgroups") != j.end())
		{
			json json_workgroups = j.at("workgroups");

			for (auto workgroups = json_workgroups.cbegin(); workgroups != json_workgroups.cend(); workgroups++)
			{
				if (workgroups.value().size())
				{
					auto new_workgroups
						= create_workgroups_from_json(workgroups.value()["type"], tenant_id_, *workgroups);

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
	using tenant_lookup_type = std::map<const std::string, workspace*>;

	using iterator = container_type::iterator;
	using const_iterator = container_type::const_iterator;
	using mutex_type = std::mutex;

private:
	tenant_lookup_type tenant_lookup_;

	container_type workspaces_;
	mutable mutex_type workspaces_mutex_;

	std::string port;
	std::string base_path;
	std::string manager_workspace;

public:
	iterator end() { return workspaces_.end(); }
	iterator begin() { return workspaces_.begin(); }
	const_iterator cend() const { return workspaces_.cend(); }
	const_iterator cbegin() const { return workspaces_.cbegin(); }

	void direct_workspaces(const http::configuration& configuration, lgr::logger& logger)
	{
		auto t0 = std::chrono::steady_clock::now();
		for (auto& workspace : workspaces_)
		{
			std::unique_lock<mutex_type> l{ workspaces_mutex_ };
			json empty_limits_adjustments = json::object();
			for (auto& workgroup : *workspace.second)
				workgroup.second->direct_workers(configuration, logger);
		}
		auto t1 = std::chrono::steady_clock::now();

		auto elapsed = t1 - t0;
		logger.api("managing: {u} workspaces took {d}msec\n", workspaces_.size(), elapsed.count() / 1000000);
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

			if (new_workspace.second)
			{
				tenant_lookup_.insert(tenant_lookup_type::value_type{ new_workspace.first->second->get_tenant_id(),
																	  new_workspace.first->second.get() });
			}

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
			tenant_lookup_.erase(i->second->get_tenant_id());
			workspaces_.erase(i);
			return true;
		}
	}

	const_iterator get_workspace(const std::string& id) const { return workspaces_.find(id); }

	workspace* get_tenant_workspace(const std::string& tenant_id) const
	{
		auto result = tenant_lookup_.find(tenant_id);

		if (result != tenant_lookup_.end())
			return result->second;
		else
			return nullptr;
	}

	iterator get_workspace(const std::string& id) { return workspaces_.find(id); }

	void to_json(json& j) const
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };

		j = json::array();

		for (auto& workspace : workspaces_)
		{
			auto workspace_json = json{};
			workspace.second->to_json(workspace_json);
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
	application(const application&){

	};

	application& operator=(const application&) { return *this; };

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

class applications
{
public:
	using container_type = std::map<const std::string, std::unique_ptr<application>>;

public:
	void from_json(const json&) {}

	void to_json(json& j) const
	{
		j = json::array();
		j.emplace_back(json::object());
	}

public:
	// bool add_application(application& ap)
	//{
	//	auto api = apps_.find(ap.get_id());
	//	if (api == apps_.end())
	//	{
	//		(*apps)[ap->get_id()] = ap;
	//		return true;
	//	}
	//	else
	//	{
	//		return false;
	//	}
	//}
private:
	container_type apps_;
};

inline void to_json(json&, const applications&) {}
inline void from_json(const json&, applications&) {}

template <typename S> class manager : public S
{
protected:
	using server_base = S;

private:
	workspaces workspaces_;
	applications applications_;
	std::thread director_thread_;

	std::promise<int> shutdown_promise;
	std::future<int> shutdown_future;
	std::string configuration_file_;

public:
	manager(http::configuration& http_configuration, const std::string& configuration_file)
		: http::basic::async::server(http_configuration)
		, shutdown_promise()
		, shutdown_future()
		, configuration_file_(configuration_file)
	{
		std::ifstream configuration_stream{ configuration_file_ };

		auto configfile_available = configuration_stream.fail() == false;

		if (configfile_available)
		{
			try
			{
				json manager_configuration_json = json::parse(configuration_stream);
				applications_.from_json(manager_configuration_json.at("applications"));
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
			applications_.from_json(json::object());
			workspaces_.from_json(json::object());
		}
		//#ifdef REST_ENABLED_LOGIC_SERVICE
		//				server_base::router_.on_post("/private/infra/logicservice/debug",
		//					[this](http::session_handler& session) {
		//
		//						EnableDebugLogging(session.request().body() == "debug");
		//
		//						session.response().status(http::status::ok);
		//					});
		//#endif
		server_base::router_.on_get("/private/infra/manager/healthcheck", [](http::session_handler& session) {
			session.response().status(http::status::ok);
			session.response().type("text");
			session.response().body() = std::string("Ok") + session.request().body();
		});

		server_base::router_.on_post("/private/infra/manager/mirror", [](http::session_handler& session) {
			session.response().status(http::status::ok);
			session.response().type(session.response().get<std::string>("Content-Type", "text/plain"));
			session.response().body() = session.request().body();
		});

		server_base::router_.on_put("/private/infra/manager/shutdown/{secs}", [this](http::session_handler& session) {
			auto& ID = session.params().get("secs");

			int shutdown = std::stoi(ID);
			send_json_response(session, http::status::ok, json{ { "time", shutdown } });
			session.response().set("Connection", "close");
			// workspaces_.delete_all_workspaces();
			shutdown_promise.set_value(shutdown);
		});

		server_base::router_.on_post("/private/infra/manager/log_level", [this](http::session_handler& session) {
			server_base::logger_.set_level(session.request().body());
			auto new_level = server_base::logger_.current_level_to_string();
			http::basic::server::configuration_.set("log_level", new_level);
			session.response().body() = server_base::logger_.current_level_to_string();
			session.response().status(http::status::ok);
		});

		server_base::router_.on_get("/private/infra/manager/log_level", [this](http::session_handler& session) {
			session.response().body() = server_base::logger_.current_level_to_string();
			session.response().status(http::status::ok);
		});

		server_base::router_.on_get("/private/infra/manager/version", [](http::session_handler& session) {
			std::string version = std::string{ "logic service " } + get_version_ex(PORT_SET, NULL) + std::string{ "/" }
								  + get_version_ex(PORT_NO, NULL);

			const auto& format = session.request().get<std::string>("Accept", "application/json");

			if (format.find("application/json") != std::string::npos)
			{
				session.response().body() = "{ \"version\" : \"" + http::util::escape_json(version) + "\"}";
				session.response().type("json");
			}
			else
			{
				session.response().body() = version;
				session.response().type("text");
			}

			session.response().status(http::status::ok);
		});

		server_base::router_.on_get("/private/infra/manager/status", [this](http::session_handler& session) {
			const auto& format = session.request().get<std::string>("Accept", "application/json");

			if (format.find("application/json") != std::string::npos)
			{
				server_base::manager().server_information(http::basic::server::configuration_.to_json_string());
				server_base::manager().router_information(server_base::router_.to_json_string());
				session.response().body() = server_base::manager().to_json_string(
					http::basic::server::server_manager::json_status_options::full);
				session.response().type("json");
			}
			else
			{
				server_base::manager().server_information(http::basic::server::configuration_.to_string());
				server_base::manager().router_information(server_base::router_.to_string());
				session.response().body() = server_base::manager().to_string();
				session.response().type("text");
			}

			session.response().status(http::status::ok);
		});

		server_base::router_.on_get("/private/infra/manager/status/{section}", [this](http::session_handler& session) {
			server_base::manager().server_information(http::basic::server::configuration_.to_json_string());
			server_base::manager().router_information(server_base::router_.to_json_string());

			auto section_option = http::basic::server::server_manager::json_status_options::full;

			const auto& section = session.params().get("section");

			if (section == "metrics")
			{
				section_option = http::basic::server::server_manager::json_status_options::server_metrics;
			}
			else if (section == "configuration")
			{
				section_option = http::basic::server::server_manager::json_status_options::config;
			}
			else if (section == "router")
			{
				section_option = http::basic::server::server_manager::json_status_options::router;
			}
			else if (section == "access_log")
			{
				section_option = http::basic::server::server_manager::json_status_options::access_log;
			}
			else
			{
				session.response().status(http::status::not_found);
				return;
			}

			session.response().body() = server_base::manager().to_json_string(section_option);
			session.response().type("json");
			session.response().status(http::status::ok);
		});

		server_base::router_.on_get("/private/infra/workspaces", [this](http::session_handler& session) {
			json workspaces_json{};
			workspaces_.to_json(workspaces_json);

			json result_json = json::object();

			result_json["workspaces"] = workspaces_json;
			send_json_response(session, http::status::ok, result_json);
		});

		server_base::router_.on_get("/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
			auto& id = session.params().get("workspace_id");
			auto w = workspaces_.get_workspace(id);

			if (w != workspaces_.end())
			{
				//				w->second.remove_deleted_workers();
				json j;
				j["workspace"] = (*(w->second));
				send_json_response(session, http::status::ok, j);
			}
			else
			{
				send_illegal_workspace_response(session, id);
			}
		});

		server_base::router_.on_post(
			"/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					send_response(session, http::status::conflict);
					return;
				}

				json workspace_json = json::parse(session.request().body());

				for (auto& workspaces : workspace_json["workspaces"].items())
				{
					workspaces.value()["id"] = workspace_id;
					workspaces_.add_workspace(workspace_id, workspaces.value());
				}

				send_response(session, http::status::ok);
			});

		server_base::router_.on_delete(
			"/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
				auto& id = session.params().get("workspace_id");
				if (workspaces_.delete_workspace(id))
				{
					session.response().status(http::status::ok);
				}
				else
				{
					send_illegal_workspace_response(session, id);
				}
			});

		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto w = workspaces_.get_workspace(workspace_id);

				if (w != workspaces_.end())
				{
					json result_json;
					result_json["workgroups"] = json::array();

					for (auto i = w->second->cbegin(); i != w->second->cend(); ++i)
					{
						json workgroups_json;
						i->second->to_json(workgroups_json);

						result_json["workgroups"].emplace_back(workgroups_json);
					}

					send_json_response(session, http::status::ok, result_json);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}", [this](http::session_handler& session) {
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
						i->second->to_json(workgroups_json);

						if ((name == i->first.first)) result_json["workgroups"].emplace_back(workgroups_json);
					}
					send_json_response(session, http::status::ok, result_json);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_post(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");

				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");

					for (auto i = workspace->second->cbegin(); i != workspace->second->cend(); ++i)
					{
						if ((name == i->first.first))
						{
							send_response(session, http::status::conflict);
							return;
						}
					}

					json workgroups_json = json::parse(session.request().body());
					workspace->second->add_workgroups(name, "", workgroups_json["workgroups"]);

					send_response(session, http::status::ok);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_delete(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}", [this](http::session_handler& session) {
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
						send_response(session, http::status::accepted);
					else
						send_response(session, http::status::not_found);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}",
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
						i->second->to_json(workgroups_json);

						if ((name == i->first.first) && (type == i->first.second))
							result_json["workgroups"].emplace_back(workgroups_json);
					}
					send_json_response(session, http::status::ok, result_json);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_post(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}",
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
							send_response(session, http::status::conflict);
							return;
						}
					}

					json workgroups_json = json::parse(session.request().body());
					workspace->second->add_workgroups(name, type, workgroups_json["workgroups"]);

					send_response(session, http::status::ok);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_delete(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}",
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
						send_response(session, http::status::accepted);
					else
						send_response(session, http::status::not_found);
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		// get info for specific worker id for a worker with {name} and {type} in workspace {workspace_id}
		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}",
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

						if (worker != workgroups->second->end()) worker->second.to_json(worker_json);

						json result;
						result["worker"] = worker_json;
						send_json_response(session, http::status::ok, result);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		// get info for specific worker {TYPE} in workspace {workspace_id}
		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers",
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
							worker.second.to_json(worker_json);

							result["workers"].emplace_back(worker_json);
						}
						send_json_response(session, http::status::ok, result);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		// put specific worker {worker_id} of worker {name} and {type} in workspace {workspace_id}
		server_base::router_.on_put(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}",
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

						auto workgroups = workspace->second->find_workgroups(name, type);

						if (workgroups != workspace->second->end())
						{
							workgroups->second->add_worker(worker_id, worker_json, server_base::get_io_context());
						}

						session.response().status(http::status::ok);

						send_no_content_response(session);
					}
					else
					{
						session.response().status(http::status::not_found);
						send_not_found_response(session);
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		// remove specific worker {worker_id} of worker {type} in workspace {workspace_id}
		server_base::router_.on_delete(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers",
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
						send_response(session, http::status::accepted);
					}
					else
					{

						session.response().status(http::status::not_found);
						send_not_found_response(session);
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		// remove specific worker {worker_id} of worker {type} in workspace {workspace_id}
		server_base::router_.on_delete(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}",
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
						json ii;

						json worker_json = json::parse(session.request().body());

						if (worker_json.contains("limits") == true)
						{
							i->second->workgroups_limits().from_json(
								worker_json["limits"],
								"workers_required",
								workgroups::limits::from_json_operation::add);
						}

						if (i->second->delete_worker(worker_id) == false)
						{
							session.response().status(http::status::not_found);
							send_not_found_response(session);
						}
						else
						{
							send_no_content_response(session);
						}
					}
					else
					{
						session.response().status(http::status::not_found);
						send_not_found_response(session);
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/limits",
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
						workgroups->second->workgroups_limits().to_json(limits);
						result["limits"] = limits;
						send_json_response(session, http::status::ok, result);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/limits/{limit_name}",
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
						workgroups->second->workgroups_limits().to_json(limits, limit_name);
						result["limits"] = limits;
						send_json_response(session, http::status::ok, result);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_put(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/limits",
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

						send_no_content_response(session);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		// get info for specific worker id for a worker with {name} and {type} in workspace {workspace_id}
		server_base::router_.on_put(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/limits/{limit_name}",
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
							server_base::configuration_,
							server_base::logger_,
							limit_name,
							limits,
							workgroups::limits::from_json_operation::set);
						workgroups->second->workgroups_limits().to_json(limits["limits"]);

						result["limits"] = limits;
						send_json_response(session, http::status::ok, result);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_patch(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/limits/{limit_name}",
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
							server_base::configuration_,
							server_base::logger_,
							limit_name,
							limits,
							workgroups::limits::from_json_operation::add);

						workgroups->second->workgroups_limits().to_json(limits["limits"]);

						result = limits;
						send_json_response(session, http::status::ok, result);
					}
					else
					{
					}
				}
				else
				{
					send_illegal_workspace_response(session, workspace_id);
				}
			});

		server_base::router_.on_get("/private/infra/manager/upstreams", [this](http::session_handler& session) {
			for (const auto& workspace : workspaces_)
			{
				auto include_connections = session.request().query().get<bool>("connections", false);

				std::stringstream ss;
				for (const auto& workgroup : *workspace.second)
				{
					if (include_connections)
						ss << workgroup.second->upstreams_.to_string(
							workspace.first, http::basic::async::upstreams::options::include_connections);
					else
						ss << workgroup.second->upstreams_.to_string(
							workspace.first, http::basic::async::upstreams::options::upstreams_only);
				}

				session.response().body() += ss.str();
			}

			session.response().status(http::status::ok);
		});

		server_base::router_.on_proxy_pass("/", [this](http::session_handler& session) {
			auto tenant_id = session.request().get<std::string>("X-Infor-TenantId", "tenant000_prd");
			auto workgroup_name = session.request().get<std::string>("X-WorkGroup-Name", "untitled");
			auto workgroup_type = session.request().get<std::string>("X-WorkGroup-Type", "bshells");
			auto workspace = workspaces_.get_tenant_workspace(tenant_id);


			bool forwarded = false;

			if (workspace != nullptr)
			{
				auto workgroup = workspace->find_workgroups(workgroup_name, workgroup_type);

				if (workgroup != workspace->end() && workgroup->second->has_workers_available())
				{
					if (session.protocol() == http::protocol::https)
					{
						session.request().set("X-Forwarded-Proto", "https");
						
						session.request().set(
							"X-Forwarded-Host",
							session.request().get<std::string>("X-Forwarded-Host", server_base::configuration_.get<std::string>("https_this_server_base_host", "")));
					}

					forwarded = true;
					session.request().set_attribute<http::basic::async::upstreams*>(
						"proxy_pass", &workgroup->second->upstreams_);
				}
			}

			if (forwarded == false)
			{
				server_base::logger().access_log("--------proxy error----------\n {s}", session.response().body());
				session.response().status(http::status::bad_gateway);
			}
		});

		server_base::router_.on_internal_error([this](http::session_handler& session, std::exception& e) {
			server_base::logger().access_log(
				"api-error with requested url: \"{s}\", error: \"{s}\", and request body:\n \"{s}\"",
				session.request().url_requested(),
				e.what(),
				http::to_string(session.request()));
			set_error_response(session, http::status::bad_request, "", e.what());
		});
	}

	virtual ~manager() {}

	// const http::configuration& configuration() { return configuration_; }

	http::basic::server::state start() override
	{
		auto ret = server_base::start();

		director_thread_ = std::thread{ [this]() { director_handler(); } };

		return ret;
	}

	void to_json(json& j) const
	{
		json applications_json;
		json workspaces_json;
		applications_.to_json(applications_json);
		workspaces_.to_json(workspaces_json);

		j["applications"] = applications_json;
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
				workspaces_.direct_workspaces(server_base::configuration_, server_base::logger_);

				json manager_json = json::object();
				to_json(manager_json);

				std::ifstream prev_configuration_file{ configuration_file_, std::ios::binary };
				std::ofstream bak_config_file{ configuration_file_ + ".bak", std::ios::binary };

				bak_config_file << prev_configuration_file.rdbuf();
				prev_configuration_file.close();

				std::ofstream new_config_file{ configuration_file_ };

				new_config_file << std::setw(4) << manager_json;

				if (new_config_file.fail() == false)
					server_base::logger_.api("managing: config saved to: \"{s}\"\n", configuration_file_);
			}

			std::this_thread::sleep_for(std::chrono::seconds(5));
		}
	}

public:
	virtual void set_error_response(
		http::session_handler& session,
		http::status::status_t status,
		const std::string& code,
		const std::string& message)
	{

		session.response().status(status);
		session.response().type("application/json");
		json error{
			{ "code", status },
		};
		error["error"].emplace_back(json{ { "code", code }, { "message", message } });

		session.response().body() = error.dump();
		server_base::logger().error("{s}, json{s}\n", session.request().url_requested(), session.response().body());
	}

	virtual void set_json_response_catch(http::session_handler& session, const json::type_error& error)
	{
		set_error_response(session, http::status::bad_request, std::to_string(error.id), error.what());
	}
	virtual void set_json_response_catch(http::session_handler& session, const json::exception& error)
	{
		set_error_response(session, http::status::bad_request, std::to_string(error.id), error.what());
	}

	virtual void set_json_response_catch(http::session_handler& session, const std::exception& error)
	{
		set_error_response(session, http::status::bad_request, "general error", error.what());
	}

	virtual void send_response(http::session_handler& session, http::status::status_t status)
	{
		session.response().status(status);
		session.response().body();
	}

	virtual void send_json_response(http::session_handler& session, http::status::status_t status, json j)
	{
		session.response().status(status);
		session.response().type("application/json");
		session.response().body() = j.dump();
	}

	virtual void send_no_content_response(http::session_handler& session)
	{
		session.response().status(http::status::no_content);
		session.response().body() = std::string("");
		// session.response().set("Connection","close");
	}

	virtual void send_not_found_response(http::session_handler& session)
	{
		session.response().status(http::status::not_found);
		session.response().body() = std::string("");
		// session.response().set("Connection","close");
	}

	virtual void wait4shutdown(void)
	{
		shutdown_future = shutdown_promise.get_future();
		int shutdown = shutdown_future.get();
		std::this_thread::sleep_for(std::chrono::seconds(shutdown));
		server_base::deactivate();
	}

	virtual void send_illegal_workspace_response(
		http::session_handler& session,
		const std::string& w_id,
		http::status::status_t status = http::status::not_found)
	{
		set_error_response(session, status, "null", "workspace_id " + w_id + " not found");
	}
};

static std::unique_ptr<manager<http::basic::async::server>> cpm_server_;

namespace selftest
{
inline bool headers_8kb()
{
	bool result = false;
	std::string error_code;
	http::client::session session;

	std::string payload{};

	auto headers
		= { std::string{ "X-Infor-TenantId: tenant000_prd" },
			std::string{ "X-00-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-01-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-02-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-03-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" } };

	auto response = http::client::request<http::method::post>(
		session, "http://localhost:4000/api/test", error_code, headers, payload, std::cerr, false);

	return result;
}

inline bool headers_16kb()
{
	bool result = false;
	std::string error_code;
	http::client::session session;

	std::string payload{};

	auto headers
		= { std::string{ "X-Infor-TenantId: tenant000_prd" },
			std::string{ "X-00-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-01-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-02-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-03-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-04-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-05-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-06-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-07-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
			std::string{ "X-08-"
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" } };

	auto response = http::client::request<http::method::post>(
		session, "http://localhost:4000/api/test", error_code, headers, payload, std::cerr, false);

	return result;
}

inline bool body_1mb()
{
	bool result = false;
	std::string error_code;
	http::client::session session;

	std::string payload;

	payload.assign(1024 * 1024, 'a');

	auto response = http::client::request<http::method::post>(
		session, "http://localhost:4000/api/test", error_code, { "X-Infor-TenantId: tenant000_prd" }, payload);

	return result;
}

inline bool post_empty_workspace()
{
	bool result = false;
	std::string error_code;
	http::client::session session;

	std::string payload;

	payload.assign(
		"{\"workspaces\":[{\"description\":\"workspace_000\",\"id\":\"workspace_000\",\"tenant_id\":\"tenant000_prd\"}]"
		"}");

	auto response = http::client::request<http::method::post>(
		session, "http://localhost:4000/private/infra/workspaces/workspace_000", error_code, {}, payload);

	return result;
}

inline bool get_empty_workspace()
{
	bool result = false;
	std::string error_code;
	http::client::session session;

	std::string payload;

	auto response = http::client::request<http::method::get>(
		session, "http://localhost:4000/private/infra/workspaces/workspace_000", error_code, {});

	return result;
}

inline bool post_test_workgroup_to_empty_workspace()
{
	bool result = false;
	std::string error_code;
	http::client::session session;

	std::string payload;

	payload.assign(
		"{\"workgroups\": [{\"details\" : {\"bse\" : \"D:/Infor/lnmsql/bse\",\"bse_bin\" : "
		"\"\\\\\\\\view\\\\enha_BDNT79248.NLBAWPSET7.ndjonge\\\\obj.dbg.WinX64\\bin\",\"bse_user\" : "
		"\"ndjonge\",\"cli_options\" :\"-httpserver -delay 0 -install -set HTTP_BOOT_PROCESS=otttsthttpboot "
		"D:/Infor/lnmsql/bse/http/t.o\",\"http_options\" : "
		"\"http_watchdog_timeout:60,log_level:access_log\",\"os_password\" : "
		"\"$2S$80EEA66DF8FBAEB005D7210E2372952C\",\"os_user\" : \"ndjonge@infor.com\",\"program\" : "
		"\"ntbshell.exe\",\"startobject\" : \"\"},\"limits\" : {\"workers_actual\" : 10,\"workers_max\" : "
		"10,\"workers_min\" : 10,\"workers_pending\" : 0,\"workers_required\" : 10},   \"name\" : "
		"\"untitled\",\"type\": \"bshells\"}]}");

	auto response = http::client::request<http::method::post>(
		session,
		"http://localhost:4000/private/infra/workspaces/workspace_000/workgroups/untitled",
		error_code,
		{},
		payload);

	return result;
}

inline bool run()
{
	bool result = false;

	result = headers_8kb();
	result = headers_16kb();
	result = body_1mb();

	result = post_empty_workspace();
	result = get_empty_workspace();
	result = post_test_workgroup_to_empty_workspace();

	return result;
}

} // namespace selftest

} // namespace platform
} // namespace cloud

#if 0
static void Daemonize()
{
	int devnull = open("/dev/null", O_RDWR);
	if (devnull > 0) {

	}

}
#endif

inline int start_cld_manager_server(std::string config_file, std::string config_options, bool, bool selftest = false)
{
	std::string server_version = std::string{ "ln-cld-mgr" };

	http::configuration http_configuration{ { { "server", server_version },
											  { "http_listen_port_begin", "4000" },
											  { "private_base", "/private/infra/manager" },
											  { "log_level", "api" },
											  { "log_file", "cout" },
											  { "https_enabled", "false" },
											  { "http_enabled", "true" },
											  { "http_use_portsharding", "false" } },
											config_options };

	if (selftest)
	{
		auto base_path = config_file.find_last_of("/\\");

		if (base_path != std::string::npos)
		{
			config_file = config_file.substr(0, base_path);
			config_file += "/test.json";
		}
	}

	cloud::platform::cpm_server_ = std::unique_ptr<cloud::platform::manager<http::basic::async::server>>(
		new cloud::platform::manager<http::basic::async::server>(http_configuration, config_file));

	cloud::platform::cpm_server_->start();

	if (selftest)
	{
		cloud::platform::selftest::run();
	}

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
		  { "foreground", { prog_args::arg_t::flag, "run in foreground" } } });

	if (cmd_args.process_args() == false)
	{
		std::cout << "error in arguments \n";
		exit(1);
	}

	return start_cld_manager_server(
		cmd_args.get_val("cld_config"), cmd_args.get_val("cld_options"), cmd_args.get_val("foreground") == "true");
}

inline int stop_cld_manager_server()
{
	cloud::platform::cpm_server_->stop();
	cloud::platform::cpm_server_.release();

	return 0;
}

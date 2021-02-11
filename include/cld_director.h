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
	std::set<S> available_sockets_;
	std::mutex m_;

	test_sockets(S b, size_t nr)
	{
		std::lock_guard<std::mutex> g{ m_ };
		for (S i = 0; i < nr; i++)
			available_sockets_.emplace(b + i);
	}

	S aquire()
	{
		std::lock_guard<std::mutex> g{ m_ };

		auto port = *(available_sockets_.begin());
		available_sockets_.erase(port);
		return port;
	}

	S aquire(S port)
	{
		std::lock_guard<std::mutex> g{ m_ };

		available_sockets_.erase(port);

		return port;
	}

	void release(const std::string& url)
	{
		std::lock_guard<std::mutex> g{ m_ };
		auto port = url.substr(1 + url.find_last_of(':'));

		available_sockets_.emplace(stoul(port));
	}
};

static test_sockets<std::uint32_t> _test_sockets{ 8000, 32 };
} // namespace local_testing

static bool create_bse_process_as_user(
	const std::string&,
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

	pid = local_testing::_test_sockets.aquire();

	ec = "";

	std::thread([pid, worker_label, worker_id]() {
		std::lock_guard<std::mutex> g{ local_testing::m };
		json put_new_instance_json = json::object();
		std::string ec;
		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["worker_label"] = worker_label;
		put_new_instance_json["base_url"] = "http://localhost:" + std::to_string(pid);
		put_new_instance_json["version"] = "test_bshell";

		auto response = http::client::request<http::method::put>(
			"http://localhost:4000/private/infra/workspaces/workspace_000/workgroups/untitled/bshells/workers/" + worker_id,
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
	http::async::upstreams::upstream* upstream_{nullptr};

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


	void worker_label(const std::string& level)
	{ 
		worker_label_ = level;
	}

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
		auto ret = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - startup_t1_).count();

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

	void
	add_worker(const std::string& worker_id, const std::string& worker_label, const json& j, asio::io_context& io_context)
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
				io_context, base_url, "/" + name_ + "/" + type_ + "/"  + worker_id + "_" + worker_label);

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
				upstreams_.erase_upstream(worker->second.get_base_url());
				limits_.workers_actual_upd(-1);
			}
			worker = workers_.erase(worker);
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
				worker->second.get_base_url() + "/private/infra/worker/process", ec, {});

			if (response.status() == http::status::no_content) 
			{
				worker->second.set_status(worker::status::down);
				result = true;
			}
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

	virtual void from_json(const json& j, const std::string& detail) = 0;
	virtual void to_json(json& j, const std::string& detail) const = 0; 

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
			return workers_required_ - (workers_actual_ + workers_pending_ );
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

		void workers_not_on_label_required(std::int16_t value) 
		{ 
			workers_not_on_label_required_ = value;
		}

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
					workers_start_at_once_max_ += j.value("workers_start_at_once_max", std::int16_t{4});
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
			if (limit_name.empty() || limit_name == "workers_not_at_label_required")
			{
				j["workers_not_at_label_required"] = workers_not_on_label_required_;
			}
			if (limit_name.empty() || limit_name == "workers_runtime_max")
			{
				j["workers_runtime_max"] = workers_runtime_max_;
			}
			if (limit_name.empty() || limit_name == "workers_requests_max")
			{
				j["workers_requests_max"] = workers_requests_max_;
			}
			if (limit_name.empty() || limit_name == "workers_label_required")
			{
				j["workers_label_required"] = workers_label_required_;
			}
			if (limit_name.empty() || limit_name == "workers_requests_max")
			{
				j["workers_label_actual"] = workers_label_actual_;
			}
			if (limit_name.empty() || limit_name == "workers_start_at_once_max")
			{
				j["workers_start_at_once_max"] = workers_start_at_once_max_;
			}
		}

	private:
		std::int16_t workers_pending_{ 0 };
		std::int16_t workers_required_{ 0 };
		std::int16_t workers_actual_{ 0 };
		std::int16_t workers_not_on_label_required_{ 0 };

		std::int16_t workers_min_{ 0 };
		std::int16_t workers_max_{ 0 };

		std::string workers_label_required_{ };
		std::string workers_label_actual_{ };

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
			auto workers_required_to_add = limits_.workers_required_to_add();
			auto workers_label_required = limits_.workers_label_required();
			auto workers_runtime_max = limits_.workers_runtime_max();
			auto workers_requests_max = limits_.workers_requests_max();

			if (limits_.workers_required() > 0)
			{
				logger.api(
					"/{s}/{s}/{s} actual: {d}, pending: {d}, required: {d}, min: {d}, max: {d}, label_required: {s}, label_actual: {s}\n",
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
					if (worker_it->second.get_base_url().empty()) // TODO change to status?
					{
						++worker_it;
						continue;
					}
					auto& worker = worker_it->second;
					auto worker_label = worker_it->second.worker_label();
					auto worker_runtime = worker_it->second.runtime();
					auto worker_requests = worker_it->second.upstream().responses_tot_.load();

					if (worker_label != workers_label_required)
					{
						worker.set_status(worker::status::drain);
						workers_required_to_add++;

						if (workers_required_to_add == 0)
						{
							break;
						}
					}
					else if (worker_requests >= workers_requests_max)
					{
						worker.set_status(worker::status::drain);
						workers_required_to_add++;

						if (workers_required_to_add == 0)
						{
							break;
						}
					}
					else if (worker_runtime >= workers_runtime_max)
					{
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
					if (worker_it->second.get_base_url().empty()) // TODO change to status?
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
							"/"+ name_ + "/" + type_ + "/" + worker_it->first + "/" + worker_it->second.worker_label());

						worker_it->second.upstream(upstream);

						worker_it->second.set_status(worker::status::up);
	
					}

					if (worker_it->second.get_status() == worker::status::up)
					{
						auto workers_feed_watchdog = workers_watchdogs_feeded++ < limits_.workers_min();

						http::headers watchdog_headers{ { "Host", "localhost" }, { "X-Feed-Watchdog", workers_feed_watchdog ? "true" : "false" }};

						http::client::async_request<http::method::post>(
							upstreams_,
							worker_it->second.get_base_url(),
							"/private/infra/worker/watchdog",
							watchdog_headers,
							std::string{},
							[this, &worker, &logger](
								http::response_message& response, asio::error_code& error_code) {
								if (!error_code && response.status() == http::status::ok
									&& worker.get_status() != worker::status::up)
								{
									worker.set_status(worker::status::up);
								}
								else if (error_code || response.status() != http::status::ok)
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

//				limits_.workers_refresh_actual(workers_on_label_required);
				auto workers_to_start = workers_not_on_label_required;
				limits_.workers_not_on_label_required(workers_not_on_label_required);

				if (workers_on_label_required + limits_.workers_pending() != limits_.workers_required())
				{
					workers_to_start = workers_not_on_label_required;
				} 
				else if (workers_responses_max_reached > 0)
				{
					workers_to_start = workers_responses_max_reached;
				}
				else if (workers_runtime_max_reached > 0)
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
							"/{s}/{s}/{s}: delete {s}\n",
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
		std::unique_lock<std::mutex> guard( workgroups::workers_mutex_ );

		workgroups::from_json(j);
		try
		{ // TODO optional parameters bse, bse_bin, bse_user, os_user and os_password.
			j["parameters"].at("bse").get_to(bse_);
			j["parameters"].at("bse_bin").get_to(bse_bin_);
			j["parameters"].at("bse_user").get_to(bse_user_);
			j["parameters"].at("os_user").get_to(os_user_);
			j["parameters"].at("os_password").get_to(os_password_);
		}
		catch (json::exception&)
		{
		}

		j["parameters"].at("program").get_to(program_);
		j["parameters"].at("cli_options").get_to(cli_options_);
		j["parameters"].at("http_options").get_to(http_options_);

		std::int16_t workers_added = 0;
		
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

			if (base_url.empty() == false)
			{
				auto base_url_split = util::split(base_url, ":");
				auto port = std::atoi(base_url_split[2].c_str());

				bse_utils::local_testing::_test_sockets.aquire(port);

			}

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
		if (detail.empty() || ((detail == "bse") && (bse_.empty() == false))) 
			j["parameters"].emplace("bse", bse_);

		if (detail.empty() || ((detail == "bse_user") && (bse_bin_.empty() == false)))
			j["parameters"].emplace("bse_bin", bse_bin_);

		if (detail.empty() || ((detail == "bse_user") && (bse_user_.empty() == false))) 
			j["parameters"].emplace("bse_user", bse_user_);

		if (detail.empty() || ((detail == "os_user") && (os_user_.empty() == false)))
			j["parameters"].emplace("os_user", os_user_);

		if (detail.empty() || ((detail == "os_password") && (os_password_.empty() == false))) 
			j["parameters"].emplace("os_password", os_password_);

		if (detail.empty() || detail == "program") 
			j["parameters"].emplace("program", program_);

		if (detail.empty() || detail == "cli_options")
			j["parameters"].emplace("cli_options", cli_options_);

		if (detail.empty() || detail == "http_options")
			j["parameters"].emplace("http_options", http_options_);
	}

	void to_json(json& j) const override
	{
		workgroups::to_json(j);

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

	void worker_ids_begin(std::uint32_t id) 
	{ 
		worker_ids_ = worker_ids_.load() <= id ? id + 1 : worker_ids_.load();
	}

public :
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
		json d(j.at("parameters"));
		d.at("python_root").get_to(rootdir);
	}

	void from_json(const json& j, const std::string& detail) override
	{ 
		if (detail.empty() || detail == "python_root")
			rootdir = j["parameters"].value("python_root", "");
	};

	void to_json(json& j, const std::string& detail) const override
	{ 
		if (detail.empty() || detail == "python_root")
			j["parameters"].emplace("python_root", rootdir);
	}

	void to_json(json& j) const override
	{
		workgroups::to_json(j);
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

private:
	std::string server_endpoint_;
	std::string workspace_id_{};
	std::string tenant_id_{};
	std::string description_{};
	std::string default_group_{};

	std::vector<std::string> errors;
	container_type workgroups_;

public:
	workspace(const std::string workspace_id, const json& json_workspace) : workspace_id_(workspace_id)
	{
		from_json(json_workspace);
	}

	workspace(const workspace&) = delete;

	const std::string& default_group() const { return default_group_; }
	void default_group(const std::string& default_group) { default_group_ = default_group; }

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
		workspace["default_group"] = default_group_;

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
		description_ = j.value("description", "");
		tenant_id_ = j.value("tenant_id", "");
		default_group_ = j.value("default_group", "untitled");

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

	void direct_workspaces(asio::io_context& io_context, const http::configuration& configuration, lgr::logger& logger)
	{
		auto t0 = std::chrono::steady_clock::now();
		for (auto& workspace : workspaces_)
		{
			std::unique_lock<mutex_type> l{ workspaces_mutex_ };
			json empty_limits_adjustments = json::object();
			for (auto& workgroup : *workspace.second)
				workgroup.second->direct_workers(io_context, configuration, logger);
		}
		auto t1 = std::chrono::steady_clock::now();

		auto elapsed = t1 - t0;
		logger.info("{u} workspaces took {d}msec\n", workspaces_.size(), elapsed.count() / 1000000);
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

	std::string configuration_file_;

public:
	manager(http::configuration& http_configuration, const std::string& configuration_file)
		: http::async::server(http_configuration), configuration_file_(configuration_file)
	{
		//server_base::logger().api("load registry\n");

		//server_base::router().use_registry(
		//	"/",
		//	"C:/tmp/pm_root/route_registry/ttwebcontexts.json", // TODO
		//	[this](const std::string& error) {
		//		server_base::logger().api("{s}\n", error);
		//		return false;
		//	},
		//	[this](
		//		const std::string& service,
		//		const std::string& name,
		//		const std::string& path,
		//		const std::string& type,
		//		const std::string& pre_attribute,
		//		const std::string& post_attribute) {
		//		server_base::logger().api(
		//			"\\--middleware--> {s} {s} {s} {s} {s} {s}\n",
		//			service,
		//			name,
		//			path,
		//			type,
		//			pre_attribute,
		//			pre_attribute);

		//		server_base::router().use_middleware(service, name, path, type, pre_attribute, post_attribute);
		//	},
		//	[this](
		//		const std::string& service,
		//		const std::string& name,
		//		http::method::method_t method,
		//		const std::string& route,
		//		const std::vector<std::string>& consumes,
		//		const std::vector<std::string>& produces) {
		//		server_base::logger().api(
		//			"\\--route---{s}-{s}->{s}|{s} [{s}/{s}]\n",
		//			service,
		//			name,
		//			route,
		//			http::method::to_string(method),
		//			"",
		//			"");

		//		server_base::router().on_http_method(
		//			service, name, method, route, consumes, produces, [](http::session_handler&) {});
		//	}

		//);
		//auto search_result = server_base::router().search("library-v1", "members");

		std::ifstream configuration_stream{ configuration_file_ };

		auto configfile_available = configuration_stream.fail() == false;

		if (configfile_available)
		{
			try
			{
				json manager_configuration_json = json::parse(configuration_stream);
				
				if (manager_configuration_json.contains("applications") == true)
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

		server_base::router_.on_get("/health", [](http::session_handler& session) {
			session.response().status(http::status::ok);
			session.response().type("text");
			session.response().body() = std::string("Ok") + session.request().body();
		});

		server_base::router_.on_post("/private/infra/manager/mirror", [](http::session_handler& session) {
			session.response().status(http::status::ok);
			session.response().type(session.response().get<std::string>("Content-Type", "text/plain"));
			session.response().body() = session.request().body();
		});

		server_base::router_.on_post("/private/infra/manager/log_level", [this](http::session_handler& session) {
			server_base::logger_.set_level(session.request().body());
			auto new_level = server_base::logger_.current_level_to_string();
			http::server::configuration_.set("log_level", new_level);
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
				session.response().body() = "{ \"version\" : \"" + util::escape_json(version) + "\"}";
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
				server_base::manager().server_information(http::server::configuration_.to_json_string());
				server_base::manager().router_information(server_base::router_.to_json_string());
				session.response().body()
					= server_base::manager().to_json_string(http::server::server_manager::json_status_options::full);
				session.response().type("json");
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

		server_base::router_.on_get("/private/infra/manager/status/{section}", [this](http::session_handler& session) {
			auto section_option = http::server::server_manager::json_status_options::full;
			const auto& section = session.params().get("section");

			if (section == "metrics")
			{
				section_option = http::server::server_manager::json_status_options::server_metrics;
			}
			else if (section == "configuration")
			{
				server_base::manager().server_information(http::server::configuration_.to_json_string());
				section_option = http::server::server_manager::json_status_options::config;
			}
			else if (section == "router")
			{
				server_base::manager().router_information(server_base::router_.to_json().dump());
				section_option = http::server::server_manager::json_status_options::router;
			}
			else if (section == "access_log")
			{
				section_option = http::server::server_manager::json_status_options::access_log;
			}
			else
			{
				session.response().status(http::status::not_found);
				return;
			}

			session.response().body() = server_base::manager().to_json_string(section_option, false);
			session.response().type("json");
			session.response().status(http::status::ok);
		});

		server_base::router_.on_get("/private/infra/workspaces", [this](http::session_handler& session) {
			json workspaces_json{};
			workspaces_.to_json(workspaces_json);

			json result_json = json::object();
			result_json["workspaces"] = workspaces_json;

			session.response().assign(http::status::ok, result_json.dump(), "application/json");
		});

		server_base::router_.on_get("/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
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

		server_base::router_.on_post(
			"/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					session.response().assign(http::status::conflict);

					return;
				}

				json workspace_json = json::parse(session.request().body());

				for (auto& workspaces : workspace_json["workspaces"].items())
				{
					workspaces.value()["id"] = workspace_id;
					workspaces_.add_workspace(workspace_id, workspaces.value());
				}

				session.response().assign(http::status::ok);
			});

		server_base::router_.on_delete(
			"/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				if (workspaces_.delete_workspace(workspace_id))
				{
					session.response().assign(http::status::conflict);
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
			"/private/infra/workspaces/{workspace_id}/workgroups", [this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto w = workspaces_.get_workspace(workspace_id);

				if (w != workspaces_.end())
				{
					json result;
					result["workgroups"] = json::array();

					for (auto i = w->second->cbegin(); i != w->second->cend(); ++i)
					{
						json workgroups_json;
						i->second->to_json(workgroups_json);

						result["workgroups"].emplace_back(workgroups_json);
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
							session.response().assign(http::status::conflict);
							return;
						}
					}

					json workgroups_json = json::parse(session.request().body());
					workspace->second->add_workgroups(name, "", workgroups_json["workgroups"]);

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
						session.response().assign(http::status::accepted);
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
							session.response().assign(http::status::conflict);
							return;
						}
					}

					json workgroups_json = json::parse(session.request().body());
					workspace->second->add_workgroups(name, type, workgroups_json["workgroups"]);

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
						session.response().assign(http::status::accepted);
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
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/parameters/{detail}",
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
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/parameters/{detail}",
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
						const std::string& worker_label = worker_json["worker_label"];

						auto workgroups = workspace->second->find_workgroups(name, type);

						if (workgroups != workspace->second->end())
						{
							workgroups->second->add_worker(
								worker_id, worker_label, worker_json, server_base::get_io_context());
						}

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
						session.response().assign(http::status::accepted);
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
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}/label",
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
							//worker->second.set_status(worker::status::drain);
							worker->second.worker_label("");
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
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/workers/{worker_id}/process",
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
							server_base::get_io_context(),
							server_base::configuration_,
							server_base::logger_,
							limit_name,
							limits,
							workgroups::limits::from_json_operation::set);
						workgroups->second->workgroups_limits().to_json(limits["limits"]);

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
							server_base::get_io_context(),
							server_base::configuration_,
							server_base::logger_,
							limit_name,
							limits,
							workgroups::limits::from_json_operation::add);

						workgroups->second->workgroups_limits().to_json(limits["limits"]);

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

		server_base::router_.on_get("/private/infra/manager/upstreams", [this](http::session_handler& session) {
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
			auto tenant_id = session.request().get<std::string>("X-Infor-TenantId", "");
			auto workspace = workspaces_.get_tenant_workspace(tenant_id);

			bool forwarded = false;

			if (workspace != nullptr)
			{
				auto workgroup_name
					= session.request().get<std::string>("X-Infor-Upstream-Group", workspace->default_group());

				auto workgroup_type = session.request().get<std::string>("X-Infor-Upstream-Type", "bshells");
				auto workgroup = workspace->find_workgroups(workgroup_name, workgroup_type);

				if (workgroup != workspace->end() && workgroup->second->has_workers_available())
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

					forwarded = true;
					session.request().set_attribute<http::async::upstreams*>(
						"proxy_pass", &workgroup->second->upstreams_);
				}
			}

			if (forwarded == false)
			{
				session.response().status(http::status::not_found);
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
				workspaces_.direct_workspaces(server_base::get_io_context(), server_base::configuration_, server_base::logger_);

				json manager_json = json::object();
				to_json(manager_json);

				std::ifstream prev_configuration_file{ configuration_file_, std::ios::binary };
				std::ofstream bak_config_file{ configuration_file_ + ".bak", std::ios::binary };

				bak_config_file << prev_configuration_file.rdbuf();
				prev_configuration_file.close();

				std::ofstream new_config_file{ configuration_file_ };

				new_config_file << std::setw(4) << manager_json;

				if (new_config_file.fail() == false)
					server_base::logger_.info("config saved to: \"{s}\"\n", configuration_file_);
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

// namespace selftest
//{
// inline bool headers_8kb()
//{
//	bool result = false;
//	std::string error_code;
//	http::client::session session;
//
//	std::string payload{};
//
//	auto headers
//		= { std::string{ "X-Infor-TenantId: tenant000_prd" },
//			std::string{ "X-00-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-01-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-02-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-03-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" } };
//
//	auto response = http::client::request<http::method::post>(
//		session, "http://localhost:4000/api/test", error_code, headers, payload, std::cerr, false);
//
//	return result;
//}
//
// inline bool headers_16kb()
//{
//	bool result = false;
//	std::string error_code;
//	http::client::session session;
//
//	std::string payload{};
//
//	auto headers
//		= { std::string{ "X-Infor-TenantId: tenant000_prd" },
//			std::string{ "X-00-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-01-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-02-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-03-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-04-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-05-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-06-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-07-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" },
//			std::string{ "X-08-"
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF00: "
//						 "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC"
//						 "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
//						 "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
//						 "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
//						 "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
//						 "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF000" } };
//
//	auto response = http::client::request<http::method::post>(
//		session, "http://localhost:4000/api/test", error_code, headers, payload, std::cerr, false);
//
//	return result;
//}
//
// inline bool body_1mb()
//{
//	bool result = false;
//	std::string error_code;
//	http::client::session session;
//
//	std::string payload;
//
//	payload.assign(1024 * 1024, 'a');
//
//	auto response = http::client::request<http::method::post>(
//		session, "http://localhost:4000/api/test", error_code, { "X-Infor-TenantId: tenant000_prd" }, payload);
//
//	return result;
//}
//
// inline bool post_empty_workspace()
//{
//	bool result = false;
//	std::string error_code;
//	http::client::session session;
//
//	std::string payload;
//
//	payload.assign(
//		"{\"workspaces\":[{\"description\":\"workspace_000\",\"id\":\"workspace_000\",\"tenant_id\":\"tenant000_prd\"}]"
//		"}");
//
//	auto response = http::client::request<http::method::post>(
//		session, "http://localhost:4000/private/infra/workspaces/workspace_000", error_code, {}, payload);
//
//	return result;
//}
//
// inline bool get_empty_workspace()
//{
//	bool result = false;
//	std::string error_code;
//	http::client::session session;
//
//	std::string payload;
//
//	auto response = http::client::request<http::method::get>(
//		session, "http://localhost:4000/private/infra/workspaces/workspace_000", error_code, {});
//
//	return result;
//}
//
// inline bool post_test_workgroup_to_empty_workspace()
//{
//	bool result = false;
//	std::string error_code;
//	http::client::session session;
//
//	std::string payload;
//
//	payload.assign(
//		"{\"workgroups\": [{\"details\" : {\"bse\" : \"D:/Infor/lnmsql/bse\",\"bse_bin\" : "
//		"\"\\\\\\\\view\\\\enha_BDNT79248.NLBAWPSET7.ndjonge\\\\obj.dbg.WinX64\\bin\",\"bse_user\" : "
//		"\"ndjonge\",\"cli_options\" :\"-httpserver -delay 0 -install -set HTTP_BOOT_PROCESS=otttsthttpboot "
//		"D:/Infor/lnmsql/bse/http/t.o\",\"http_options\" : "
//		"\"http_watchdog_timeout:60,log_level:access_log\",\"os_password\" : "
//		"\"$2S$80EEA66DF8FBAEB005D7210E2372952C\",\"os_user\" : \"ndjonge@infor.com\",\"program\" : "
//		"\"ntbshell.exe\",\"startobject\" : \"\"},\"limits\" : {\"workers_actual\" : 10,\"workers_max\" : "
//		"10,\"workers_min\" : 10,\"workers_pending\" : 0,\"workers_required\" : 10},   \"name\" : "
//		"\"untitled\",\"type\": \"bshells\"}]}");
//
//	auto response = http::client::request<http::method::post>(
//		session,
//		"http://localhost:4000/private/infra/workspaces/workspace_000/workgroups/untitled",
//		error_code,
//		{},
//		payload);
//
//	return result;
//}
//
// inline bool run()
//{
//	bool result = false;
//
//	result = headers_8kb();
//	result = headers_16kb();
//	result = body_1mb();
//
//	result = post_empty_workspace();
//	result = get_empty_workspace();
//	result = post_test_workgroup_to_empty_workspace();
//
//	return result;
//}
//
//} // namespace selftest

} // namespace platform
} // namespace cloud


inline int start_cld_manager_server(std::string config_file, std::string config_options, bool run_as_daemon)
{
	std::string server_version = std::string{ "ln-cld-mgr" };

	if (run_as_daemon) util::daemonize("/tmp", "/var/lock/" + server_version + ".pid");

	http::configuration http_configuration{ { { "server", server_version },
											  { "http_listen_port_begin", "4000" },
											  { "private_base", "/private/infra/manager" },
											  { "private_ip_white_list", "::ffff:172.31.238.0/120;::1/128;::ffff:127.0.0.0/120;::ffff:127.1.0.0/120" },
											  { "public_ip_white_list", "::ffff:172.31.238.0/120;::1/128;::ffff:192.168.1.0/120;::ffff:127.0.0.1/128" },
											  { "log_level", "trafic:access_log_all;admin:access_log_all" },
											  { "log_file", "trafic:access_log.txt;admin:console" },
											  { "https_enabled", "false" },
											  { "http_enabled", "true" },
											  { "http_use_portsharding", "false" } },
											config_options };



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
		  { "daemonize", { prog_args::arg_t::flag, "run as daemon" } } });

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

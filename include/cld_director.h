#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#define CURL_STATICLIB

#ifndef LOCAL_TESTING
#include "baanlogin.h"
#include "bdaemon.h"
#include "nlohmann_json.hpp"
#include <curl/curl.h>

#ifdef _WIN32
#include "sspisecurity.h"
#include <direct.h>
#include <process.h>
#define HOST_NAME_MAX 256
#endif

#else
#define get_version_ex(PORT_SET, NULL) "version 1.0"
#define BAAN_WINSTATION_NAME "baan"
#define BAAN_DESKTOP_NAME "desktop"
#define PORT_SET "9.4x"

#include <nlohmann/json.hpp>
#endif

#include "http_basic.h"
#include "http_network.h"
#include "prog_args.h"

using json = nlohmann::json;

#ifdef LOCAL_TESTING

namespace
{
using SCK_t = network::socket_t;

int CheckUserInfo(
	const char* ,
	const char* ,
	const char* ,
	SCK_t ,
	char* ,
#ifdef _WIN32
	size_t ,
	HANDLE* aUserToken
#else
	size_t errorStringBufSize
#endif
)
{
#ifdef _WIN32
	aUserToken = nullptr;
#endif
	return 0;
}
}
#endif

namespace bse_utils
{

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
	auto user_ok = CheckUserInfo(user.data(), password.data(), NULL, 0, NULL, 0);
#else
	HANDLE requested_user_token = 0;
	auto user_ok = CheckUserInfo(user.data(), password.data(), NULL, 0, NULL, 0, &requested_user_token);

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

		error = 0;
		result = CreateProcessAsUser(
			requested_user_token, /* Handle to logged-on user */
			NULL, /* module name */
			const_cast<LPSTR>(command.data()), /* command line */
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
		const char* required_environment_vars[] = { "PATH",		 "CLASSPATH",	 "CLASSPATH", "SLMHOME", "SLM_RUNTIME",
													"SLM_DEBUG", "SLM_DEBUFILE", "HOSTNAME",  "TMP",	 "TEMP" };

		std::vector<char*> envp;

		std::string environment_block;
		std::stringstream ss;

		ss << "BSE=" << bse << char{ 0 };
		envp.push_back(strdup(ss.str().data()));
		std::stringstream().swap(ss);

		ss << "SYSTEMLIBDIR64=" << bse << "/shlib"
		   << ":" << getenv("SYSTEMLIBDIR64") << char{ 0 };
		envp.push_back(strdup(ss.str().data()));
		std::stringstream().swap(ss);

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
			if (ImpersonateUser(user.data(), NULL, 0, NULL) == -1)
			{
				printf("error on fork: %d\n", errno);
				_exit(1);
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

class worker_instance
{
public:
	enum class status
	{
		initial = 0,
		running = 1,
		deleted = 2,
		error = 3
	};

private:
	std::string base_url_{};
	std::string version_{};
	std::int32_t process_id_;
	status status_{ status::initial };
	json instance_metrics_{};

public:
	worker_instance() = default;
	worker_instance(const std::string& base_url, std::string version, std::int32_t process_id)
		: base_url_(base_url), version_(version), process_id_(process_id), status_(worker_instance::status::initial)
	{
	}

	worker_instance(const worker_instance& worker_instance)
		: base_url_(worker_instance.base_url_)
		, version_(worker_instance.version_)
		, process_id_(worker_instance.process_id_)
		, status_(worker_instance.status_)
	{
	}

	virtual ~worker_instance() { instance_metrics_.clear(); };

	const std::string& get_base_url() const { return base_url_; };
	int get_process_id() const { return process_id_; };

	std::string get_status() const
	{
		switch (status_)
		{
			case status::initial:
				return "initial";
			case status::running:
				return "running";
			case status::deleted:
				return "deleted";
			case status::error:
				return "error";
			default:
				return "not yet";
		}
	}
	void set_status(status s) { status_ = s; };

	void to_json(json& instance_json) const
	{
		if (!base_url_.empty())
		{
			instance_json["link_to_status_url"] = base_url_ + "/private/infra/worker/status";
			instance_json["base_url"] = base_url_;
			instance_json["version"] = version_;

			if (instance_metrics_.is_null() == false)
				for (auto metric = std::begin(instance_metrics_["metrics"]);
					 metric != std::end(instance_metrics_["metrics"]);
					 metric++)
					instance_json["metrics"][metric.key()] = metric.value();
		}
		instance_json["status"] = get_status();
		instance_json["process_id"] = process_id_;
		instance_json["started_at"] = std::time(nullptr);
	}

	json get_instance_metrics(void) { return instance_metrics_; }
	void set_instance_metrics(json& j) { instance_metrics_ = std::move(j); }
};

//
// Implementor
//
class workgroups
{

public:
	using container_type = std::map<const std::string, worker_instance>;
	using iterator = container_type::iterator;
	using const_iterator = container_type::const_iterator;

	workgroups(const std::string& workspace_id, const std::string& type)
		: workspace_id_(workspace_id), type_(type), tenant_(){};
	virtual ~workgroups() = default;

	iterator begin() { return worker_instances_.begin(); }
	iterator end() { return worker_instances_.end(); }
	const_iterator cbegin() const { return worker_instances_.cbegin(); }
	const_iterator cend() const { return worker_instances_.cend(); }

	virtual void direct_instaces(lgr::logger& logger) = 0;

	void cleanup(){};

	iterator find_instance(const std::string& instance_id)
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		return worker_instances_.find(instance_id);
	}

	void add_instance(const json& j)
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		std::int32_t process_id;
		std::string base_url;
		std::string version;

		j.at("process_id").get_to(process_id);

		base_url = j.value("base_url", "");
		version = j.value("version", "");

		worker_instances_[std::to_string(process_id)] = worker_instance{ base_url, version, process_id };

		if (base_url.empty() == false) limits_.instances_actual(limits_.instances_actual() + 1);
	}

	bool delete_instance(const std::string& pid)
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		bool result = false;

		auto worker_instance = worker_instances_.find(pid);

		if (worker_instance != worker_instances_.end())
		{
			if (worker_instance->second.get_base_url().empty() == false)
				limits_.instances_actual(limits_.instances_actual() - 1);

			worker_instance = worker_instances_.erase(worker_instance);
			result = true;
		}
		return result;
	}

	bool shutdown_instance_by_pid(const std::string& pid)
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		bool result = false;

		auto worker_instance = worker_instances_.find(pid);

		if (worker_instance != worker_instances_.end())
		{
			std::string ec;
			auto response = http::client::request<http::method::delete_>(
				worker_instance->second.get_base_url() + "/private/infra/worker/shutdown", ec, {});

			if (!ec.empty())
			{
				worker_instance->second.set_status(worker_instance::status::deleted);
				result = true;
			}
			else
			{
				worker_instance->second.set_status(worker_instance::status::error);
				result = false;
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
		// TODO instances....
	}

	virtual void to_json(json& j) const
	{
		j["name"] = name_;
		j["type"] = type_;

		json limits_json;
		limits_.to_json(limits_json);
		j["limits"] = limits_json;
		j["instances"] = json::array();
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		for (auto instance = worker_instances_.cbegin(); instance != worker_instances_.cend(); ++instance)
		{
			json instance_json;

			instance->second.to_json(instance_json);

			j["instances"].emplace_back(instance_json);
		}
	}

	virtual bool create_instance(
		const std::string& workspace_id,
		const std::string& worker_type,
		const std::string& worker_name,
		std::uint32_t& pid,
		std::string& ec)
		= 0;

	void remove_instance(worker_instance& worker_instance)
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		std::string ec;
		auto response = http::client::request<http::method::delete_>(
			worker_instance.get_base_url() + "/private/infra/worker/shutdown", ec, {});

		if (!ec.empty())
		{
			worker_instance.set_status(worker_instance::status::deleted); // mark as deleted
		}
		else
		{
			worker_instance.set_status(worker_instance::status::error);
		}
	}

	void keep_instance_alive(worker_instance& worker_instance)
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		std::string ec;

		auto response = http::client::request<http::method::post>(
			worker_instance.get_base_url() + "/private/infra/worker/status/idle_since", ec, {}, "0");

		if (ec.empty())
		{
		}
		else
		{
			worker_instance.set_status(worker_instance::status::error);
		}
	}

	void request_instance_status_(worker_instance& worker_instance) const
	{
		std::lock_guard<std::mutex> g{ worker_instances_mutex_ };
		std::string ec;
		auto response = http::client::request<http::method::get>(
			worker_instance.get_base_url() + "/private/infra/worker/status/statistics", ec, {});

		if (ec.empty())
		{
			json ret = json::parse(response.body());
			worker_instance.set_instance_metrics(ret["metrics"]);
		}
		else
		{
			worker_instance.set_status(worker_instance::status::error);
		}
	}

	// remove all
	void remove_all_instances(void)
	{
		for (auto in = worker_instances_.begin(); in != worker_instances_.end(); ++in)
		{
			remove_instance(in->second);
		}
	}

	void cleanup_all_instances(void)
	{
		for (auto in = worker_instances_.begin(); in != worker_instances_.end();)
		{
			in = worker_instances_.erase(in);
		}
	}

	void remove_deleted_instances(void)
	{
		for (auto in = worker_instances_.begin(); in != worker_instances_.end();)
		{
			if (in->second.get_status() == "deleted")
			{
				in = worker_instances_.erase(in);
			}
			else
				in++;
		}
	}

	class limits
	{
	public:
		size_t instances_pending() const { return instances_pending_; }
		size_t instances_required() const { return instances_required_; }
		size_t instances_actual() const { return instances_actual_; }
		size_t instances_min() const { return instances_min_; }
		size_t instances_max() const { return instances_max_; }

		void instances_pending(size_t value) { instances_pending_ = value; }
		void instances_required(size_t value) { instances_required_ = value; }
		void instances_actual(size_t value) { instances_actual_ = value; }
		void instances_min(size_t value) { instances_min_ = value; }
		void instances_max(size_t value) { instances_max_ = value; }

		enum class from_json_operation
		{
			add,
			set
		};

		void from_json(
			const json& j, const std::string& limit_name = "", from_json_operation method = from_json_operation::set)
		{
			if (method == from_json_operation::set)
			{
				if (limit_name.empty() || limit_name == "instances_required")
					instances_required_ = j.value("instances_required", instances_min_);

				if (limit_name.empty() || limit_name == "instances_min") instances_min_ = j.value("instances_min", 0);

				if (limit_name.empty() || limit_name == "instances_max")
					instances_max_ = j.value("instances_max", instances_min_);
			}
			else
			{
				if (limit_name.empty() || limit_name == "instances_required")
					instances_required_ += j.value("instances_required", 0);

				if (limit_name.empty() || limit_name == "instances_min") instances_min_ += j.value("instances_min", 0);

				if (limit_name.empty() || limit_name == "instances_max") instances_max_ += j.value("instances_max", 0);
			}

			if (instances_min_ > instances_max_) instances_min_ = instances_max_;
			if (instances_max_ < instances_min_) instances_max_ = instances_min_;
			if (instances_required_ > instances_max_) instances_required_ = instances_max_;
			if (instances_required_ < instances_min_) instances_required_ = instances_min_;
		}

		void to_json(json& j, const std::string& limit_name = "") const
		{
			if (limit_name.empty() || limit_name == "instances_required")
			{
				j["instances_required"] = instances_required_;
			}
			if (limit_name.empty() || limit_name == "instances_actual")
			{
				j["instances_actual"] = instances_actual_;
			}
			if (limit_name.empty() || limit_name == "instances_min")
			{
				j["instances_min"] = instances_min_;
			}
			if (limit_name.empty() || limit_name == "instances_max")
			{
				j["instances_max"] = instances_max_;
			}
		}

	private:
		size_t instances_pending_;
		size_t instances_required_;
		size_t instances_actual_;
		size_t instances_min_;
		size_t instances_max_;
	};

	limits& workgroups_limits() { return limits_; }

protected:
	std::string name_;
	std::string workspace_id_;
	std::string type_;
	std::string tenant_;

	limits limits_;

	container_type worker_instances_;
	mutable std::mutex worker_instances_mutex_;
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
	std::string startobject_;
	std::string cli_options_;
	std::string http_options_;

public:
	bshell_workgroups(const std::string& workspace_id, const json& worker_type_json)
		: workgroups(workspace_id, worker_type_json["type"])
	{
		from_json(worker_type_json);
	}

	virtual void set_tenant(const std::string& t) { tenant_ = t; };

	virtual void direct_instaces(lgr::logger& logger) override
	{
		std::string ec{};
		std::unique_lock<std::mutex> lock{ worker_instances_mutex_ };

		if (limits_.instances_actual() < limits_.instances_required())
		{
			auto nr_of_new_instances_required = limits_.instances_required() - worker_instances_.size();
			lock.unlock();

			for (size_t n = 0; n < nr_of_new_instances_required; n++)
			{
				std::uint32_t pid = 0;
				bool success = create_instance(workspace_id_, type_, name_, pid, ec);

				if (!success) // todo
				{
					logger.api(
						"create new instance in workgroup /{s}/{s}/{s} ({u}/{u}), failed to start proces: {s}\n",
						workspace_id_,
						type_,
						name_,
						limits_.instances_actual() + n + 1,
						limits_.instances_required(),
						ec);
				}
				else
				{
					logger.api(
						"create new instance in workgroup /{s}/{s}/{s} ({u}/{u}), processid: {d}\n",
						workspace_id_,
						type_,
						name_,
						limits_.instances_actual() + n + 1,
						limits_.instances_required(),
						static_cast<int>(pid));

					json pending_instance = json::object();
					pending_instance["process_id"] = pid;
					add_instance(pending_instance);
				}
			}
		}
		else if (limits_.instances_actual() > limits_.instances_required())
		{
			// todo: scale down.
			// for now let the idle watchdog handle it.
		}
		else
		{
			size_t instances_ok = 0;

			for (auto worker_instance = worker_instances_.begin(); worker_instance != worker_instances_.end();)
			{
				if (worker_instance->second.get_base_url().empty()) // TODO change to status?
				{
					++worker_instance;
					continue;
				}

				ec.clear();

				auto response = http::client::request<http::method::get>(
					worker_instance->second.get_base_url() + "/private/infra/worker/status/statistics", ec, {});

				if (ec.empty() && response.get("Content-type").find("json") != std::string::npos)
				{
					json ret = std::move(json::parse(response.body()));
					std::string link_to_status;
					worker_instance->second.set_instance_metrics(ret);
					logger.info(
						"instance {s}({s}) in /{s}/{s}/{s} is healthy\n",
						worker_instance->first,
						worker_instance->second.get_base_url(),
						workspace_id_,
						type_,
						name_);

					if (instances_ok < limits_.instances_min())
					{
						ec.clear();
						response.clear();
						response = http::client::request<http::method::post>(
							worker_instance->second.get_base_url() + "/private/infra/worker/status/watchdog", ec, {});

						if (ec.empty() && response.status() == http::status::no_content)
						{
							instances_ok++;
						}
					}

					if (worker_instance->second.get_status() != "running")
					{
						worker_instance->second.set_status(worker_instance::status::running);
					}
				}
				else if (ec.empty() && response.body().find("HTTP server has been stopped") != std::string::npos)
				{
					logger.debug(
						"instance {s}({s}) in /{s}/{s}/{s} is unavailable\n",
						worker_instance->first,
						worker_instance->second.get_base_url(),
						workspace_id_,
						type_,
						name_);
					worker_instance->second.set_status(worker_instance::status::running);
					// special case, wait until next loop, server is started or stopped
				}
				else
				{
					if (worker_instance->second.get_status() == "running")
					{
						worker_instance->second.set_status(worker_instance::status::error);
						logger.api(
							"instance {s}({s}) in workgroup /{s}/{s}/{s} failed healthcheck!\n",
							worker_instance->first,
							worker_instance->second.get_base_url(),
							workspace_id_,
							type_,
							name_);
					}
					else
					{
						logger.api(
							"instance {s}({s}) in workgroup /{s}/{s}/{s} will be deleted from workgroup\n",
							worker_instance->first,
							worker_instance->second.get_base_url(),
							workspace_id_,
							type_,
							name_);
						worker_instance = worker_instances_.erase(worker_instances_.find(worker_instance->first));
						limits_.instances_actual(worker_instances_.size());
						continue;
					}
				}

				++worker_instance;
			}
		}
	};

	void from_json(const json& j)
	{
		workgroups::from_json(j);
		j["details"].at("bse").get_to(bse_);
		j["details"].at("bse_bin").get_to(bse_bin_);
		j["details"].at("bse_user").get_to(bse_user_);
		j["details"].at("os_user").get_to(os_user_);
		j["details"].at("os_password").get_to(os_password_);
		j["details"].at("program").get_to(program_);
		j["details"].at("cli_options").get_to(cli_options_);
		j["details"].at("http_options").get_to(http_options_);
	}

	void to_json(json& j) const override
	{
		workgroups::to_json(j);
		j["details"].emplace("bse", bse_);
		j["details"].emplace("bse_bin", bse_bin_);
		j["details"].emplace("bse_user", bse_user_);
		j["details"].emplace("os_user", os_user_);
		j["details"].emplace("os_password", os_password_);
		j["details"].emplace("program", program_);
		j["details"].emplace("startobject", startobject_);
		j["details"].emplace("cli_options", cli_options_);
		j["details"].emplace("http_options", http_options_);
	}

public:
	bool create_instance(
		const std::string& workspace_id,
		const std::string& worker_type,
		const std::string& worker_name,
		std::uint32_t& pid,
		std::string& ec)
	{
		std::string tenant_id_ = "";
		std::stringstream parameters;

		parameters << "-httpserver_options cld_workgroup_instance_type:workgroup_instance,cld_manager_workspace:"
				   << workspace_id << ",cld_manager_workgroup:" << worker_name << "/" << worker_type;

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
			bse_bin_ + "/" + program_ + std::string{ " " } + parameters.str(),
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

	void from_json(const json& j)
	{
		workgroups::from_json(j);
		json d(j.at("details"));
		d.at("PythonRoot").get_to(rootdir);
	}

	void to_json(json& j) const
	{
		workgroups::to_json(j);
		j["details"].emplace("PythonRoot", rootdir);
	}

	virtual void direct_instaces(lgr::logger&) override{};

	virtual bool create_instance(
		const std::string&, // workspace_id,
		const std::string&, // worker_type,
		const std::string&, // worker_name,
		std::uint32_t&, // pid,
		std::string&) // ec)
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
	std::string workspace_id_{};
	std::string tenant_id_{};
	std::string description_{};

	bool deleted{ false };

	class api_url_configuration
	{
	public:
		api_url_configuration(
			const std::string& manager_base_url,
			const std::string manger_base_part,
			const std::string& manager_workspace_part)
			: manager_base_url_(manager_base_url)
			, manger_base_part_(manger_base_part)
			, manager_workspace_part_(manager_workspace_part)
		{
		}

	private:
		std::string manager_base_url_;
		std::string manger_base_part_;
		std::string manager_workspace_part_;
	};

	std::vector<std::string> errors;
	container_type workgroups_;

	api_url_configuration api_url_configuration_;

public:
	workspace(
		const std::string workspace_id,
		const std::string& manager_base_url,
		const std::string manger_base_part,
		const std::string& manager_workspace_part,
		const json& json_workspace)
		: workspace_id_(workspace_id)
		, api_url_configuration_(manager_base_url, manger_base_part, manager_workspace_part)
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
	std::unique_ptr<workgroups> create_workgroups_from_json(const std::string& type, const json& worker_type_json)
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
		j.at("description").get_to(description_);
		j.at("tenant_id").get_to(tenant_id_);

		if (j.find("workgroups") != j.end())
		{
			json json_workgroups = j.at("workgroups");

			for (auto workgroups = json_workgroups.cbegin(); workgroups != json_workgroups.cend(); workgroups++)
			{
				if (workgroups.value().size())
				{
					auto new_workgroups = create_workgroups_from_json(workgroups.value()["type"], *workgroups);

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
	using mutex_type = std::mutex;

private:
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

	void direct_workspaces(lgr::logger& logger)
	{
		auto t0 = std::chrono::steady_clock::now();
		for (auto& workspace : workspaces_)
		{

			std::unique_lock<mutex_type> l{ workspaces_mutex_ };
			for (auto& workgroup : *workspace.second)
				workgroup.second->direct_instaces(logger);
		}
		auto t1 = std::chrono::steady_clock::now();

		auto elapsed = t1 - t0;
		logger.api("directing {u} workspaces took {d}msec\n", workspaces_.size(), elapsed.count() / 1000000);
	}

public:
	bool add_workspace(const std::string id, const json::value_type& j)
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };

		auto i = workspaces_.find(id);

		if (i == workspaces_.end())
		{
			workspaces_.insert(container_type::value_type{
				id, new workspace{ id, "http://127.0.0.1:" + port, base_path, manager_workspace, j } });
			return true;
		}
		else
		{
			return false;
		}
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

	const_iterator get_workspace(const std::string& id) const { return workspaces_.find(id); }

	iterator get_workspace(const std::string& id) { return workspaces_.find(id); }

	void to_json(json& j) const
	{
		std::unique_lock<mutex_type> l{ workspaces_mutex_ };

		for (auto& workspace : workspaces_)
		{
			auto workspace_json = json{};
			workspace.second->to_json(workspace_json);
			j["workspaces"].emplace_back(workspace_json);
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
	void from_json(const json&)
	{

		// json startup;
		// json shutdown;

		// for (auto &el : a.items() ) {
		// 	application *app = new application();
		// 	app->from_json( el.value() );

		// }
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

class manager : public http::basic::threaded::server
{
public:
private:
	workspaces workspaces_;
	applications applications_;
	std::thread director_thread_;

	std::promise<int> shutdown_promise;
	std::future<int> shutdown_future;

public:
	manager(http::configuration& http_configuration, json& manager_configuration)
		: http::basic::threaded::server(http_configuration), shutdown_promise(), shutdown_future()
	{
		try
		{

			applications_.from_json(manager_configuration.at("applications"));
			workspaces_.from_json(manager_configuration.at("workspaces"));
		}
		catch (json::exception& e)
		{
			logger_.api("config error: {s}", e.what());
		}
		//#ifdef REST_ENABLED_LOGIC_SERVICE
		//				router_.on_post("/private/infra/logicservice/debug",
		//					[this](http::session_handler& session) {
		//
		//						EnableDebugLogging(session.request().body() == "debug");
		//
		//						session.response().status(http::status::ok);
		//					});
		//#endif
		router_.on_get("/private/infra/manager/healthcheck", [this](http::session_handler& session) {
			session.response().status(http::status::ok);
			session.response().type("text");
			session.response().body() = std::string("Ok") + session.request().body();
		});

		router_.on_put("/private/infra/manager/shutdown/{secs}", [this](http::session_handler& session) {
			auto& ID = session.params().get("secs");

			int shutdown = std::stoi(ID);
			send_json_response(session, http::status::ok, json{ { "time", shutdown } });
			// workspaces_.delete_all_workspaces();
			shutdown_promise.set_value(shutdown);
		});

		router_.on_post("/private/infra/manager/log_level", [this](http::session_handler& session) {
			logger_.set_level(session.request().body());
			auto new_level = logger_.current_level_to_string();
			http::basic::server::configuration_.set("log_level", new_level);
			session.response().body() = logger_.current_level_to_string();
			session.response().status(http::status::ok);
		});

		router_.on_get("/private/infra/manager/log_level", [this](http::session_handler& session) {
			session.response().body() = logger_.current_level_to_string();
			session.response().status(http::status::ok);
		});

#ifdef INFOR
		router_.on_get("/private/infra/manager/version", [this](http::session_handler& session) {
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
		});
#endif
		router_.on_get("/private/infra/manager/status", [this](http::session_handler& session) {
			const auto& format = session.request().get<std::string>("Accept", "application/json");

			if (format.find("application/json") != std::string::npos)
			{
				http::basic::threaded::server::manager().server_information(configuration_.to_json_string());
				http::basic::threaded::server::manager().router_information(router_.to_json_string());
				session.response().body() = http::basic::threaded::server::manager().to_json_string(
					http::basic::server::server_manager::json_status_options::full);
				session.response().type("json");
			}
			else
			{
				http::basic::threaded::server::manager().server_information(configuration_.to_string());
				http::basic::threaded::server::manager().router_information(router_.to_string());
				session.response().body() = http::basic::threaded::server::manager().to_string();
				session.response().type("text");
			}

			session.response().status(http::status::ok);
		});

		router_.on_get("/private/infra/manager/status/{section}", [this](http::session_handler& session) {
			http::basic::threaded::server::manager().server_information(configuration_.to_json_string());
			http::basic::threaded::server::manager().router_information(router_.to_json_string());

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
				section_option = http::basic::server::server_manager::json_status_options::accesslog;
			}
			else
			{
				session.response().status(http::status::not_found);
				return;
			}

			session.response().body() = http::basic::threaded::server::manager().to_json_string(section_option);
			session.response().type("json");
			session.response().status(http::status::ok);
		});

		router_.on_get("/private/infra/workspaces", [this](http::session_handler& session) {
			json workspaces_json{};
			workspaces_.to_json(workspaces_json);
			send_json_response(session, http::status::ok, workspaces_json);
		});

		// router_.on_post("/private/infra/workspaces",
		//	[this](http::session_handler& session)
		//	{
		//		try
		//		{
		//			json j = json::parse(session.request().body());
		//			std::string id;
		//			j.at("workspace_id").get_to(id);

		//			if (workspaces_.add_workspace(id, j) == true)
		//			{
		//				session.response().status(http::status::created);
		//			}
		//			else
		//			{
		//				set_error_response(
		//					session, http::status::conflict, "null", "workspace " + id + " already present");
		//			}
		//		}
		//		catch (json::exception& e)
		//		{
		//			set_json_response_catch(session, e);
		//		}
		//		catch (...)
		//		{
		//			session.response().status(http::status::bad_request);
		//		}
		//	});

		router_.on_get("/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
			auto& id = session.params().get("workspace_id");
			auto w = workspaces_.get_workspace(id);

			if (w != workspaces_.end())
			{
				//				w->second.remove_deleted_instances();
				json j;
				j["workspace"] = (*(w->second));
				send_json_response(session, http::status::ok, j);
			}
			else
			{
				send_illegal_workspace_response(session, id);
			}
		});

		router_.on_post("/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
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

		router_.on_delete("/private/infra/workspaces/{workspace_id}", [this](http::session_handler& session) {
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

		router_.on_get("/private/infra/workspaces/{workspace_id}/workgroups", [this](http::session_handler& session) {
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

		router_.on_get(
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

		router_.on_post(
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

		router_.on_delete(
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

		router_.on_get(
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

		router_.on_post(
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

		router_.on_delete(
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

		// get info for specific instance id for a worker with {name} and {type} in workspace {workspace_id}
		router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/instances/{instance_id}",
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
						json instance_json;
						auto& instance_id = session.params().get("instance_id");

						auto instance = workgroups->second->find_instance(instance_id);

						if (instance != workgroups->second->end()) instance->second.to_json(instance_json);

						json result;
						result["instance"] = instance_json;
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
		router_.on_get(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/instances",
			[this](http::session_handler& session) {
				auto& workspace_id = session.params().get("workspace_id");
				auto workspace = workspaces_.get_workspace(workspace_id);

				if (workspace != workspaces_.end())
				{
					auto& name = session.params().get("name");
					auto& type = session.params().get("type");

					auto workgroups = workspace->second->find_workgroups(name, type);

					json result;
					result["instances"] = json::array();

					if (workgroups != workspace->second->end())
					{

						for (const auto& instance : *workgroups->second)
						{
							json instance_json;
							instance.second.to_json(instance_json);

							result["instances"].emplace_back(instance_json);
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

		// put specific instance {instance_id} of worker {name} and {type} in workspace {workspace_id}
		router_.on_put(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/instances/{instance_id}",
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
						json instance_json = json::parse(session.request().body());

						auto workgroups = workspace->second->find_workgroups(name, type);

						if (workgroups != workspace->second->end())
						{
							workgroups->second->add_instance(instance_json);
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

		// remove specific instance {instance_id} of worker {type} in workspace {workspace_id}
		router_.on_delete(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/instances",
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

						i->second->cleanup_all_instances();
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

		// remove specific instance {instance_id} of worker {type} in workspace {workspace_id}
		router_.on_delete(
			"/private/infra/workspaces/{workspace_id}/workgroups/{name}/{type}/instances/{instance_id}",
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
						auto& instance_id = session.params().get("instance_id");
						json ii;

						json instance_json = json::parse(session.request().body());

						if (instance_json.contains("limits") == true)
						{
							size_t instances_required_update = instance_json["limits"]["instances_required"];

							i->second->workgroups_limits().instances_required(
								i->second->workgroups_limits().instances_required() + instances_required_update);
						}

						if (i->second->delete_instance(instance_id) == false)
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

		router_.on_get(
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

		router_.on_get(
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

		router_.on_put(
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

		// get info for specific instance id for a worker with {name} and {type} in workspace {workspace_id}
		router_.on_put(
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

						workgroups->second->workgroups_limits().from_json(limits["limits"], limit_name);
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

		router_.on_patch(
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

						workgroups->second->workgroups_limits().from_json(
							limits["limits"], limit_name, workgroups::limits::from_json_operation::add);
						workgroups->second->workgroups_limits().to_json(limits["limits"], limit_name);
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

		router_.on_internal_error([this](http::session_handler& session, std::exception& e) {
			logger().accesslog(
				"api-error with requested url: \"{s}\", error: \"{s}\", and request body:\n \"{s}\"",
				session.request().url_requested(),
				e.what(),
				http::to_string(session.request()));
			set_error_response(session, http::status::bad_request, "", e.what());
		});
	}

	virtual ~manager() {}

	const http::configuration& configuration() { return configuration_; }

	http::basic::server::state start() override
	{
		auto ret = http::basic::threaded::server::start();

		director_thread_ = std::move(std::thread{ [this]() { director_handler(); } });

		return ret;
	}

private:
	void director_handler()
	{
		while (!is_active() && !is_activating())
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		while (is_active() || is_activating())
		{
			if (is_active())
			{
				workspaces_.direct_workspaces(logger_);
			}

			std::this_thread::sleep_for(std::chrono::seconds(10));
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
		logger().error(
			"set_error_response: {s}, json{s}", session.request().url_requested(), session.response().body());
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
		deactivate();
	}

	virtual void send_illegal_workspace_response(
		http::session_handler& session,
		const std::string& w_id,
		http::status::status_t status = http::status::not_found)
	{
		set_error_response(session, status, "null", "workspace_id " + w_id + " not found");
	}
};

static std::unique_ptr<manager> cpm_server_;
} // namespace platform
} // namespace cloud

class curl_global
{
public:
	curl_global() { curl_global_init(CURL_GLOBAL_ALL); }

	~curl_global() { curl_global_cleanup(); }
};

#if 0
static void Daemonize()
{
	int devnull = open("/dev/null", O_RDWR);
	if (devnull > 0) {

	}

}
#endif

inline int start_rest_server(int argc, const char** argv)
{
	prog_args::arguments_t cmd_args(
		argc,
		argv,
		{ { "workdir", { prog_args::arg_t::arg_val, " <workdir>: Working directory for Platform Manager ", "." } },
		  { "configfile", { prog_args::arg_t::arg_val, " <config>: filename for the config file", "pm.json" } },
		  { "curldebug", { prog_args::arg_t::flag, " enables cURL tracing ", "false" } },
		  { "http_port", { prog_args::arg_t::arg_val, "port number to use", "4000" } },
		  { "port", { prog_args::arg_t::arg_val, "port number to use", "5000" } },
		  { "fg", { prog_args::arg_t::flag, "run in foreground" } },
		  { "tracelevel", { prog_args::arg_t::arg_val, " <tracelevel>: set tracelevel for Platform Manager ", "0" } },
		  { "tracefile", { prog_args::arg_t::arg_val, " <trace filename>: Output for trace file ", "cpm_trace.log" } },
		  { "errorfile",
			{ prog_args::arg_t::arg_val, " <trace filename>: Output for error file ", "cpm_error.log" } } });

	if (cmd_args.process_args() == false)
	{
		std::cout << "error in arguments\n";
		exit(1);
	}

	json manager_configuration_json;

	if (cmd_args.get_val("configfile").empty())
	{
	}
	else
	{
		std::ifstream configuration_stream{ cmd_args.get_val("configfile") };
		try
		{
			manager_configuration_json = json::parse(configuration_stream);
		}
		catch (json::exception& e)
		{
			std::cout << "error in configuration: " << e.what() << std::endl;
		}
	}

	std::string server_version = std::string{ "Platform Manager/" } + get_version_ex(PORT_SET, NULL);

	http::configuration http_configuration{ { { "server", server_version },
											  { "http_listen_port_begin", cmd_args.get_val("http_port") },
											  { "private_base", "/private/infra/manager" },
											  { "log_file", "cerr" },
											  { "log_level", "api" },
											  { "https_enabled", "false" },
											  { "http_use_portsharding", "false" } } };

	cloud::platform::cpm_server_ = std::unique_ptr<cloud::platform::manager>(
		new cloud::platform::manager(http_configuration, manager_configuration_json));

	cloud::platform::cpm_server_->start();

	return 0;
}

inline int stop_rest_server()
{
	cloud::platform::cpm_server_->stop();
	cloud::platform::cpm_server_.release();

	return 0;
}

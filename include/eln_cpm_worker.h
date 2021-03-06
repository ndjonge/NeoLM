#pragma once

#if !defined(IBM_RS6000) && !defined(HPUX) && !defined(SUN_SPARC) // HTTP_ENABLED

#ifdef IPV6STRICT
#undef IPV6STRICT
#endif

#if defined _WIN32
#include <process.h>
#define getpid() _getpid()
#endif

#include "http_basic.h"

namespace cloud
{

namespace platform
{

enum result
{
	failed,
	sucess
};

class worker_base
{
public:
	enum class remove_worker_options
	{
		just_remove,
		remove_and_decrease_required_limit
	};

	enum class state
	{
		initial,
		added,
		removed,
	};

	worker_base(const http::server& server) : server_(server), state_(state::initial) {}

	virtual ~worker_base(){};

	virtual result add() noexcept = 0;

	virtual result remove(remove_worker_options option) noexcept = 0;

	virtual result fork() noexcept = 0;
	virtual bool is_forked() const { return is_forked_; };
	virtual void set_forked(bool f) { is_forked_ = f; };

protected:
	const http::server& server_;
	state state_;
	bool is_forked_{ false };
};

namespace implementations
{

template <typename T> class worker : public worker_base
{

protected:
	std::string manager_endpoint_url_;
	std::string cpm_worker_id_;
	std::string cpm_worker_label_;

	using json = T;

public:
	worker(const http::server& server) : worker_base(server)
	{
		cpm_worker_id_ = server_.config().template get<std::string>("cpm_worker_id", "no_id");
		cpm_worker_label_ = server_.config().template get<std::string>("cpm_worker_label", "no_label");

		manager_endpoint_url_ = server_.config().template get<std::string>(
									"cpm_endpoint", "http://127.0.0.1:8080/internal/platform/manager/workspaces")
								+ "/" + server_.config().template get<std::string>("cpm_workspace", "workspace-000")
								+ "/workgroups/"
								+ server_.config().template get<std::string>("cpm_workgroup", "anonymous/bshells");
	}

	virtual result add() noexcept override
	{
		if (state_ == state::added) return result::failed;

		std::string ec;

		//{
		//	"process_id": 1235,
		//	"base_url": "http://localhost:5000"
		//}

		json put_new_instance_json = json::object();

		auto pid = getpid();

		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["worker_label"] = cpm_worker_label_;
		put_new_instance_json["worker_id"] = cpm_worker_id_;

		if (server_.config().template get<bool>("https_enabled", false) == true)
			put_new_instance_json["base_url"] = server_.config().template get<std::string>("https_this_server_local_url", "");
		else
			put_new_instance_json["base_url"] = server_.config().template get<std::string>("http_this_server_local_url", "");

		put_new_instance_json["version"] = server_.config().template get<std::string>("server", "");

		auto response = http::client::request<http::method::post>(
			manager_endpoint_url_ + "/workers/", ec, {}, put_new_instance_json.dump());

		if (ec.empty())
		{
			if (response.status() == http::status::ok || response.status() == http::status::created
				|| response.status() == http::status::no_content)
			{
				state_ = state::added;
				return result::sucess;
			}
			else
			{
				return result::failed;
			}
		}
		else
		{
			return result::failed;
		}
	}

	virtual result remove(remove_worker_options option) noexcept override
	{
		if (state_ == state::removed) return result::failed;

		std::string ec;

		json put_new_instance_json = json::object();
		auto pid = getpid();

		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["worker_label"] = cpm_worker_label_;
		put_new_instance_json["base_url"] = server_.config().get("http_this_server_local_url");

		if (option == remove_worker_options::remove_and_decrease_required_limit)
			put_new_instance_json["limits"]["workers_required"] = -1;

		auto response = http::client::request<http::method::delete_>(
			manager_endpoint_url_ + "/workers/" + cpm_worker_id_, ec, {}, put_new_instance_json.dump());

		if (ec.empty())
		{
			if (response.status() == http::status::ok || response.status() == http::status::no_content
				|| response.status() == http::status::accepted)
			{
				state_ = state::removed;
				return result::sucess;
			}
			else
			{
				return result::failed;
			}
		}
		else
		{
			return result::failed;
		}
	}

	virtual result fork() noexcept override
	{
		if (state_ != state::added) return result::failed;

		std::string ec;

		//{
		//	"process_id": 1235,
		//	"base_url": "http://localhost:5000"
		//}

		json patch_workers_required_json = json::object();
		patch_workers_required_json["limits"]["workers_required"] = 1;

		auto response = http::client::request<http::method::patch>(
			manager_endpoint_url_ + "/limits/workers_required", ec, {}, patch_workers_required_json.dump());

		if (ec.empty())
		{
			if (response.status() == http::status::ok || response.status() == http::status::accepted)
			{
				set_forked(true);
				return result::sucess;
			}
			else
			{
				return result::failed;
			}
		}
		else
		{
			return result::failed;
		}
	}
};

} // namespace implementations

template <typename J> class enable_server_as_worker
{
public:
	using json = J;
	enable_server_as_worker(http::server* server)
		: workgroup_controller_(workgroup_controller_from_configuration(*server))
	{
		// http://localhost:4000/internal/platform/manager/workspaces/workspace_000/workgroups/untitled/bshells/worker
	}

	~enable_server_as_worker(){};

protected:
	std::unique_ptr<worker_base> workgroup_controller_;

	std::unique_ptr<worker_base> workgroup_controller_from_configuration(http::server& server)
	{
		if (server.config().get("cpm_workgroup_membership_type") == "worker")
		{
			return std::move(std::unique_ptr<cloud::platform::implementations::worker<J>>(
				new cloud::platform::implementations::worker<J>(server)));
		}

		return {};
	}
};

} // namespace platform

} // namespace cloud
#endif

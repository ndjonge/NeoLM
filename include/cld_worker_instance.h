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

class worker_instance_base
{
public:
	enum class remove_instance_options
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

	worker_instance_base(const http::basic::server& server) : server_(server), state_(state::initial) {}

	virtual ~worker_instance_base(){};

	virtual result add() noexcept = 0;

	virtual result remove(remove_instance_options option) noexcept = 0;

	virtual result fork() const noexcept = 0;

protected:
	const http::basic::server& server_;
	state state_;
};

namespace implementations
{

template <typename T> class workgroup_instance : public worker_instance_base
{

protected:
	std::string manager_endpoint_url_;
	using json = T;

public:
	workgroup_instance(const http::basic::server& server) : worker_instance_base(server)
	{
		manager_endpoint_url_ = server_.config().get<std::string>(
									"cld_manager_endpoint", "http://localhost:4000/private/infra/workspaces")
								+ "/" + server_.config().get<std::string>("cld_manager_workspace", "workspace-000")
								+ "/workgroups/"
								+ server_.config().get<std::string>("cld_manager_workgroup", "anonymous/bshells");
	}

	virtual result add() noexcept override
	{
		if (state_ == state::added) return result::failed;

		std::string ec;

		//{
		//	"process_id": 1235,
		//	"base_url": "http://localhost:5000"
		//}

		std::string this_endpoint_url = "http://127.0.0.1:" + server_.config().get<std::string>("http_listen_port");

		json put_new_instance_json = json::object();

		auto pid = getpid();

		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["base_url"] = this_endpoint_url;
		put_new_instance_json["version"] = server_.config().get<std::string>("server", "");

		auto response = http::client::request<http::method::put>(
			manager_endpoint_url_ + "/instances/" + std::to_string(pid), ec, {}, put_new_instance_json.dump());

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

	virtual result remove(remove_instance_options option) noexcept override
	{
		if (state_ == state::removed) return result::failed;

		std::string ec;

		std::string this_endpoint_url = "http://127.0.0.1:" + server_.config().get<std::string>("http_listen_port");

		json put_new_instance_json = json::object();
		auto pid = getpid();

		put_new_instance_json["process_id"] = pid;
		put_new_instance_json["base_url"] = this_endpoint_url;

		if (option == remove_instance_options::remove_and_decrease_required_limit)
			put_new_instance_json["limits"]["instances_required"] = -1;

		auto response = http::client::request<http::method::delete_>(
			manager_endpoint_url_ + "/instances/" + std::to_string(pid), ec, {}, put_new_instance_json.dump());

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

	virtual result fork() const noexcept override
	{
		if (state_ != state::added) return result::failed;

		std::string ec;

		//{
		//	"process_id": 1235,
		//	"base_url": "http://localhost:5000"
		//}

		std::string this_endpoint_url = "http://localhost:" + server_.config().get<std::string>("http_listen_port");

		json patch_instances_required_json = json::object();
		patch_instances_required_json["limits"]["instances_required"] = 1;

		auto response = http::client::request<http::method::patch>(
			manager_endpoint_url_ + "/limits/instances_required", ec, {}, patch_instances_required_json.dump());

		if (ec.empty())
		{
			if (response.status() == http::status::ok || response.status() == http::status::accepted)
			{
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

template <typename J> class enable_server_as_workgroup_instance
{
public:
	using json = J;
	enable_server_as_workgroup_instance(http::basic::server* server)
		: workgroup_instance_controller_(workgroup_instance_controller_from_configuration(*server))
	{
		// http://localhost:4000/private/infra/workspaces/workspace_000/workgroups/untitled/bshells/instances
	}

	~enable_server_as_workgroup_instance(){};

protected:
	std::unique_ptr<worker_instance_base> workgroup_instance_controller_;

	std::unique_ptr<worker_instance_base> workgroup_instance_controller_from_configuration(http::basic::server& server)
	{
		if (server.config().get("cld_workgroup_instance_type") == "workgroup_instance")
		{
			return std::move(std::unique_ptr<cloud::platform::implementations::workgroup_instance<J>>(
				new cloud::platform::implementations::workgroup_instance<J>(server)));
		}

		return {};
	}
};

} // namespace platform

} // namespace cloud
#endif

#pragma once

#include "http_basic.h"
#include "http_network.h"


// http_upstream_node.h
//{ "upstream-node-nginx-endpoint", "http://nlbalndjonge01.mshome.net:4000/dynamic" },
//{ "upstream-node-nginx-endpoint-downstream", "backend" },
//{ "upstream-node-nginx-endpoint-myip", "172.17.245.161" },
//{ "upstream-node-nginx-endpoint-api", "ngx_dynamic_upstream" },
//{ "upstream-node-scaling", "self-scale" },
//{ "upstream-node-scaling-fork-cmd", "start /b " + std::accumulate(argv, argv + argc, std::string("")) },
//{ "upstream-node-connection-limit-high", "2" },
//{ "upstream-node-connection-limit-lwo", "0"}
// http_upstream_node.h

namespace http
{

namespace upstream
{
enum result
{
	failed,
	sucess
};

enum servertype_specialisations 
{
	for_nginx,
	for_haproxy
};

template<servertype_specialisations>
class enable_server_as_upstream
{
public:
	enable_server_as_upstream(http::configuration& configuration, http::basic::server& server) : configuration_(configuration), server_(server) {};

private:
	http::configuration& configuration_;
	http::basic::server& server_;
};

//CRTP
template<class T>
class upstream_controller
{	
public:
	upstream_controller(http::configuration& configuration, http::basic::server& server) : configuration_(configuration), server_(server) 
	{}

	bool fork()
	{
		auto future_ = std::async(std::launch::async, [this]()
		{
			auto result = std::system(configuration_.get("upstream-node-scaling-fork-cmd").c_str());
		});

		return true;
	}

	const result add(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->add_impl(myurl);
	}

	const result remove(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->remove_impl(myurl);
	}

	const result enable(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->enable_impl(myurl);
	}

	const result disable(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->enable_impl(myurl);
	}

	const std::string list() const noexcept
	{
		return static_cast<T*>(this)->enable_impl();
	}

protected:
	http::configuration& configuration_;
	http::basic::server& server_;
};

namespace implementations 
{

class nginx : public upstream_controller<nginx>
{
public:
	nginx(http::configuration& configuration, http::basic::server& server) : upstream_controller(configuration, server) {
		endpoint_base_url_ = configuration_.get("upstream-node-nginx-endpoint") + 
			"?upstream=" + 
			configuration_.get("upstream-node-nginx-endpoint-downstream"); 
	};

	const result add(const std::string& server) const noexcept
	{
        http::configuration c{};
        http::session_handler session{c};

		auto result = session.get(endpoint_base_url_ + "&add=&server=" + server, {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const result remove(const std::string& server) const noexcept
	{
        http::configuration c{};
		http::session_handler session{c};

		auto result = session.get(endpoint_base_url_ + "&remove=&server=" + server, {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const result enable(const std::string& server) const noexcept
    {	
        http::configuration c{};
		http::session_handler session{c};

		auto result = session.get(endpoint_base_url_ + "&server=" + server+ "&up", {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const result disable(const std::string& server) const noexcept
	{
        http::configuration c{};
		http::session_handler session{c};

		auto result = session.get(endpoint_base_url_ + "&server=" + server + "&down", {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const std::string list() const noexcept
	{
        http::configuration c{};
		http::session_handler session{c};

		auto result = session.get(endpoint_base_url_, {});

		if (result.status() == http::status::ok)
			return result.body();
		else
			return "";
	}
	
private:
	std::string endpoint_base_url_;
};

class haproxy : public upstream_controller<haproxy>
{
public:
	haproxy(http::configuration& configuration, http::basic::server& server) : upstream_controller(configuration, server) {};

	const result add(std::string& ) const noexcept
	{
		return http::upstream::sucess;
	}

	const result remove(std::string& ) const noexcept
	{
		return http::upstream::sucess;
	}

	const result enable(std::string& ) const noexcept
	{
		return http::upstream::sucess;
	}

	const result disable(std::string& ) const noexcept
	{
		return http::upstream::sucess;
	}

	const std::string list(std::string& ) const noexcept
	{
		return "";
	}

private:
//	network::tcp::endpoint& nginx_endpoint_;
};

}

template<>
class enable_server_as_upstream<for_nginx>
{
public:
	enable_server_as_upstream(http::configuration& configuration, http::basic::server& server) : upstream_controller_(configuration, server) {};
protected:
	implementations::nginx& upstream_controller() {return upstream_controller_;};
private:
	implementations::nginx upstream_controller_;
};

template<>
class enable_server_as_upstream<for_haproxy>
{
public:
	enable_server_as_upstream(http::configuration& configuration, http::basic::server& server) : upstream_controller_(configuration, server) {};
private:
	implementations::haproxy upstream_controller_;
};
}

}

/*
Copyright (c) <2018> <ndejonge@gmail.com>

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include "http_basic.h"
#include "http_network.h"


//		{ "upstream-node-nginx-endpoint", "http://localhost:4000/dynamic" },
//		{ "upstream-node-nginx-endpoint-downstream", "backend" },
//		{ "upstream-node-scaling", "self-scale" },
//		{ "upstream-node-scaling-limit-high", "2" },
//		{ "upstream-node-scaling-limit-lwo", "0"},

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
template<class I>
class upstream_controller
{	
public:
	upstream_controller(http::configuration& configuration, http::basic::server& server) : configuration_(configuration), server_(server) 
	{}

	const result add(const std::string& myurl) const noexcept
	{
		return static_cast<T*>add_impl(myrl);
	}

	const result remove(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->remove_impl(myrl);
	}

	const result enable(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->enable_impl(myrl);
	}

	const result disable(const std::string& myurl) const noexcept
	{
		return static_cast<T*>(this)->enable_impl(myrl);
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
		http::session_handler session{http::configuration{}};

		auto result = session.get(endpoint_base_url_ + "&add=&server=" + server, {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const result remove(const std::string& server) const noexcept
	{
		http::session_handler session{http::configuration{}};

		auto result = session.get(endpoint_base_url_ + "&remove=&server=" + server, {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const result enable(const std::string& server) const noexcept
	{
		http::session_handler session{http::configuration{}};

		auto result = session.get(endpoint_base_url_ + "&server=" + server+ "&up", {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const result disable(const std::string& server) const noexcept
	{
		http::session_handler session{http::configuration{}};

		auto result = session.get(endpoint_base_url_ + "&server=" + server + "&down", {});

		if (result.status() == http::status::ok)
			return http::upstream::sucess;
		else
			return http::upstream::failed;
	}

	const std::string list() const noexcept
	{
		http::session_handler session{http::configuration{}};

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

	const result add(std::string& myurl) const noexcept
	{
		return http::upstream::sucess;
	}

	const result remove(std::string& myurl) const noexcept
	{
		return http::upstream::sucess;
	}

	const result enable(std::string& myurl) const noexcept
	{
		return http::upstream::sucess;
	}

	const result disable(std::string& myurl) const noexcept
	{
		return http::upstream::sucess;
	}

	const std::string list(std::string& myurl) const noexcept
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
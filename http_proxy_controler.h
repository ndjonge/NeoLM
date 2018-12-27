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

namespace http
{

namespace reverse_proxy_controller
{

class nginx
{
public:
	nginx(const std::string& nginx_endpoint = "http://localhost:4000/dynamic") : nginx_endpoint_(network::resolver::from_string(nginx_endpoint))
	{
		http::session_handler::request 
	}

	nginx(network::tcp::endpoint& nginx_endpoint)
	{
	}


	bool add_cluster_node()
	{
	}

	bool enable_cluster_node()
	{
	}

	bool disable_cluster_node()
	{
	}

	bool remove_cluster_node()
	{
	}

private:
	network::tcp::endpoint& nginx_endpoint_;
}

}

}
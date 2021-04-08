#include <array>
#include <chrono>
#include <ctime>
#include <future>
#include <iostream>
#include <mutex>
#include <numeric>
#include <unordered_map>
#include <vector>

#include "http_basic.h"
#include "cld_director.h"

#include "nlohmann/json.hpp"
using json = nlohmann::json;

//   "workgroups": [
//               {
//"limits" : {
//	"workers_label_required" : "v8",
//	"workers_max" : 8,
//	"workers_min" : 8,
//	"workers_requests_max" : 32,
//	"workers_required" : 8,
//	"workers_runtime_max" : 2,
//	"workers_start_at_once_max" : 4
//},
//		   "name" : "service_a_e",
//					"parameters"
//	: {
//		"bse" : "D:/Infor/lnmsql/bse",
//		"bse_bin" : "\\\\view\\enha_BDNT79248.NLBAWPSET7.ndjonge\\obj.dbg.WinX64\\bin",
//		"bse_user" : "ndjonge",
//		"cli_options" :
//			"-httpserver -delay 0 -install -set HTTP_BOOT_PROCESS=otttsthttpboot D:/Infor/lnmsql/bse/http/t.o",
//		"http_options" : "http_watchdog_timeout:62,log_level:api",
//		"os_password" : "$2S$80EEA66DF8FBAEB005D7210E2372952C",
//		"os_user" : "ndjonge@infor.com",
//		"program" : "ntbshell.exe"
//	},
//	  "paths" : [ "/v1", "/service_e", "/external" ],
//				"type" : "bshells",

namespace tests
{
bool add_workspace(std::string workspace_id, std::string tenant_id){ json workspace_def{
	{ "workspace",
						  { { "id", workspace_id },
		{ "routes",
		  { { "paths", { "/api", "/internal" } },
			{ "methods", { "get", "head", "post" } },
			{ "headers", { { "X-Infor-TenantId", { tenant_id } } } } } } } } };
		//,
							//{ "workgroups",
							//  { { { "name", "service_a000" },
							//	  { "type", "bshells" },
							//	  { "routes",
							//	{ { "paths", { "/tests", "/platform" } },
							//		  { "methods", { "get", "head", "post" } },
							//		  { "headers", { { "X-Infor-Company", { id } } } } } },
							//	  { "limits",
							//		{ { "workers_min", 4 },
							//		  { "workers_max", 8 },
							//		  { "workers_required", 4 },
							//		  { "workers_start_at_once_max", 8 } } },
							//	  { "parameters", { "program", "bshell" } } } } } } } };


//	std::cout << workspace_def.dump(4, ' ') << "\n";
	std::string error;

	auto response = http::client::request<http::method::post>(
		"http://localhost:4000/internal/platform/manager/workspaces", error, {}, workspace_def["workspace"].dump());

	if (error.empty() == false) return false;

	if (response.status() == http::status::conflict)
	{
	}

	return true;
}


bool add_workgroup(std::string workspace_id, std::string workgroup_name) 
{


	json workgroup_def{ { "name", workgroup_name },
						{ "type", "bshells"}, { "limits",
												{ { "workers_min", 1 },
												  { "workers_max", 16 },
												  { "workers_required", 1 },
												  { "workers_start_at_once_max", 8 } } } };


	//std::cout << workgroup_def.dump(4, ' ') << "\n";

	std::string error;

	auto response = http::client::request<http::method::post>(
		"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id + "/workgroups",
		error,
		{},
		workgroup_def.dump());

	if (error.empty() == false) return false;

	if (response.status() == http::status::conflict)
	{
	}

	return true;
}

bool increase_workgroup_limits(std::string workspace_id, std::string workgroup_name)
{
	json limits_def{ { "limits", { { "workers_required", 8 } } } };

	// std::cout << workgroup_def.dump(4, ' ') << "\n";

	std::string error;

	auto response = http::client::request<http::method::put>(
		"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id + "/workgroups/" + workgroup_name
		 + "/limits/workers_required",
		error,
		{},
		limits_def.dump());

	if (error.empty() == false) return false;

	if (response.status() == http::status::conflict)
	{
	}

	return true;
}


bool remove_workgroup(std::string workspace_id, std::string workgroup_name)
{
	std::string error;

	auto response = http::client::request<http::method::delete_>(
		"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id + "/workgroups/"
			+ workgroup_name,
		error,
		{});

	if (error.empty() == false) return false;

	if (response.status() == http::status::conflict)
	{
	}

	return true;
}

bool remove_workspace(std::string workspace_id)
{
	std::string error;

	auto response = http::client::request<http::method::delete_>(
		"http://localhost:4000/internal/platform/manager/workspaces/" + workspace_id,
		error,
		{});

	if (error.empty() == false) return false;

	if (response.status() == http::status::conflict)
	{
	}

	return true;
} 

bool generate_requests(const std::string& request_url, int count) 
{ 
	std::thread{ [count, request_url]() {
		for (int i = 0; i != count; i++)
		{
			std::string error;
			auto response = http::client::request<http::method::get>(
				"http://localhost:4000" + request_url, error, { { "X-Infor-TenantId", "tenant100_tst" } }, {});

			if (response.status() == http::status::not_found)
			{
			}
			else
			{
			}
		}
	} }.detach();


	return true;
}

} // namespace tests

int main(int argc, const char* argv[])
{
	network::init();
	network::ssl::init();

	start_cld_manager_server(argc, argv);

	while (1)
	{
		const auto workspace_count = 1;
		const auto workgroup_count = 1;

		tests::generate_requests("/api/tests/1k", -1);

		for (int i = 0; i < workspace_count; i++)
			tests::add_workspace("workspace_" + std::to_string(100 + i), "tenant" + std::to_string(100 + i) + "_tst");

		for (int i = 0; i < workgroup_count; i++)
			tests::add_workgroup("workspace_" + std::to_string(100 + i), "workgroup_" + std::to_string(i));

		std::this_thread::sleep_for(std::chrono::seconds(10));

		for (int i = 0; i < workgroup_count; i++)
			tests::increase_workgroup_limits("workspace_" + std::to_string(100 + i), "workgroup_" + std::to_string(i));

		std::this_thread::sleep_for(std::chrono::seconds(10));

		for (int i = 0; i < workgroup_count; i++)
			tests::remove_workgroup("workspace_" + std::to_string(100 + i), "workgroup_" + std::to_string(i));

		std::this_thread::sleep_for(std::chrono::seconds(10));

		for (int i = 0; i < workspace_count; i++)
			tests::remove_workspace("workspace_" + std::to_string(100 + i));	

		std::this_thread::sleep_for(std::chrono::seconds(30));
	}

	run_cld_manager_server();

	stop_cld_manager_server();
};
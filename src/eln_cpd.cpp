#include "eln_cpd.h"

int main(int argc, const char* argv[])
{
	start_eln_cpd_server(argc, argv);	
	run_eln_cpd_server();
	stop_eln_cpd_server();
};
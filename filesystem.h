#include <cstdint>
#include <string>

#include <sys/stat.h>


namespace filesystem
{
	std::uintmax_t 	file_size(const std::string& path)
	{
		struct stat t;

		int ret = stat(path.c_str(), &t);

		if (ret != 0)
			return t.st_size;
		else
			return -1;
	}
}
#pragma once

#include <filesystem>
#include "check_list.hpp"

namespace checks
{
	namespace data
	{
		extern std::vector<check_list> javaw_bad;
		extern std::vector<check_list> explorer_bad;
		extern std::vector<check_list> mod_bad;
		extern std::vector<check_list> versions_bad;
		extern std::vector<check_list> process_bad;

		extern std::string code_str;
	}

	namespace impl
	{
		// Processes
		extern bool scan_process(unsigned long pid, std::vector<check_list>* proc_vec, uint64_t* creation_time);
		extern void check_processes();

		// Vape Detect
		//extern void check_vape_lite();

		// Jar Checker
		extern void check_mods();
		extern void check_versions();
		extern void process_jar(const std::experimental::filesystem::path& jar_file, std::vector<check_list>& detection_list, uint64_t& detection_count);

		// Process Checker
		extern void check_bad_processes();

		// Recycle Bin Checker
		extern void check_recycle();

		// Xray Checker
		extern void check_xray();

		// Info report
		extern void report();
	}

	extern void run();
	extern void run_deep();
}

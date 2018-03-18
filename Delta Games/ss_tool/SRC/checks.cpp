#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <functional>

#define _SILENCE_PARALLEL_ALGORITHMS_EXPERIMENTAL_WARNING
#define WIN32_LEAN_AND_MEAN

#include "Windows.h"
#include <TlHelp32.h>
#include <sddl.h>
#include "console.hpp"
#include "checks.hpp"
#include "extensions.hpp"

#define LODEPNG_NO_COMPILE_ZLIB
#include "lodepng.hpp"
#include "miniz.h"
#include <regex>
#include "crypto.hpp"
#include "check_list.hpp"

#undef max, min

extern "C" long __stdcall NtReadVirtualMemory(HANDLE, void*, void*, unsigned long, unsigned long*);

namespace fs = std::experimental::filesystem;

class MemoryProtect
{
public:
	MemoryProtect(void* Address, size_t Size, DWORD ProtectionFlags)
	{
		m_Address = Address;
		m_Size = Size;
		m_Flags = ProtectionFlags;
		Protect(m_Address, m_Size, m_Flags);
	}

	~MemoryProtect()
	{
		Protect(m_Address, m_Size, m_OldProtection);
	}

private:
	bool Protect(void* Address, size_t Size, DWORD ProtectionFlags)
	{
		return VirtualProtect(Address, Size, ProtectionFlags, &m_OldProtection);
	}

	void* m_Address;
	size_t m_Size;
	DWORD m_Flags;
	DWORD m_OldProtection;
};

namespace checks::data
{
	std::vector<std::wstring> proc_list;

	std::vector<check_list> javaw_bad;
	std::vector<check_list> explorer_bad;
	std::vector<check_list> mod_bad;
	std::vector<check_list> versions_bad;
	std::vector<check_list> process_bad;

	std::string code_str;

	namespace detections
	{
		uint64_t string = 0;
		uint64_t mod = 0;
		uint64_t version = 0;
		uint64_t proc = 0;
		uint64_t xray = 0;
	}

	namespace time
	{
		uint64_t string = 0;
		uint64_t mod = 0;
		uint64_t version = 0;
		uint64_t proc = 0;
		uint64_t recycle = 0;
		std::string recycle_date;
		uint64_t xray = 0;

		uint64_t javaw_create_time = 0;
		uint64_t explorer_create_time = 0;
	}
}

void checks::run()
{
	impl::check_processes();

	impl::check_bad_processes();

	impl::check_recycle();

	// Report info
	impl::report();
}

void checks::run_deep()
{
	impl::check_processes();

	//impl::check_mods();

	impl::check_versions();

	impl::check_bad_processes();

	impl::check_recycle();

	//impl::check_xray();

	// Report info
	impl::report();
}

bool checks::impl::scan_process(unsigned long pid, std::vector<check_list>* proc_vec, uint64_t* creation_time)
{
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (proc)
	{
		set_colour(console::success);
		std::cout << enc_str(" SUCCESS");
		set_colour(console::seperator);
		std::cout << enc_str(".");

		if (creation_time != nullptr)
		{
			FILETIME creation_file_time, et, kt, ut;
			auto filetime_to_timet = [](const FILETIME& ft) -> time_t
			{
				ULARGE_INTEGER ull;
				ull.LowPart = ft.dwLowDateTime;
				ull.HighPart = ft.dwHighDateTime;

				return ull.QuadPart / 10000000ULL - 11644473600ULL;
			};

			GetProcessTimes(proc, &creation_file_time, &et, &kt, &ut);

			*creation_time = filetime_to_timet(creation_file_time);

			auto now = std::chrono::system_clock::now();
			auto creation = std::chrono::system_clock::from_time_t(*creation_time);

			auto seconds_since_creation = std::chrono::duration_cast<std::chrono::minutes>(now - creation).count();

			std::cout << enc_str(" (Process created ") << seconds_since_creation << enc_str(" minutes ago.)") << std::endl;
		}
		else
			std::cout << std::endl;

		MEMORY_BASIC_INFORMATION info;

		std::cout << enc_str(" Checks failed: ");

		ext::ThreadPool pool(10);
		std::vector<std::future<void>> results;
		uint64_t checks_failed = 0;

		for (auto& x : *proc_vec)
			for (auto& i : x.detection_list())
				ext::xor_enc::inplace_xor(i, data::code_str);

		unsigned char* p = nullptr;

		for (p = nullptr; VirtualQueryEx(proc, p, &info, sizeof info) == sizeof info; p += info.RegionSize)
		{
			const size_t qe = VirtualQueryEx(proc, p, &info, sizeof info);
			if (qe == 0)
				std::cout << enc_str("Something fucked up.") << std::endl;

			if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE)
			{
				std::vector<char> chunk;

				uint64_t bytes_read;
				chunk.resize(info.RegionSize);

				MemoryProtect protect(p, info.RegionSize, PAGE_EXECUTE_READWRITE);

				if (NtReadVirtualMemory(proc, p, &chunk[0], info.RegionSize, reinterpret_cast<unsigned long*>(&bytes_read)) < 0xC0000000)
				{
					results.emplace_back(pool.enqueue([&](std::vector<char> chunk_data)
					{
						ext::concurrent_searcher(*proc_vec, chunk_data);
					}, chunk));
				}
			}
		}

		for (auto&& result : results)
			result.get();

		for (auto& x : *proc_vec)
		{
			for (auto& i : x.detection_list())
				ext::xor_enc::inplace_xor(i, data::code_str);

			checks_failed += x.get_detections();
		}

		checks_failed == 0 ? set_colour(console::success) : set_colour(console::fail);
		std::cout << checks_failed << std::endl;
		set_colour(console::seperator);

		data::detections::string += checks_failed;

		return true;
	}

	set_colour(console::fail);
	std::cout << enc_str(" FAIL");
	set_colour(console::seperator);
	std::cout << enc_str(".") << std::endl;

	return false;
}

void checks::impl::check_processes()
{
	const auto start = std::chrono::high_resolution_clock::now();

	unsigned long pid = 1337;
	PROCESSENTRY32W pe_info;

	std::array<std::tuple<std::wstring, bool, std::vector<check_list>*, uint64_t*>, 2> proccess_arr{
		make_tuple(L"explorer.exe", false, &data::explorer_bad, &data::time::explorer_create_time),
		make_tuple(L"javaw.exe", false, &data::javaw_bad, &data::time::javaw_create_time)
	};

	const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, pid);
	if (snapshot)
	{
		pe_info.dwSize = sizeof pe_info;
		auto next_proc = Process32First(snapshot, &pe_info);
		while (next_proc)
		{
			for (auto& x : proccess_arr)
			{
				std::wstring proc_name(pe_info.szExeFile);
				data::proc_list.push_back(proc_name);

				proc_name.resize(std::get<0>(x).size());

				if (std::get<0>(x) == proc_name)
				{
					std::wcout << std::endl << L"Opening process " << std::get<0>(x) << L"...";
					std::get<1>(x) = true;
					if (!scan_process(pe_info.th32ProcessID, std::get<2>(x), std::get<3>(x)))
					{
						set_colour(console::logo);
						std::cout << enc_str(" Please restart the program as administrator.") << std::endl;
						set_colour(console::seperator);
					}
				}
			}
			next_proc = Process32Next(snapshot, &pe_info);
		}
		CloseHandle(snapshot);

		for (const auto& x : proccess_arr)
		{
			if (!std::get<1>(x))
			{
				std::wcout << std::endl << L"Opening process " << std::get<0>(x) << "... ";
				set_colour(console::fail);
				std::cout << enc_str("FAIL");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl;
				set_colour(console::logo);
				std::cout << enc_str(" The process couldn't be found.") << std::endl;
				set_colour(console::seperator);
			}
		}
	}

	data::time::string = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
}

void checks::impl::check_mods()
{
	const auto start = std::chrono::high_resolution_clock::now();

	fs::path appdata = getenv(enc_char("APPDATA"));
	appdata /= enc_str("/.minecraft/mods/");

	std::vector<std::pair<std::string, uint64_t>> write_times;

	auto filetime_to_timet = [](const FILETIME& ft) -> time_t
	{
		ULARGE_INTEGER ull;
		ull.LowPart = ft.dwLowDateTime;
		ull.HighPart = ft.dwHighDateTime;

		return ull.QuadPart / 10000000ULL - 11644473600ULL;
	};

	for (auto& p : fs::recursive_directory_iterator(appdata))
	{
		const fs::path& cur_file(p);

		if (is_regular_file(cur_file) && cur_file.extension() == enc_str(".jar"))
		{
			FILETIME last_write;
			GetFileTime(CreateFile(cur_file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), nullptr, &last_write, nullptr);
			write_times.emplace_back(cur_file.filename().generic_string(), filetime_to_timet(last_write));
		}
	}

	for (const auto& x : write_times)
	{
		if (x.second > data::time::javaw_create_time)
		{
			std::cout << std::endl << x.second << enc_str(" has ");
			set_colour(console::fail);
			std::cout << enc_str("SELF DESTRUCTED");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl;
		}
	}

	data::time::mod = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
}

void checks::impl::check_versions()
{
	const auto start = std::chrono::high_resolution_clock::now();

	std::vector<fs::path> path_vec;

	fs::path appdata = getenv(enc_char("APPDATA"));
	appdata /= enc_str("/.minecraft/versions/");

	for (auto& p : fs::recursive_directory_iterator(appdata))
	{
		const fs::path& cur_file(p);

		if (is_regular_file(cur_file) && cur_file.extension() == enc_str(".jar"))
			path_vec.emplace_back(cur_file);
	}

	for (auto& x : path_vec)
		process_jar(x, data::versions_bad, data::detections::version);

	data::time::version = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
}

void checks::impl::process_jar(const fs::path& jar_file, std::vector<check_list>& detection_list, uint64_t& detection_count)
{
	std::cout << std::endl << enc_str("Loading ") << jar_file.filename() << enc_str("... ");

	mz_zip_archive zip_archive;
	memset(&zip_archive, 0, sizeof(zip_archive));

	if (!mz_zip_reader_init_file(&zip_archive, jar_file.generic_string().data(), 0))
	{
		set_colour(console::fail);
		std::cout << enc_str("FAILED");
		set_colour(console::seperator);
		std::cout << enc_str(".") << std::endl;

		return;
	}

	set_colour(console::success);
	std::cout << enc_str("SUCCESS");
	set_colour(console::seperator);
	std::cout << enc_str(".") << std::endl;

	ext::ThreadPool pool(10);
	std::vector<std::future<void>> results;
	uint64_t checks_failed = 0;

	for (auto& x : detection_list)
		for (auto& i : x.detection_list())
			ext::xor_enc::inplace_xor(i, data::code_str);

	
	for (size_t i = 0; i < mz_zip_reader_get_num_files(&zip_archive); i++)
	{
		mz_zip_archive_file_stat file_stat;
		if (!mz_zip_reader_file_stat(&zip_archive, i, &file_stat))
		{
			set_colour(console::fail);
			std::cout << enc_str(" Reading file within jar failed.") << std::endl;
			set_colour(console::seperator);
	
			continue;
		}
	
		if (file_stat.m_uncomp_size < 1)
			continue;
	
		std::vector<char> file_buf;
		file_buf.resize(file_stat.m_uncomp_size);
	
		if (!mz_zip_reader_extract_to_mem(&zip_archive, i, &file_buf[0], file_stat.m_uncomp_size, 0))
		{
			set_colour(console::fail);
			std::cout << enc_str(" Reading file within jar failed.") << std::endl;
			set_colour(console::seperator);
	
			continue;
		}
	
		results.emplace_back(pool.enqueue([&](std::vector<char> chunk_data)
		{
			ext::concurrent_searcher(detection_list, chunk_data);
		}, file_buf));
	}

	mz_zip_reader_end(&zip_archive);

	for (auto&& result : results)
		result.get();

	for (auto& x : detection_list)
	{
		for (auto& i : x.detection_list())
			ext::xor_enc::inplace_xor(i, data::code_str);

		checks_failed += x.get_detections();
	}

	std::cout << enc_str(" Checks failed: ");
	checks_failed == 0 ? set_colour(console::success) : set_colour(console::fail);
	std::cout << checks_failed << std::endl;
	set_colour(console::seperator);

	detection_count += checks_failed;
}

void checks::impl::check_bad_processes()
{
	const auto start = std::chrono::high_resolution_clock::now();

	std::vector<std::string> found_proc;

	std::cout << std::endl << enc_str("Searching for recording software... ");

	for (auto& x : data::process_bad)
	{
		for (auto& i : x.detection_list())
		{
			ext::xor_enc::inplace_xor(i, data::code_str);

			std::wstring proc_view(i.begin(), i.end());

			const auto it = find(data::proc_list.begin(), data::proc_list.end(), proc_view);
			if (it != data::proc_list.end())
			{
				data::detections::proc++;
				found_proc.push_back(std::string(i.begin(), i.end()));
			}

			ext::xor_enc::inplace_xor(i, data::code_str);
		}
	}

	data::detections::proc == 0 ? set_colour(console::success) : set_colour(console::fail);
	std::cout << data::detections::proc;
	set_colour(console::seperator);
	std::cout << enc_str(".") << std::endl;

	if (data::detections::proc > 0)
	{
		std::cout << enc_str(" ");

		set_colour(console::fail);

		for (const auto& x : found_proc)
			std::cout << x << enc_str(" ");

		set_colour(console::seperator);
	}

	std::cout << std::endl << std::endl;

	data::time::proc = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
}

void checks::impl::check_recycle()
{
	const auto start = std::chrono::high_resolution_clock::now();

	data::time::recycle_date.erase();

	const auto filetime_to_time_t = [](FILETIME const& ft) -> time_t
		{
			ULARGE_INTEGER ull;
			ull.LowPart = ft.dwLowDateTime;
			ull.HighPart = ft.dwHighDateTime;
			return ull.QuadPart / 10000000ULL - 11644473600ULL;
		};

	HANDLE token;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);

	PTOKEN_USER token_user = static_cast<PTOKEN_USER>(malloc(sizeof _TOKEN_USER));
	unsigned long size = 0;
	if (!GetTokenInformation(token, TokenUser, nullptr, size, &size))
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			token_user = static_cast<PTOKEN_USER>(malloc(size));

	GetTokenInformation(token, TokenUser, token_user, size, &size);

	LPSTR lpz_str = nullptr;

	ConvertSidToStringSidA(token_user->User.Sid, &lpz_str);

	std::string path(enc_str("C:\\$RECYCLE.BIN\\"));
	path.append(lpz_str);

	WIN32_FIND_DATAA data;
	void* h = FindFirstFileA(path.c_str(), &data);
	FindClose(h);
	free(token_user);

	auto time = filetime_to_time_t(data.ftLastWriteTime);

	data::time::recycle_date.append(std::ctime(&time));

	data::time::recycle = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
}

void checks::impl::check_xray()
{
	namespace fs = std::experimental::filesystem;

	const auto start = std::chrono::high_resolution_clock::now();

	std::vector<std::thread> threadpool;

	fs::path appdata = getenv(enc_char("APPDATA"));
	appdata /= enc_str("/.minecraft/resourcepacks/");

	const auto bad_file_name = [](const std::wstring_view& filename)
		{
			std::array<std::wstring, 2> bad_names{enc_wstr("cobblestone.png"), enc_wstr("stone.png")};

			for (const auto& x : bad_names)
				if (filename == x)
					return true;

			return false;
		};

	const auto scan_zip = [&](const std::string_view& path)
		{
			const auto clean_filename = [](const std::string& file_path) -> std::string
				{
					return file_path.substr(file_path.find_last_of('/') + 1);
				};

			mz_zip_archive zip_archive;
			memset(&zip_archive, 0, sizeof(zip_archive));

			if (!mz_zip_reader_init_file(&zip_archive, path.data(), 0))
				return;

			std::vector<uint8_t> file_buf;

			// Get and print information about each file in the archive.
			for (size_t i = 0; i < mz_zip_reader_get_num_files(&zip_archive); i++)
			{
				mz_zip_archive_file_stat file_stat;
				if (!mz_zip_reader_file_stat(&zip_archive, i, &file_stat))
					continue;

				if (file_stat.m_uncomp_size < 1 || file_stat.m_is_directory)
					continue;

				auto tmp = clean_filename(file_stat.m_filename);
				if (!bad_file_name(std::wstring(tmp.begin(), tmp.end())))
					continue;

				file_buf.resize(file_stat.m_uncomp_size);

				if (!mz_zip_reader_extract_to_mem(&zip_archive, i, &file_buf[0], file_stat.m_uncomp_size, 0))
					continue;

				uint32_t w, h;

				lodepng::decode(file_buf, w, h, file_buf);

				uint8_t counter = 0;
				for (auto alpha = 3; alpha < file_buf.size(); alpha += 4)
				{
					if (file_buf[alpha] <= 170)
						counter++;
				}

				auto alpha_num = file_buf.size() / 4;
				if (counter > (alpha_num / 4)) // More than 25% transparent
					data::detections::xray++;
			}

			mz_zip_reader_end(&zip_archive);
		};

	for (auto& p : fs::recursive_directory_iterator(appdata))
	{
		const fs::path& cur_file(p);

		if (is_regular_file(cur_file) && cur_file.extension() == enc_str(".zip"))
			threadpool.emplace_back(scan_zip, cur_file.generic_string());

		if (is_regular_file(cur_file) && cur_file.extension() == enc_str(".png") && bad_file_name(cur_file.filename().c_str()))
		{
			std::vector<uint8_t> decoded_png_buf;
			uint32_t w, h;

			lodepng::decode(decoded_png_buf, w, h, cur_file.generic_string());

			uint8_t counter = 0;
			for (auto alpha = 3; alpha < decoded_png_buf.size(); alpha += 4)
			{
				if (decoded_png_buf[alpha] <= 170)
					counter++;
			}

			auto alpha_num = decoded_png_buf.size() / 4;
			if (counter >(alpha_num / 4)) // More than 25% transparent
				data::detections::xray++;
		}
	}

	for (auto& x : threadpool)
		x.join();

	data::time::xray = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
}

void checks::impl::report()
{
	std::cout << console::spacer << std::endl << std::endl;
	std::cout << enc_str("Strings scanned in ") << data::time::string << enc_str("ms with ");
	data::detections::string == 0 ? set_colour(console::success) : set_colour(console::fail);
	std::cout << data::detections::string;
	set_colour(console::seperator);
	std::cout << enc_str(" detections.") << std::endl;

	std::cout << enc_str("Mods scanned in ") << data::time::mod << enc_str("ms with ");
	data::detections::mod == 0 ? set_colour(console::success) : set_colour(console::fail);
	std::cout << data::detections::mod;
	set_colour(console::seperator);
	std::cout << enc_str(" detections.") << std::endl;

	std::cout << enc_str("Versions scanned in ") << data::time::version << enc_str("ms with ");
	data::detections::version == 0 ? set_colour(console::success) : set_colour(console::fail);
	std::cout << data::detections::version;
	set_colour(console::seperator);
	std::cout << enc_str(" detections.") << std::endl;

	std::cout << enc_str("Processes scanned in ") << data::time::proc << enc_str("ms with ");
	data::detections::proc == 0 ? set_colour(console::success) : set_colour(console::fail);
	std::cout << data::detections::proc;
	set_colour(console::seperator);
	std::cout << enc_str(" detections.") << std::endl;

	std::cout << enc_str("Recycle Bin checked in ") << data::time::recycle << enc_str("ms and was last cleared on ");
	set_colour(console::success);
	std::cout << data::time::recycle_date;
	set_colour(console::seperator);

	//std::cout << "Resourcepacks scanned in " << data::time::xray << "ms with ";
	//data::detections::xray == 0 ? set_colour(console::success) : set_colour(console::fail);
	//std::cout << data::detections::xray;
	//set_colour(console::seperator);
	//std::cout << " detections." << std::endl;

	std::cout << std::endl << enc_str("Total check time in ") << data::time::proc + data::time::mod + data::time::version + data::time::recycle + data::time::string + data::time::xray << enc_str("ms.") << std::endl;

	data::detections::string = 0;
	data::detections::mod = 0;
	data::detections::proc = 0;
	data::detections::xray = 0;

	std::cout << std::endl << console::spacer << std::endl << std::endl;
}

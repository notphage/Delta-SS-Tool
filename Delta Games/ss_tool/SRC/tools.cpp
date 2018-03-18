#include "tools.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinInet.h>

#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <array>
#include <vector>
#include "console.hpp"
#include "crypto.hpp"

namespace tools
{
	enum tool_list
	{
		process_hacker = 1,
		last_activity,
		executed_programs_list,
		usb_deview,
		reg_scanner,
		win_prefetch_view,
		search_everything,
		emeditor,
		rtn
	};

	std::array<std::pair<uint8_t, std::string>, 9> arr_programs
	{
		std::pair<uint8_t, std::string>{process_hacker, enc_str("Process Hacker 2")},
		std::pair<uint8_t, std::string>{last_activity, enc_str("Last Activity")},
		std::pair<uint8_t, std::string>{executed_programs_list, enc_str("Executed Programs List")},
		std::pair<uint8_t, std::string>{usb_deview, enc_str("USB Deview")},
		std::pair<uint8_t, std::string>{reg_scanner, enc_str("Reg Scanner")},
		std::pair<uint8_t, std::string>{win_prefetch_view, enc_str("Win Prefetch View")},
		std::pair<uint8_t, std::string>{search_everything, enc_str("Search Everything")},
		std::pair<uint8_t, std::string>{emeditor, enc_str("EM Editor")},
		std::pair<uint8_t, std::string>{rtn, enc_str("Return")}
	};

	namespace impl
	{
		std::optional<std::vector<uint8_t>> get_file(const std::string_view& url)
		{
			static HINTERNET internet = InternetOpenA(enc_char("Mozilla/5.0 (Windows NT 6.1; rv:10.0) Gecko/20100101 Firefox/10.0"), INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);

			char head[15];
			head[0] = '\0';

			HINTERNET connect = InternetOpenUrlA(internet, url.data(), head, 15, INTERNET_FLAG_DONT_CACHE, 0);

			if (!connect)
			{
				std::cout << enc_str("Error: InternetOpenUrl") << std::endl;
				return {};
			}

			std::vector<uint8_t> file_vec;

			bool read;
			unsigned long bytes_read;
			do
			{
				const size_t old_buf_len = file_vec.size();
				file_vec.resize(old_buf_len + 0x8000);

				read = InternetReadFile(connect, static_cast<void*>(&file_vec[old_buf_len]), 0x8000, &bytes_read);

				file_vec.resize(old_buf_len + bytes_read);
			}
			while (bytes_read != 0 || !read);

			return file_vec;
		}

		void write_file(const std::string_view& file_name, const std::vector<uint8_t>& file_buf)
		{
			FILE* file = nullptr;
			if (!fopen_s(&file, file_name.data(), enc_char("wb")) || file == nullptr)
			{
				fwrite(&file_buf[0], 1, file_buf.size(), file);
				fclose(file);

				return;
			}

			fclose(file);
			std::cout << enc_str("Error writing file.") << std::endl;
		}

		void process_hacker()
		{
			std::cout << enc_str("Downloading Process Hacker 2... ");

			auto opt = get_file(enc_str(R"(https://github.com/processhacker2/processhacker/releases/download/v2.39/processhacker-2.39-bin.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("processhacker-2.39-bin.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void last_activity()
		{
			std::cout << enc_str("Downloading Last Activity... ");

			auto opt = get_file(enc_str(R"(https://www.nirsoft.net/utils/lastactivityview.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("lastactivityview.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void executed_programs_list()
		{
			std::cout << enc_str("Downloading Executed Programs List... ");

			auto opt = get_file(enc_str(R"(https://www.nirsoft.net/utils/executedprogramslist.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("executedprogramslist.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void usb_deview()
		{
			std::cout << enc_str("Downloading USBDeview... ");

			auto opt = get_file(enc_str(R"(https://www.nirsoft.net/utils/usbdeview.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("usbdeview.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void reg_scanner()
		{
			std::cout << enc_str("Downloading Reg Scanner... ");

			auto opt = get_file(enc_str(R"(https://www.nirsoft.net/utils/regscanner.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("regscanner.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void win_prefetch_view()
		{
			std::cout << enc_str("Downloading Win Prefetch View... ");

			auto opt = get_file(enc_str(R"(https://www.nirsoft.net/utils/winprefetchview.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("winprefetchview.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void search_everything()
		{
			std::cout << enc_str("Downloading Search Everything... ");

			auto opt = get_file(enc_str(R"(https://www.voidtools.com/Everything-1.4.1.877.x86.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("Everything-1.4.1.877.x86.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}

		void emeditor()
		{
			std::cout << enc_str("Downloading EmEditor... ");

			auto opt = get_file(enc_str(R"(http://files.emeditor.com/emed32_17.3.2_portable.zip)"));
			if (opt.has_value())
			{
				write_file(enc_str("emed32_17.3.2_portable.zip"), opt.value());

				set_colour(console::success);
				std::cout << enc_str("SUCCESS");
				set_colour(console::seperator);
				std::cout << enc_str(".") << std::endl << std::endl;

				return;
			}

			set_colour(console::fail);
			std::cout << enc_str("FAIL");
			set_colour(console::seperator);
			std::cout << enc_str(".") << std::endl << std::endl;
		}
	}

	void run()
	{
		std::cout << std::endl << console::spacer << std::endl << std::endl;

		for (const auto& x : arr_programs)
		{
			std::cout << static_cast<int>(x.first) << enc_str(") ");
			set_colour(console::logo);
			std::cout << x.second << std::endl;
			set_colour(console::seperator);
		}

		std::cout << std::endl << console::spacer << std::endl << std::endl;

		const auto accept_command = []()
			{
				std::string command;
				uint32_t command_flag = 0;
				do
				{
					std::cout << enc_str("> ");
					set_colour(console::logo);
					std::cin >> command;
					set_colour(console::seperator);

					command_flag = (command.c_str()[0] - '0');
					if (command.length() == 1 && command_flag <= rtn && command_flag > 0)
						return command_flag;

					set_colour(console::fail);
					std::cout << enc_str("Sorry, this is not a recognized command.") << std::endl << std::endl;
					set_colour(console::seperator);
				}
				while (!command_flag);

				return command_flag;
			};

		auto exit_command = false;
		do
		{
			switch (accept_command())
			{
				case process_hacker:
					impl::process_hacker();
					break;

				case last_activity:
					impl::last_activity();
					break;

				case executed_programs_list:
					impl::executed_programs_list();
					break;

				case usb_deview:
					impl::usb_deview();
					break;

				case reg_scanner:
					impl::reg_scanner();
					break;

				case win_prefetch_view:
					impl::win_prefetch_view();
					break;

				case search_everything:
					impl::search_everything();
					break;

				case emeditor:
					impl::emeditor();
					break;

				case rtn:
					exit_command = true;
					break;

				default:
					break;
			}
		}
		while (!exit_command);

		system(enc_char("cls"));
		set_colour(console::logo);
		std::cout << std::endl << console::logo_txt << std::endl << std::endl;
		set_colour(console::seperator);
		std::cout << console::spacer << std::endl << std::endl;

		set_colour(console::logo);
		std::cout << std::endl << enc_str("                               Commands") << std::endl << std::endl;
		set_colour(console::seperator);

		std::cout << enc_str("run: Scans the system for all presences of cheating software.") << std::endl;
		std::cout << enc_str("deep: Additionally checks versions and mods folders for cheats.") << std::endl;
		std::cout << enc_str("tools: Lists common tools with the downloads for use during a screenshare.") << std::endl;
		std::cout << enc_str("exit: Exits the program.") << std::endl << std::endl;
		std::cout << console::spacer << std::endl << std::endl;
	}
}

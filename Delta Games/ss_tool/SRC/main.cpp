#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <functional>
#include <atomic>
#include <algorithm>

#include "console.hpp"
#include "checks.hpp"
#include "tools.hpp"
#include <regex>
#include "crypto.hpp"

#pragma comment(lib,"ntdll.lib")

/*
					    _   ______  ______________________
					   / | / / __ \/_  __/  _/ ____/ ____/
					  /  |/ / / / / / /  / // /   / __/   
					 / /|  / /_/ / / / _/ // /___/ /___   
					/_/ |_/\____/ /_/ /___/\____/_____/   
					                                      
		These functions below are **NOT** included in the open source 
		version of delta and are left up to the reader as an excercise.
		Showing the way we encrypt our output from the server would
		create a large security flaw. The maintainers of the repository
		will **NOT** help you with successfully implimenting your own
		system, so please do not create issues or tag developers for help.
		They should be fairly obvious as to what you'll need to construct
		to get this tool fully usable. Official releases on the github
		will have the full functionality implimented to prevent skid from
		copy pasting this project and trying to sell it.
 */

extern std::vector<char> connect(const std::string_view& code_str); // returns an encrypted blod of strings
extern void handle_strings(const std::vector<char>& recv); // decrypts the strings and then transforms them into a useable format

int main()
{
	std::vector<char> recv;
	SetWindowTextA(GetForegroundWindow(), enc_char("Delta | ScreenShare Tool"));

	std::string pin;

	console::fill_colours();

	do
	{
		set_colour(console::logo);
		std::cout << std::endl << console::logo_txt << std::endl << std::endl;
		set_colour(console::seperator);
		std::cout << console::spacer << std::endl << std::endl;

		std::cout << enc_str("PIN: ");
		set_colour(console::logo);
		std::cin >> pin;
		set_colour(console::seperator);

		std::cout << std::endl << console::spacer << std::endl;

		if (pin.length() != 8 && all_of(pin.begin(), pin.end(), isdigit))
		{
			std::cout << std::endl << enc_str("Incorrect pin!") << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(2));
			system(enc_char("cls"));
		}
		else
			recv = connect(pin);

		if (recv.size() <= 0)
		{
			std::cout << std::endl << enc_str("Incorrect pin!") << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(2));
			system(enc_char("cls"));
		}
	}
	while (recv.size() <= 0);

	checks::data::code_str = pin;

	handle_strings(recv);
	recv.clear();
	recv.shrink_to_fit();

	set_colour(console::logo);
	std::cout << std::endl << enc_str("                               Commands") << std::endl << std::endl;
	set_colour(console::seperator);

	std::cout << enc_str("run: Scans the system for all presences of cheating software.") << std::endl;
	std::cout << enc_str("deep: Additionally checks versions and mods folders for cheats.") << std::endl;
	std::cout << enc_str("tools: Lists common tools with the downloads for use during a screenshare.") << std::endl;
	std::cout << enc_str("exit: Exits the program.") << std::endl << std::endl;
	std::cout << console::spacer << std::endl << std::endl;

	const auto accept_command = []()
		{
			std::string command;
			uint8_t command_flag = 0;
			do
			{
				std::cout << enc_str("> ");
				set_colour(console::logo);
				std::cin >> command;
				set_colour(console::seperator);

				if (command == enc_str("run"))
					command_flag = 1;
				else if (command == enc_str("deep"))
					command_flag = 2;
				else if (command == enc_str("tools"))
					command_flag = 3;
				else if (command == enc_str("exit"))
					command_flag = 4;
				else
				{
					set_colour(console::fail);
					std::cout << enc_str("Sorry, this is not a recognized command.") << std::endl << std::endl;
					set_colour(console::seperator);
				}
			}
			while (!command_flag);

			return command_flag;
		};

	auto exit_command = false;
	do
	{
		switch (accept_command())
		{
			case 1:
				checks::run();
				break;

			case 2:
				checks::run_deep();
				break;

			case 3:
				tools::run();
				break;

			case 4:
				exit_command = true;

			default:
				break;
		}
	}
	while (!exit_command);

	return 0;
}

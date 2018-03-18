#pragma once
#define WIN32_LEAN_AND_MEAN
#include "windows.h"

namespace console
{
	static const char logo_txt[] = (R"(                  _____    ______   __       ______  ______   
                 /\  __-. /\  ___\ /\ \     /\__  _\/\  __ \  
                 \ \ \/\ \\ \  __\ \ \ \____\/_/\ \/\ \  __ \ 
                  \ \____- \ \_____\\ \_____\  \ \_\ \ \_\ \_\
                   \/____/  \/_____/ \/_____/   \/_/  \/_/\/_/
                                             
)");

	static unsigned char spacer[] = {
		0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
		0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
		0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
		0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
		0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
		0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B,
		0x2B, 0x00};

	enum colors
	{
		background,
		seperator,
		logo,
		success,
		fail
	};

	__forceinline void set_colour(int col)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<uint16_t>(col + background * 16));
	}

	__forceinline void fill_colours()
	{
		CONSOLE_SCREEN_BUFFER_INFOEX ci;
		ci.cbSize = sizeof CONSOLE_SCREEN_BUFFER_INFOEX;

		GetConsoleScreenBufferInfoEx(GetStdHandle(STD_OUTPUT_HANDLE), &ci);

		ci.ColorTable[background] = 0x00202020;
		ci.ColorTable[seperator] = 0x00e9e9ee;
		ci.ColorTable[logo] = 0x000095e0;
		ci.ColorTable[success] = 0x0043b54b;
		ci.ColorTable[fail] = 0x00130fdb;

		//ci.srWindow.Right += 1;
		//ci.srWindow.Bottom += 1;

		SetConsoleScreenBufferInfoEx(GetStdHandle(STD_OUTPUT_HANDLE), &ci);
	}
}

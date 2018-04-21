#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <functional>
#include <atomic>

#include "console.hpp"
#include "checks.hpp"
#include <WinInet.h>
#include <regex>
#include "extensions.hpp"
#include <winternl.h>
#include "crypto.hpp"
#include "check_list.hpp"

std::vector<char> connect(const std::string_view& code_str)
{
	DWORD bytes_read = 0;
	std::vector<char> recv_buf;

	HANDLE web_handle = InternetOpenA(enc_char("Mozilla/5.0 (Windows NT 6.1; rv:10.0) Gecko/20100101 Firefox/10.0"), INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);

	if (web_handle != nullptr)
	{
		HANDLE connect_handle = InternetConnectA(web_handle, enc_char("delta.games"), 8880, nullptr, nullptr, INTERNET_SERVICE_HTTP, INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_CACHE_WRITE, 1);

		if (connect_handle != nullptr)
		{
			std::string req(enc_str("/ss?code="));
			req.append(code_str);

			HANDLE request_handle = HttpOpenRequestA(connect_handle, enc_char("GET"), req.c_str(), nullptr, nullptr, nullptr, INTERNET_FLAG_RELOAD, 1);

			if (request_handle != nullptr)
			{
				BOOL send = HttpSendRequestA(request_handle, nullptr, 0, nullptr, 0);

				if (send)
				{
					bool read;
					do
					{
						const size_t old_buf_len = recv_buf.size();
						recv_buf.resize(old_buf_len + 4096);

						read = InternetReadFile(request_handle, static_cast<void*>(&recv_buf[old_buf_len]), 4096, &bytes_read);

						recv_buf.resize(old_buf_len + bytes_read);
					}
					while (bytes_read != 0 || !read);
				}
				else
					std::cout << GetLastError() << std::endl;
			}
			else
				std::cout << GetLastError() << std::endl;
		}
		else
			std::cout << GetLastError() << std::endl;
	}
	else
		std::cout << GetLastError() << std::endl;

	return recv_buf;
}

std::vector<check_list>* determine_vector(const std::regex_iterator<std::string::iterator>& it)
{
	std::vector<check_list>* ref_vector = nullptr;

	uint64_t vector_id = std::stoull(it->str().substr(1, it->str().length() - 2));
	switch (vector_id)
	{
		case 0xd5c9a13b9c890c2a: // explorer
		{
			ref_vector = &checks::data::explorer_bad;
			break;
		}

		case 0x0808591917670ee3: // mod
		{
			ref_vector = &checks::data::mod_bad;
			break;
		}

		case 0x71c101c65726118c: // versions
		{
			ref_vector = &checks::data::versions_bad;
			break;
		}

		case 0x01dabe85903dc59a: // process
		{
			ref_vector = &checks::data::process_bad;
			break;
		}

		case 0xa744f6d32f0bd376: // javaw
		{
			ref_vector = &checks::data::javaw_bad;
			break;
		}

		default:
			break;
	}

	return ref_vector;
}

void handle_strings(const std::vector<char>& recv)
{
	std::string recv_str(recv.begin(), recv.end());
	recv_str = ext::base64::base64_decode(recv_str);

	ext::xor_enc::inplace_xor(recv_str, checks::data::code_str);

	std::regex r(enc_str("\\[[0-9]*\\]"));

	std::regex_iterator<std::string::iterator> it(recv_str.begin(), recv_str.end(), r);
	std::regex_iterator<std::string::iterator> end;

	bool looped = false;
	while (it != end)
	{
		looped = true;
		auto next = std::next(it);

		std::vector<check_list>* ref_vector = determine_vector(it);

		std::string enc_str;
		if (next != end)
			enc_str = recv_str.substr(it->position() + it->length(), next->position() - (it->position() + it->length()));
		else
			enc_str = recv_str.substr(it->position() + it->length());

		auto vec = ext::split(enc_str, '}');

		for (auto i = 0; i < vec.size(); i++)
		{
			if (vec[i].empty())
				continue;

			std::vector<std::vector<char>> encrypted_str_list;

			std::regex r2(enc_str(R"(\((.*?)\))"));
			std::regex_iterator<std::string::iterator> it2(vec[i].begin(), vec[i].end(), r2);
			while (it2 != end)
			{
				auto str_buf = ext::hex_to_bytes(it2->str().substr(1, it2->str().size() - 2));
				ext::xor_enc::inplace_xor(str_buf, checks::data::code_str);
				encrypted_str_list.push_back(str_buf);
				++it2;
			}

			std::string name;

			std::regex r3(enc_str(R"(\[(.*?)\])"));
			std::regex_iterator<std::string::iterator> it3(vec[i].begin(), vec[i].end(), r3);
			name = it3->str().substr(1, it3->str().size() - 2);

			ref_vector->emplace_back(name, encrypted_str_list);
		}

		++it;
	}

	if (it == end && !looped)
	{
		std::cout << enc_str("Webserver is down, please check the Delta Discord for updates.") << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(2));
		exit(0);
	}
}

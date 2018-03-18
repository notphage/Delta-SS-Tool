#pragma once
#include <array>
#include <vector>
#include <atomic>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <future>
#include <functional>
#include <stdexcept>

#define _SILENCE_PARALLEL_ALGORITHMS_EXPERIMENTAL_WARNING
#include <execution>
#include "crypto.hpp"

//#define PRINTSTR

namespace ext
{
	class ThreadPool
	{
		// need to keep track of threads so we can join them
		std::vector<std::thread> workers;
		// the task queue
		std::queue<std::function<void()>> tasks;

		// synchronization
		std::mutex queue_mutex;
		std::condition_variable condition;
		bool stop;
	public:
		// the constructor just launches some amount of workers
		explicit ThreadPool(size_t threads)
			: stop(false)
		{
			for (size_t i = 0; i < threads; ++i)
			{
				workers.emplace_back([this]
					{
						for (;;)
						{
							std::function<void()> task;
							{
								std::unique_lock<std::mutex> lock(this->queue_mutex);
								this->condition.wait(lock,
									[this]
								{
									return this->stop || !this->tasks.empty();
								});

								if (this->stop && this->tasks.empty())
									return;

								task = std::move(this->tasks.front());
								this->tasks.pop();
							}

							task();
						}
					}
				);
			}
		}

		// add new work item to the pool
		template <class F, class... Args>
		auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args ...)>::type>
		{
			using return_type = typename std::result_of<F(Args ...)>::type;

			auto task = std::make_shared<std::packaged_task<return_type()>>(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
				);

			std::future<return_type> res = task->get_future();
			{
				std::unique_lock<std::mutex> lock(queue_mutex);

				// don't allow enqueueing after stopping the pool
				if (stop)
					throw std::runtime_error(enc_str("enqueue on stopped ThreadPool"));

				tasks.emplace([task]()
				{
					(*task)();
				});
			}
			condition.notify_one();
			return res;
		}

		~ThreadPool()
		{
			{
				std::unique_lock<std::mutex> lock(queue_mutex);
				stop = true;
			}

			condition.notify_all();
			for (std::thread& worker : workers)
				worker.join();
		}
	};

	namespace xor_enc
	{
		inline void inplace_xor(std::string& message, const std::string& key)
		{
			for (size_t i = 0; i < message.length(); i++)
				message[i] ^= key[i % key.length()];
		}

		inline void inplace_xor(std::vector<char>& message, const std::string& key)
		{
			for (size_t i = 0; i < message.size(); i++)
				message[i] ^= key[i % key.length()];
		}
	}

	namespace pattern_impl
	{
		inline void fill_shift_table(const uint8_t* pPattern, size_t patternSize, uint8_t wildcard, size_t* bad_char_skip)
		{
			size_t idx = 0;
			size_t last = patternSize - 1;

			// Get last wildcard position
			for (idx = last; idx > 0 && pPattern[idx] != wildcard; --idx);
			size_t diff = last - idx;
			if (diff == 0)
				diff = 1;

			// Prepare shift table
			for (idx = 0; idx <= UCHAR_MAX; ++idx)
				bad_char_skip[idx] = diff;
			for (idx = last - diff; idx < last; ++idx)
				bad_char_skip[pPattern[idx]] = last - idx;
		}

		inline bool bmh_search(const uint8_t* pScanPos, size_t scanSize, const uint8_t* pPattern, size_t patternSize, uint8_t wildcard)
		{
			size_t bad_char_skip[UCHAR_MAX + 1];
			const uint8_t* scanEnd = pScanPos + scanSize - patternSize;
			intptr_t last = static_cast<intptr_t>(patternSize) - 1;

			fill_shift_table(pPattern, patternSize, wildcard, bad_char_skip);

			// Search
			for (; pScanPos <= scanEnd; pScanPos += bad_char_skip[pScanPos[last]])
			{
				for (intptr_t idx = last; idx >= 0; --idx)
				{
					if (pScanPos[idx] != pPattern[idx])
						goto skip;

					if (idx == 0)
						return true;
				}
			skip:;
			}

			return false;
		}
	}

	inline void concurrent_searcher(std::vector<check_list>& needle_list, std::vector<char>& chunk)
	{
		std::for_each(std::execution::par_unseq, needle_list.begin(), needle_list.end(), [&](check_list& check)
		{
			auto str_list = check.detection_list();

			std::for_each(std::execution::par_unseq, str_list.begin(), str_list.end(), [&](const std::vector<char>& str)
			{
				if (pattern_impl::bmh_search(reinterpret_cast<const uint8_t*>(chunk.data()), chunk.size(), reinterpret_cast<const uint8_t*>(str.data()), str.size(), 0xCC))
				{
					check.add_detection();

#ifdef PRINTSTR
					std::cout << std::string(str.data(), str.size()) << std::endl;
#endif
				}
			});
		});
	}

	inline std::vector<std::string> split(const std::string& s, char start_delim, char end_delim)
	{
		std::vector<std::string> output;

		size_t prev_pos = 0, pos = 0;

		while ((pos = s.find(start_delim, pos)) != std::string::npos)
		{
			output.push_back(s.substr(prev_pos, pos - prev_pos - s.find(end_delim)));

			prev_pos = ++pos;
		}

		output.push_back(s.substr(prev_pos, pos - prev_pos)); // Last word

		return output;
	}

	inline std::vector<std::string> split(const std::string& s, char start_delim)
	{
		std::vector<std::string> output;

		size_t prev_pos = 0, pos = 0;

		while ((pos = s.find(start_delim, pos)) != std::string::npos)
		{
			output.push_back(s.substr(prev_pos, pos - prev_pos));

			prev_pos = ++pos;
		}

		output.push_back(s.substr(prev_pos, pos - prev_pos)); // Last word

		return output;
	}

	inline std::vector<char> hex_to_bytes(const std::string& hex)
	{
		std::vector<char> bytes;

		for (unsigned int i = 0; i < hex.length(); i += 3)
		{
			std::string byteString = hex.substr(i, 2);
			char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
			bytes.push_back(byte);
		}

		return bytes;
	}

	namespace rot47
	{
		inline void inplace_rot47(std::string& s)
		{
			std::transform(s.begin(), s.end(), s.begin(), [&](char plain)
			               {
				               return '!' + (plain - '!' + 47) % 94;
			               });
		}
	}

	namespace base64
	{
		static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

		static bool is_base64(unsigned char c)
		{
			return (isalnum(c) || (c == '+') || (c == '/'));
		}

		inline std::string base64_decode(std::string const& encoded_string)
		{
			int in_len = encoded_string.size();
			int i = 0;
			int j = 0;
			int in_ = 0;
			unsigned char char_array_4[4], char_array_3[3];
			std::string ret;

			while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
			{
				char_array_4[i++] = encoded_string[in_];
				in_++;
				if (i == 4)
				{
					for (i = 0; i < 4; i++)
						char_array_4[i] = base64_chars.find(char_array_4[i]);

					char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
					char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
					char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

					for (i = 0; (i < 3); i++)
						ret += char_array_3[i];
					i = 0;
				}
			}

			if (i)
			{
				for (j = i; j < 4; j++)
					char_array_4[j] = 0;

				for (j = 0; j < 4; j++)
					char_array_4[j] = base64_chars.find(char_array_4[j]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (j = 0; (j < i - 1); j++)
					ret += char_array_3[j];
			}

			return ret;
		}
	}
}

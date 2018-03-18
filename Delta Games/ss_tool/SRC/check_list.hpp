#pragma once
#include <vector>
#include <atomic>

struct check_list
{
	std::string name_;
	std::vector<std::vector<char>> detection_list_;
	std::atomic<uint64_t> detection_;
public:
	check_list(std::string name, std::vector<std::vector<char>> detections)
		: name_(std::move(name)), detection_list_(std::move(detections)), detection_(0)
	{
	}

	check_list(check_list&& other) noexcept
		: name_(std::move(other.name_)), detection_list_(std::move(other.detection_list_)), detection_(other.detection_.load())
	{
	}

	check_list& operator=(const check_list& other) = default;

	std::vector<std::vector<char>>& detection_list()
	{
		return detection_list_;
	}

	uint64_t get_detections() const
	{
		return detection_;
	}

	void add_detection()
	{
		++detection_;
	}

	std::string get_name() const
	{
		return name_;
	}

	friend std::ostream& operator<<(std::ostream& os, const check_list& check)
	{
		if (check.get_detections() > 0)
		{
			os << "Detected " << check.get_name() << std::endl;
		}

		return os;
	}
};

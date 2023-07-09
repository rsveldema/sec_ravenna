#pragma once

#include <chrono>

class Timeout
{
public:
    Timeout(const std::chrono::milliseconds& ms) { m_deadline = now() + ms; }

    static std::chrono::milliseconds now() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    }

private:
    std::chrono::milliseconds m_deadline;
};
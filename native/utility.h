// SPDX-License-Identifier: GPL-3.0-only
/*
 *  utility.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef UTILITY_H
#define UTILITY_H
#include <chrono>
#include <iostream>
#include <random>
#include <string>

namespace utility
{
template <typename R, typename... Args>
void measure_perf(int rep, std::string const& info, R&& r, Args&&... args)
{
    using namespace std::chrono;
    time_point<steady_clock> start = steady_clock::now();
    for (unsigned i = rep; i; i--) {
        std::invoke(std::forward<R>(r), std::forward<Args>(args)...);
    }
    auto end = steady_clock::now();
    auto t = duration_cast<nanoseconds>((end - start) / rep).count();
    if (t) {
        std::cout << info << ": each round took <" << t << "> nanoseconds\n";
    } else {
        auto t = duration_cast<nanoseconds>(end - start).count();
        std::cout << info << ": [" << rep << "] rounds took <" << t << "> nanoseconds\n";
    }
}

template <typename R, typename... Args>
void measure(std::string const& info, R&& r, Args&&... args)
{
    measure_perf(5000, info, std::forward<R>(r), std::forward<Args>(args)...);
}

template <typename R, typename... Args>
void measure_slow(std::string const& info, R&& r, Args&&... args)
{
    measure_perf(1000, info, std::forward<R>(r), std::forward<Args>(args)...);
}

template <typename R, typename... Args>
void measure_very_slow(std::string const& info, R&& r, Args&&... args)
{
    measure_perf(50, info, std::forward<R>(r), std::forward<Args>(args)...);
}

template <typename R, typename... Args>
void test_run(std::string const& info, R&& r, Args&&... args)
{
    bool ret = true;
    unsigned i;
    std::cout << info << ":\n";
    for (i = 0; i < 24; i++) {
        std::cout << ".";
        ret = std::invoke(std::forward<R>(r), std::forward<Args>(args)...);
        if (!ret)
            break;
    }
    if (!ret) {
        std::cout << "\ntest failed at round <" << i << ">\n";
        exit(1);
    } else {
        std::cout << "\npassed\n";
    }
}

} // namespace utility

#endif

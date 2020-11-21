#ifndef DEBUG_H
#define DEBUG_H

#ifdef HAVE_LOG

#include "secure_allocator.h"
#include <string>
#include <vector>

class Logger {
public:
    enum class LEVEL : uint8_t {
        error,
        warn,
        info,
        debug,
        verbose
    };

    Logger(LEVEL l = LEVEL::debug) : level{l} {};

    template <typename... Args>
    void verbose(Args&&... args) {
        print(LEVEL::verbose, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void debug(Args&&... args) {
        print(LEVEL::debug, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void info(Args&&... args) {
        print(LEVEL::info, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void warn(Args&&... args) {
        print(LEVEL::warn, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void error(Args&&... args) {
        print(LEVEL::error, std::forward<Args>(args)...);
    };

    template <typename... Args>
    void print(LEVEL l, Args&&... args) {
        if (level >= l)
            do_print(std::forward<Args>(args)...);
    };

private:
    void log(const std::string& msg);
    void log(const char* str);

    template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
    void log(T i) {
        log(std::to_string(i));
    }

    static inline char nibble2hex(uint8_t b)
    {
        if (b <= 9) {
            return b + '0';
        } else {
            return b - 10 + 'A';
        }
    };

    void log(secure_vector const& v)
    {
        std::string str;
        for (auto c : v) {
            str.push_back(nibble2hex(c >> 4));
            str.push_back(nibble2hex(c & 0x0F));
        }
        log(str);
    };

    void log(char c)
    {
        log(std::string{c});
    };

    template <typename T, typename... Args>
    void do_print(T arg, Args&&... args)
    {
        log(arg);
        if constexpr (sizeof...(args) > 0) {
            do_print(std::forward<Args>(args)...);
        }
    };

    LEVEL level;
};

extern Logger logger;

#define LEVEL_VERBOSE 0
#define LEVEL_DEBUG 1
#define LEVEL_INFO 2
#define LEVEL_WARN 3
#define LEVEL_ERROR 4
#define LEVEL_NONE 5

#ifndef LOG_LEVEL
#define LOG_LEVEL LEVEL_DEBUG
#endif

#if LOG_LEVEL < LEVEL_NONE
#define pr_log(level, arg0, ...)               \
    do {                                       \
        if (level >= LOG_LEVEL)                \
            logger.debug(arg0, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_log(level, ...)
#endif

#define pr_verbose(...) pr_log(LEVEL_VERBOSE, ##__VA_ARGS__)
#define pr_debug(...) pr_log(LEVEL_DEBUG, ##__VA_ARGS__)
#define pr_info(...) pr_log(LEVEL_INFO, ##__VA_ARGS__)
#define pr_warn(...) pr_log(LEVEL_WARN, ##__VA_ARGS__)
#define pr_error(...) pr_log(LEVEL_ERROR, ##__VA_ARGS__)

#else // HAVE_LOG
#define pr_verbose(...)
#define pr_debug(...)
#define pr_info(...)
#define pr_warn(...)
#define pr_error(...)
#endif

#endif // DEBUG_H

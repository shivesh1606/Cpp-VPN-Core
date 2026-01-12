#pragma once
#include <cstddef>

enum LogLevel {
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
};

void log_init();                         // auto: env / default stderr
void log_init_file(const char* path);    // explicit file
void log_shutdown();                     // flush + close

void log_write(LogLevel lvl, const char* fmt, ...);
void log_flush();

#define LOG(lvl, fmt, ...) log_write(lvl, fmt, ##__VA_ARGS__)

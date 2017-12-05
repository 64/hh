#pragma once

#define RED    "\e[31m"
#define BLUE   "\e[34m"
#define YELLOW "\e[33m"
#define WHITE  "\e[1m"
#define GREY   "\e[1;30m"
#define COLOR_RST "\e[m"

#define LOG_LEVEL_FATAL 0
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_TRACE 4

#ifndef LOG_LEVEL
#define LOG_LEVEL 4
#endif

#if LOG_LEVEL >= LOG_LEVEL_FATAL
#define log_fatal(fmt, ...) fprintf(stderr, "[" RED "ERROR" COLOR_RST "] " fmt "\n",##__VA_ARGS__)
#else
#define log_fatal(fmt, ...) do {} while(0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define log_warn(fmt, ...) fprintf(stderr, "[" YELLOW "WARN" COLOR_RST "] " fmt "\n",##__VA_ARGS__)
#else
#define log_warn(fmt, ...) do {} while(0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define log_info(fmt, ...) fprintf(stdout, "[" BLUE "INFO" COLOR_RST "] " fmt "\n",##__VA_ARGS__)
#else
#define log_info(fmt, ...) do {} while(0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_debug(fmt, ...) fprintf(stdout, "[" GREY "DEBUG" COLOR_RST " - %s:%d] " fmt "\n", __FILE__, __LINE__,##__VA_ARGS__)
#else
#define log_debug(fmt, ...) do {} while(0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_TRACE
#define log_trace() fprintf(stdout, "[" WHITE "TRACE" COLOR_RST "] %s:%d\n", __FILE__, __LINE__)
#else
#define log_trace() do {} while(0)
#endif

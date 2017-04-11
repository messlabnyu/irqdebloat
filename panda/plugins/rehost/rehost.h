#ifndef REHOST_H
#define REHOST_H

#include "panda/plugin.h"

typedef bool (*hook_func_t)(CPUState *, TranslationBlock *);

#define DEBUG_REHOST_PLUGIN

#ifdef DEBUG_REHOST_PLUGIN
#define DEBUG(fmt, ...) \
    do { fprintf(stderr, "panda_rehost - DEBUG: " fmt "\n", ## __VA_ARGS__); } while (0)
#else
#define DEBUG(fmt, ...) do {} while(0)
#endif

#define INFO(fmt, ...) \
    do { fprintf(stderr, "panda_rehost - INFO: " fmt "\n", ## __VA_ARGS__); } while (0)

#define WARN(fmt, ...) \
    do { fprintf(stderr, "panda_rehost - WARN: " fmt "\n", ## __VA_ARGS__); } while (0)

#define ERROR(fmt, ...) \
    do { fprintf(stderr, "panda_rehost - ERROR: " fmt "\n", ## __VA_ARGS__); } while (0)

#endif

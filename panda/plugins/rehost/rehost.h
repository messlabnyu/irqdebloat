#ifndef REHOST_H
#define REHOST_H

#include "panda/plugin.h"

typedef bool (*hook_func_t)(CPUState *, TranslationBlock *);

class CallTree {
    public:
        target_ulong address = 0;
        CallTree *parent = NULL;
        std::vector<CallTree*> subcalls;
};

// Logging macros

#define DEBUG_REHOST_PLUGIN // Enable debug

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

#ifndef REHOST_H
#define REHOST_H

#include "panda/plugin.h"

enum device_t {
    UNKNOWN_DEVICE = 0,
    UART_DEVICE,
    TIMER_DEVICE,
    INTERRUPT_CONTROLLER_DIST,
    INTERRUPT_CONTROLLER_CPU,
    NAND_CONTROLLER_DEVICE
};

typedef bool (*hook_func_t)(CPUState *, TranslationBlock *);

#define DEBUG_REHOST_PLUGIN

#ifdef DEBUG_REHOST_PLUGIN
#define DEBUG(fmt, ...) \
    do { fprintf(stderr, "panda_rehost: " fmt "\n", ## __VA_ARGS__); } while (0)
#else
#define DEBUG(fmt, ...) do {} while(0)
#endif

#endif

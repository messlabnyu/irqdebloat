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

typedef void (*hook_func_t)(CPUState *);

#endif

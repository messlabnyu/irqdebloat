/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

extern "C" {
#include "callstack_instr/callstack_instr.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}

FILE *outf;

static void print_call(CPUState *env, target_ulong called_func, target_ulong ret_addr, target_ulong stackid) {
    fprintf(outf, "=> " TARGET_FMT_lx "\n", called_func);
}

static void print_ret(CPUState *env, target_ulong func, target_ulong ret_addr, target_ulong stackid) {
    fprintf(outf, "<= " TARGET_FMT_lx "\n", func);
}

bool init_plugin(void *self) {
    panda_require("callstack_instr");

    PPP_REG_CB("callstack_instr", on_call, print_call);
    PPP_REG_CB("callstack_instr", on_ret, print_ret);

    panda_arg_list *args = panda_get_args("printcalls");
    const char *name = panda_parse_string_req(args, "out", "name of the output file");
    outf = fopen(name, "w");

    return true;
}

void uninit_plugin(void *self) {
    fclose(outf);
}

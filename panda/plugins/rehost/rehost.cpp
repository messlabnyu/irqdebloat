/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Nick Gregory    ngregory@nyu.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#define __STDC_FORMAT_MACROS

#include <iostream>
#include <string>
#include <unordered_map>
#include <map>
#include <vector>
#include <deque>
#include <unordered_set>
#include <time.h>
#include <fstream>
#include <sstream>

#include "rehost.h"
#include "packets.pb.h"

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"


extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

// Declaration from sysemu/sysemu.h
void qemu_system_shutdown_request();

}

// Connection stuff
int master_sockfd;

int recv_pkt(packets::PacketType type, std::string &pkt)
{
    uint32_t recvd_type, pkt_len, read_len;
    recvd_type = 0xffffffff;
    pkt_len = 0;
    read_len = 0;
    char *c_pkt = 0;

    if (read(master_sockfd, &recvd_type, sizeof(recvd_type)) != sizeof(recvd_type)) {
        ERROR("Error reading packet type");
        return -1;
    }

    recvd_type = ntohl(recvd_type);

    if (recvd_type != type) {
        ERROR("Received unexpected type. Expected %d got %d", type, recvd_type);
        return -2;
    }

    if (read(master_sockfd, &pkt_len, sizeof(pkt_len)) != sizeof(pkt_len)) {
        ERROR("Error reading packet length");
        return -1;
    }

    pkt_len = ntohl(pkt_len);
    if (pkt_len == 0) {
        pkt = std::string();
        return 0;
    }

    c_pkt = (char*)malloc(pkt_len);
    if (!c_pkt) {
        ERROR("Can't allocate memory for packet data");
        return -1;
    }

    while (read_len < pkt_len) {
        size_t read_this_round = 0;
        if (!(read_this_round = read(master_sockfd, c_pkt+read_len, pkt_len-read_len))) {
            ERROR("Error reading packet. Read %d bytes, expected %d bytes", read_len, pkt_len);
            free(c_pkt);
            return -3;
        }
        read_len += read_this_round;
    }

    pkt = std::string(c_pkt, pkt_len);

    return 0;
}

int send_pkt(packets::PacketType type, const std::string &pkt)
{
    uint32_t pkt_type = htonl(type);

    if (send(master_sockfd, &pkt_type, sizeof(pkt_type), 0) != sizeof(pkt_type)) {
        ERROR("Error sending packet type");
        return -1;
    }

    uint32_t pkt_len = htonl(pkt.length());
    if (send(master_sockfd, &pkt_len, sizeof(pkt_len), 0) != sizeof(pkt_len)) {
        ERROR("Error sending packet length");
        return -1;
    }

    const char *raw_pkt = pkt.c_str();

    if (send(master_sockfd, raw_pkt, pkt.length(), 0) != pkt.length()) {
        ERROR("Error sending packet");
        return -1;
    }

    return 0;
}

// State tracking
packets::MemoryAccess::DeviceType last_device = packets::MemoryAccess::UNKNOWN;
clock_t last_device_time = 0;

// Log from hooking printk & co.
std::string guest_log;


/*
 * Guest function hooks
 */

// set ARG0_REG to the register value which contains the first argument to a
// function based on the standard calling convention for that arch
#if defined(TARGET_ARM)
#define ARG0_REG (((CPUArchState*)cpu->env_ptr)->regs[0])

#elif defined(TARGET_MIPS)
#define ARG0_REG (((CPUArchState*)cpu->env_ptr)->regs[4])

#else
#define ARG0_REG (0)
#endif

bool set_last_device(packets::MemoryAccess::DeviceType type)
{
    last_device = type;
    last_device_time = clock();

    return 0;
}

bool emit_char_hook(CPUState *cpu, TranslationBlock *tb)
{
    char chr = (char)ARG0_REG;

    guest_log += chr;
    printf("%c", (char)chr);
    
    return 0;
}

// Not currently used - emit_char_hook is used so we can get formatted output
bool print_hook(CPUState *cpu, TranslationBlock *tb)
{
    uint8_t buf[1024];

    panda_virtual_memory_read(cpu, ARG0_REG, buf, sizeof(buf));

    printf("%s", buf);
    
    return 0;
}

bool poweroff_hook(CPUState *cpu, TranslationBlock *tb)
{
    INFO("Kernel exiting, stopping qemu early");
    qemu_system_shutdown_request();
    
    return 0;
}

/*
 * List of addresses that have already been patched by the skip function.
 * We need to keep this to prevent an endless loop of exec->re-translate->exec->...
 * We can't write all of these at load time because things may not be loaded/decompressed yet.
 * We only care about things in kernel-land right now so there's no chance we'll have a
 *  virtual address overlap issue.
 */
std::unordered_set<target_ulong> patched_funcs;

#if defined(TARGET_ARM)
    // mov r0, #0; bx lr
    uint8_t patch_asm[] = {0x00, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1};

#elif defined(TARGET_MIPS)
#ifdef TARGET_WORDS_BIGENDIAN
    // big e
    // move $v0, $0; jr $ra
    uint8_t patch_asm[] = {0x20, 0x02, 0x00, 0x00, 0x03, 0xe0, 0x00, 0x08};
#else
    // little e
    uint8_t patch_asm[] = {0x00, 0x00, 0x02, 0x20, 0x08, 0x00, 0xe0, 0x03};
#endif

#else
    uint8_t patch_asm[] = {};
#endif

bool skip_func(CPUState *cpu, TranslationBlock *tb)
{

    target_ulong addr = tb->pc;

    if (patched_funcs.find(tb->pc) == patched_funcs.end()) {
        DEBUG("Patching function at 0x" TARGET_FMT_lx, addr);
        panda_virtual_memory_write(cpu, addr, patch_asm, sizeof(patch_asm));
        patched_funcs.insert(addr);
        return true; // Signal that we need to invalidate the TB
    } else {
        return false; // TB already modified on a prior run so no need to invalidate
    }
}


/*
 * Plugin-wide maps
 */

// addr->function: hook function to run when addr is executed
std::unordered_map<target_ulong, std::vector<hook_func_t>> hooks;

// func_name->addr: function name to address lookup so we can have
// position-independent constant hooks in `readable_hooks`
std::map<std::string, target_ulong> kallsyms;

// addr: set of all kernel function addresses for call trace generation
std::unordered_set<target_ulong> kernel_functions;

// func_name->function: hook function to run when the kernel function
// func_name is called
std::map<std::string, hook_func_t> readable_hooks = {
    {"emit_log_char", emit_char_hook},
    {"printascii", skip_func}, // Appears this expects the UART to fully work so let's get rid of it for now
    {"init_IRQ", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(packets::MemoryAccess::INTERRUPT_CONTROLLER_DIST);
        }
    },
    {"gic_cpu_init", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(packets::MemoryAccess::INTERRUPT_CONTROLLER_CPU);
        }
    },
    {"uart_register_driver", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(packets::MemoryAccess::UART);
        }
    },
    {"*timer_init", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(packets::MemoryAccess::TIMER);
        }
    },
    {"panic", poweroff_hook},
};

// addr->queue: ordered list of all previously encountered memory accesses
// so we know how to respond and/or if we've diverged
std::unordered_map<target_ulong, std::deque<packets::MemoryAccess>> known_mem_accesses;

CallTree call_tree;
CallTree *current_branch = &call_tree;
size_t depth;


/*
 * PANDA callback functions
 */

void add_call(CPUState *env, target_ulong func)
{
	if (kernel_functions.find(func) != kernel_functions.end()) {
		CallTree *new_branch = new CallTree();
		new_branch->address = func;
		new_branch->parent = current_branch;
		current_branch->subcalls.push_back(new_branch);
		current_branch = new_branch;
		depth++;
	}
}

void return_from_call(CPUState *env, target_ulong func)
{
    /*
     * callstack_instr doesn't really look for RET instructions, but
     * rather it looks to see if a BB is the expected return address
     * of a given call. Because of this, we can skip multiple steps
     * back up the call tree in one call to this callback
     */

    // If this is the RET from a kernel function we would have added
    // a branch because of
    if (kernel_functions.find(func) != kernel_functions.end()) {
        // Walk until we find the branch where addr is what we're returning from
        // In 99% of cases this loop won't ever iterate because current_branch->addr
        // is likely already `func`
        while (current_branch->address != func && current_branch->parent != NULL) {
            depth--;
            current_branch = current_branch->parent;
        }

        if (current_branch->parent == NULL) {
            WARN("Couldn't find CALL corresponding to ret (from func " TARGET_FMT_lx ")!", func);
        } else {
            depth--;
            current_branch = current_branch->parent;
        }
    }
}

bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb)
{
    bool ret = false;

    auto func_hooks = hooks.find(tb->pc);
    if (func_hooks != hooks.end()) {
        for (auto &hook : func_hooks->second) {
            ret |= (*hook)(cpu, tb);
        }
    }

    if (ret) {
        DEBUG("Invalidating the translation block at 0x" TARGET_FMT_lx, tb->pc);
    }

    return ret;
}

int check_unassigned_mem_r(CPUState *cpu, target_ulong pc, target_ulong addr,
                           target_ulong size, void *buf)
{
    MemoryRegion *subregion;
    
    QTAILQ_FOREACH(subregion, &cpu->memory->subregions, subregions_link) {
        if (addr >= subregion->addr && addr < subregion->addr + subregion->size) {
            // addr is in a defined memory region, so just let QEMU process it as normal
            return 0;
        }
    }

    // This memory read is not in any existing MemoryRegion, so try to respond from
    // what the master sent us at startup

    if (!known_mem_accesses[addr].empty()) {
        packets::MemoryAccess old_access = known_mem_accesses[addr].front();
        known_mem_accesses[addr].pop_front();
        
        if (old_access.type() != packets::MemoryAccess::READ) {
            WARN("Desync! Memory read at " TARGET_FMT_lx " but next expected access is write", addr);
            return 0;
        }

        uint64_t old_size = old_access.value().length();
        if (old_size != size) {
            WARN("Desync! Memory read at " TARGET_FMT_lx " was size %lu before, now is " TARGET_FMT_lx, addr, old_size, size);
            return 0;
        }

        memcpy(buf, old_access.value().c_str(), size);

    } else {
        for (unsigned i = 0; i < size; i++) {
            *(uint8_t *)(buf+i) = rand() % 256;
        }

        packets::MemoryAccess new_access;
        new_access.set_address(addr);
        new_access.set_type(packets::MemoryAccess::READ);
        new_access.set_device(last_device);
        
        std::string response((char*)buf, size);
        new_access.set_value(response);

        std::string pkt;
        new_access.SerializeToString(&pkt);
        
        if (send_pkt(packets::PacketType::NEW_MEMORY_ACCESS, pkt)) {
            ERROR("Failed to send memory access notification");
        }
        
        last_device = packets::MemoryAccess::UNKNOWN;
    }
    
    return 0;
}

int check_unassigned_mem_w(CPUState *cpu, target_ulong pc, target_ulong addr,
                           target_ulong size, void *buf)
{
    MemoryRegion *subregion;
    
    QTAILQ_FOREACH(subregion, &cpu->memory->subregions, subregions_link) {
        if (subregion->addr <= addr && addr < subregion->addr + subregion->size) {
            return 0;
        }
    }

    if (!known_mem_accesses[addr].empty()) {
        packets::MemoryAccess old_access = known_mem_accesses[addr].front();
        known_mem_accesses[addr].pop_front();
        
        if (old_access.type() != packets::MemoryAccess::WRITE) {
            WARN("Desync! Memory write at " TARGET_FMT_lx " but next expected access is read", addr);
            return 0;
        }

        uint64_t old_size = old_access.value().length();
        if (old_size != size) {
            WARN("Desync! Memory write at " TARGET_FMT_lx " was size %lu before, now is " TARGET_FMT_lx, addr, old_size, size);
            return 0;
        }

        if (memcmp(buf, old_access.value().c_str(), size)) {
            WARN("Memory write at " TARGET_FMT_lx " has a different value now", addr);
        }
    } else {
        packets::MemoryAccess new_access;
        new_access.set_address(addr);
        new_access.set_type(packets::MemoryAccess::WRITE);
        new_access.set_device(last_device);
        
        std::string val((char*)buf, size);
        new_access.set_value(val);

        std::string pkt;
        new_access.SerializeToString(&pkt);
        
        if (send_pkt(packets::PacketType::NEW_MEMORY_ACCESS, pkt)) {
            ERROR("Failed to send memory access notification");
        }
        
        last_device = packets::MemoryAccess::UNKNOWN;
    }
    
    return 0;
}


/*
 * Plugin initialization
 */

int recv_symtab()
{
    std::string pkt;

    if (recv_pkt(packets::PacketType::SYMBOLS, pkt)) {
        ERROR("Error receiving SYMBOLS packet");
        return -1;
    }

    packets::SymbolTable parsed_symtab;

    if (!parsed_symtab.ParseFromString(pkt)) {
        ERROR("Error parsing SYMBOLS packet");
        return -1;
    }

    for (packets::SymbolTable::Symbol sym : parsed_symtab.symbols()) {
        kallsyms[sym.name()] = sym.address();
        kernel_functions.insert(sym.address());
    }

    // Transform the readable_hooks into their address equivalents
    for (auto hook : readable_hooks) {
        std::string sym_name = hook.first;
        hook_func_t callback = hook.second;
        
        if (sym_name[0] == '*') {
            for (auto ksym : kallsyms) {
                if (ksym.first.find(sym_name.substr(1)) != std::string::npos) {
                    hooks[ksym.second].push_back(callback);
                }
            }
        } else {
            auto resolved_addr = kallsyms.find(sym_name);
            if (resolved_addr != kallsyms.end()) {
                hooks[resolved_addr->second].push_back(callback);
            } else {
                WARN("Function %s used in a hook is not present in kallsyms", sym_name.c_str());
            }
        }
    }

    DEBUG("Received %zu symbols", kallsyms.size());
    
    return 0;
}

int recv_mem_accesses()
{
    std::string pkt;

    if (recv_pkt(packets::PacketType::OLD_MEMORY_ACCESSES, pkt)) {
        ERROR("Error receiving OLD_MEMORY_ACCESSES packet");
        return -1;
    }

    packets::OldMemoryAccesses parsed_accesses;

    if (!parsed_accesses.ParseFromString(pkt)) {
        ERROR("Error parsing OLD_MEMORY_ACCESSES packet");
        return -1;
    }

    for (packets::MemoryAccess access : parsed_accesses.accesses()) {
        known_mem_accesses[access.address()].push_back(access);
    }

    DEBUG("Received %d known memory accesses", parsed_accesses.accesses().size());

    return 0;
}

int recv_nop_functions()
{
    std::string pkt;

    if (recv_pkt(packets::PacketType::NOP_FUNCTIONS, pkt)) {
        ERROR("Error receiving NOP_FUNCTIONS packet");
        return -1;
    }

    packets::NOPFunctions parsed_nops;

    if (!parsed_nops.ParseFromString(pkt)) {
        ERROR("Error parsing NOP_FUNCTIONS packet");
        return -1;
    }

    for (uint64_t func : parsed_nops.addresses()) {
        DEBUG("Adding 0x%08lx as a function to NOP", func);
        hooks[func].push_back(skip_func);
    }
    
    return 0;
}

int connect_master(const char *server_string, uint32_t session_id)
{
    struct sockaddr_in server;
    master_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (master_sockfd < 0) {
        ERROR("Couldn't create socket");
        return -1;
    }
    
    // Yes this is bad, no I don't care
    char ip[16];
    uint16_t port;
    
    if (sscanf(server_string, "%s %hu", ip, &port) != 2) {
        ERROR("Error parsing master server string");
        return -1;
    }
    
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(master_sockfd, (sockaddr*)&server, sizeof(server)) < 0) {
        ERROR("Couldn't connect to master server");
        return -1;
    }

    uint32_t id_nl = htonl(session_id);

    send(master_sockfd, &id_nl, sizeof(id_nl), 0);

    recv_symtab();
    recv_mem_accesses();
    recv_nop_functions();
    
    INFO("Fully synced with master. Beginning emulation");

    return 0;
}

bool init_plugin(void *self)
{
    panda_cb cb;
    panda_arg_list *args;
    uint32_t session_id;
    const char *server;

    /* Callback registration */

    // May not be necessary but to afraid that not having this will silently break stuff
    panda_disable_tb_chaining();
    cb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, cb);
   
    panda_enable_memcb();
    cb.phys_mem_after_read = check_unassigned_mem_r;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, cb);
    cb.phys_mem_after_write = check_unassigned_mem_w;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, cb);

	panda_require("callstack_instr");
    if (!init_callstack_instr_api()) {
        ERROR("callstack_instr failed to initialize");
        return false;
    }

    PPP_REG_CB("callstack_instr", on_call, add_call);
    PPP_REG_CB("callstack_instr", on_ret, return_from_call);

    /* Arg parsing */
    args = panda_get_args("rehost");
    
    session_id = panda_parse_uint32_req(args, "id", "The session ID of this QEMU runner");
    
    // Seed random for memory READ responses so that it will differ between runs but
    // is still easily replicable for testing/debugging.
    srand(session_id);

    server = panda_parse_string_req(args, "server", "host port of the server that we should communicate information back to");

    panda_free_args(args);

    /* Final init */
    if (connect_master(server, session_id)) {
        WARN("Failed to connect to master and sync");
        return false;
    }

    return true;
}

void dump_calltree(packets::CallTree *pkt_call_tree)
{
    pkt_call_tree->set_address(current_branch->address);
    for (auto subcall : current_branch->subcalls) {
        current_branch = subcall;
        packets::CallTree *new_pkt_tree = pkt_call_tree->add_called();
        dump_calltree(new_pkt_tree);
        current_branch = current_branch->parent;

    }
}

void uninit_plugin(void *self)
{
    INFO("Unloading plugin");
    packets::CallTree pkt_call_tree;
    unsigned i = 0;
    while (current_branch->parent != NULL) {
        i++;
        current_branch = current_branch->parent;
    }

    INFO("We stopped emulation %u calls deep", i);

    dump_calltree(&pkt_call_tree);

    std::string pkt;
    pkt_call_tree.SerializeToString(&pkt);
    
    if (send_pkt(packets::PacketType::CALL_TRACE, pkt)) {
        ERROR("Failed to send final call trace");
    }

    packets::GuestLog log;
    log.set_log(guest_log);

    log.SerializeToString(&pkt);

    if (send_pkt(packets::PacketType::GUEST_LOG, pkt)) {
        ERROR("Failed to send final guest log");
    }
    
    INFO("Unloaded");
}

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

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}


// Connection stuff
int master_sockfd;

int recv_pkt(PacketType type, std::string &pkt)
{
    uint32_t recvd_type, pkt_len, read_len;
    recvd_type = 0xffffffff;
    pkt_len = 0;
    read_len = 0;
    char *c_pkt = 0;

    if (read(master_sockfd, &recvd_type, sizeof(recvd_type)) != sizeof(recvd_type)) {
        DEBUG("Error reading packet type");
        return -1;
    }

    recvd_type = ntohl(recvd_type);

    if (recvd_type != type) {
        DEBUG("Received unexpected type. Expected %d got %d", type, recvd_type);
        return -2;
    }

    if (read(master_sockfd, &pkt_len, sizeof(pkt_len)) != sizeof(pkt_len)) {
        DEBUG("Error reading packet length");
        return -1;
    }

    pkt_len = ntohl(pkt_len);
    if (pkt_len <= 0) {
        DEBUG("Bad packet length recieved %d", pkt_len);
        return -1;
    }

    c_pkt = (char*)malloc(pkt_len);
    if (!c_pkt) {
        DEBUG("Can't allocate memory for packet data");
        return -1;
    }

    while (read_len < pkt_len) {
        size_t read_this_round = 0;
        if (!(read_this_round = read(master_sockfd, c_pkt+read_len, pkt_len-read_len))) {
            DEBUG("Error reading packet. Read %d bytes, expected %d bytes", read_len, pkt_len);
            free(c_pkt);
            return -3;
        }
        read_len += read_this_round;
    }

    pkt = std::string(c_pkt, pkt_len);

    return 0;
}

int send_pkt(PacketType type, const std::string &pkt)
{
    uint32_t pkt_type = htonl(type);

    if (send(master_sockfd, &pkt_type, sizeof(pkt_type), 0) != sizeof(pkt_type)) {
        DEBUG("Error sending packet type");
        return -1;
    }

    uint32_t pkt_len = htonl(pkt.length());
    if (send(master_sockfd, &pkt_len, sizeof(pkt_len), 0) != sizeof(pkt_len)) {
        DEBUG("Error sending packet length");
        return -1;
    }

    const char *raw_pkt = pkt.c_str();

    if (send(master_sockfd, raw_pkt, pkt.length(), 0) != pkt.length()) {
        DEBUG("Error sending packet");
        return -1;
    }

    return 0;
}

// State tracking
MemoryAccess::DeviceType last_device = MemoryAccess::UNKNOWN;
clock_t last_device_time = 0;


/*
 * Guest function hooks
 */

bool set_last_device(MemoryAccess::DeviceType type)
{
    last_device = type;
    last_device_time = clock();

    return 0;
}

bool print_hook(CPUState *cpu, TranslationBlock *tb)
{
    uint8_t buf[1024];
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong str_ptr = env->regs[0]; // TODO: Architecture neutral

    panda_virtual_memory_read(cpu, str_ptr, buf, sizeof(buf));

    printf("%s", buf);
    
    return 0;
}

bool poweroff_hook(CPUState *cpu, TranslationBlock *tb)
{
    DEBUG("Machine should restart or shutdown now.");
    
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

// mov r0, #0; bx lr
// TODO: architecture-independent
uint8_t patch_asm[] = {0x00, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1};

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
    {"printk", print_hook},
    {"printascii", print_hook},
    {"init_IRQ", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(MemoryAccess::INTERRUPT_CONTROLLER_DIST);
        }
    },
    {"gic_cpu_init", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(MemoryAccess::INTERRUPT_CONTROLLER_CPU);
        }
    },
    {"uart_register_driver", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(MemoryAccess::UART);
        }
    },
    {"die", poweroff_hook},
    {"machine_restart", poweroff_hook},
};

// addr->queue: ordered list of all previously encountered memory accesses
// so we know how to respond and/or if we've diverged
std::unordered_map<target_ulong, std::deque<MemoryAccess>> known_mem_accesses;

// TODO: Call tree
// TODO: Hook function returns to know when to step up the tree


/*
 * PANDA callback functions
 */

bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb)
{
    bool ret = false;

    auto func_hooks = hooks.find(tb->pc);
    if (func_hooks != hooks.end()) {
        for (auto &hook : func_hooks->second) {
            ret |= (*hook)(cpu, tb);
        }
    }

    // TODO: Add to call trace

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
        MemoryAccess old_access = known_mem_accesses[addr].front();
        known_mem_accesses[addr].pop_front();
        
        if (old_access.type() != MemoryAccess::READ) {
            DEBUG("Desync! Memory read at " TARGET_FMT_lx " but next expected access is write", addr);
            return 0;
        }

        uint64_t old_size = old_access.value().length();
        if (old_size != size) {
            DEBUG("Desync! Memory read at " TARGET_FMT_lx " was size %lu before, now is " TARGET_FMT_lx, addr, old_size, size);
            return 0;
        }

        memcpy(buf, old_access.value().c_str(), size);

    } else {
        DEBUG("New unassigned read at 0x" TARGET_FMT_lx, addr);
        DEBUG("Current last device: %u set at time %lu", last_device, last_device_time);

        for (unsigned i = 0; i < size; i++) {
            *(uint8_t *)(buf+i) = rand() % 256;
        }

        MemoryAccess new_access;
        new_access.set_address(addr);
        new_access.set_type(MemoryAccess::READ);
        new_access.set_device(last_device);
        
        std::string response((char*)buf, size);
        new_access.set_value(response);

        std::string pkt;
        new_access.SerializeToString(&pkt);
        
        if (send_pkt(PacketType::NEW_MEMORY_ACCESS, pkt)) {
            DEBUG("Failed to send memory access notification");
        }
        
        last_device = MemoryAccess::UNKNOWN;
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
        MemoryAccess old_access = known_mem_accesses[addr].front();
        known_mem_accesses[addr].pop_front();
        
        if (old_access.type() != MemoryAccess::WRITE) {
            DEBUG("Desync! Memory write at " TARGET_FMT_lx " but next expected access is read", addr);
            return 0;
        }

        uint64_t old_size = old_access.value().length();
        if (old_size != size) {
            DEBUG("Desync! Memory write at " TARGET_FMT_lx " was size %lu before, now is " TARGET_FMT_lx, addr, old_size, size);
            return 0;
        }

        if (memcmp(buf, old_access.value().c_str(), size)) {
            DEBUG("Warning: Memory write at " TARGET_FMT_lx " has a different value now", addr);
        }
    } else {
        DEBUG("New unassigned write at 0x" TARGET_FMT_lx, addr);
        DEBUG("Current last device: %u set at time %lu", last_device, last_device_time);

        MemoryAccess new_access;
        new_access.set_address(addr);
        new_access.set_type(MemoryAccess::WRITE);
        new_access.set_device(last_device);
        
        std::string val((char*)buf, size);
        new_access.set_value(val);

        std::string pkt;
        new_access.SerializeToString(&pkt);
        
        if (send_pkt(PacketType::NEW_MEMORY_ACCESS, pkt)) {
            DEBUG("Failed to send memory access notification");
        }
        
        last_device = MemoryAccess::UNKNOWN;
    }
    
    return 0;
}


/*
 * Plugin initialization
 */

int recv_symtab()
{
    std::string pkt;

    if (recv_pkt(PacketType::SYMBOLS, pkt)) {
        DEBUG("Error receiving SYMBOLS packet");
        return -1;
    }

    SymbolTable parsed_symtab;

    if (!parsed_symtab.ParseFromString(pkt)) {
        DEBUG("Error parsing SYMBOLS packet");
        return -1;
    }

    for (SymbolTable::Symbol sym : parsed_symtab.symbols()) {
        kallsyms[sym.name()] = sym.address();
        kernel_functions.insert(sym.address());
    }

    DEBUG("Received %zu symbols", kallsyms.size());
    
    return 0;
}

int recv_mem_accesses()
{
    std::string pkt;

    if (recv_pkt(PacketType::OLD_MEMORY_ACCESSES, pkt)) {
        DEBUG("Error receiving OLD_MEMORY_ACCESSES packet");
        return -1;
    }

    OldMemoryAccesses parsed_accesses;

    if (!parsed_accesses.ParseFromString(pkt)) {
        DEBUG("Error parsing OLD_MEMORY_ACCESSES packet");
        return -1;
    }

    for (MemoryAccess access : parsed_accesses.accesses()) {
        known_mem_accesses[access.address()].push_back(access);
    }

    return 0;
}

int connect_master(const char *server_string, uint32_t session_id)
{
    struct sockaddr_in server;
    master_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (master_sockfd < 0) {
        fprintf(stderr, "panda_rehost: Couldn't create socket\n");
        return -1;
    }
    
    // Yes this is bad, no I don't care
    char ip[16];
    uint16_t port;
    
    if (sscanf(server_string, "%s %hu", ip, &port) != 2) {
        fprintf(stderr, "panda_rehost: Error parsing master server string\n");
        return -1;
    }
    
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(master_sockfd, (sockaddr*)&server, sizeof(server)) < 0) {
        fprintf(stderr, "panda_rehost: Couldn't connect to master server\n");
        return -1;
    }

    uint32_t id_nl = htonl(session_id);

    send(master_sockfd, &id_nl, sizeof(id_nl), 0);

    recv_symtab();
    recv_mem_accesses();

    return 0;
}

bool init_plugin(void *self)
{
    panda_cb cb;
    panda_arg_list *args;
    uint32_t session_id;
    const char *server;

    // May not be necessary but to afraid that not having this will silently break stuff
    panda_disable_tb_chaining();
    cb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, cb);
   
    panda_enable_memcb();
    cb.phys_mem_after_read = check_unassigned_mem_r;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, cb);
    cb.phys_mem_after_write = check_unassigned_mem_w;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, cb);

    args = panda_get_args("rehost");
    
    session_id = panda_parse_uint32_req(args, "id", "The session ID of this QEMU runner");
    
    // Seed random for memory READ responses so that it will differ between runs but
    // is still easily replicable for testing/debugging.
    srand(session_id);

    server = panda_parse_string_req(args, "server", "host port of the server that we should communicate information back to");
    connect_master(server, session_id);

    panda_free_args(args);

    return true;
}

void uninit_plugin(void *self)
{
    // TODO: Dump new things to master
}

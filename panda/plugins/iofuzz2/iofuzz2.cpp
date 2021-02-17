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
bool init_plugin(void *);
void uninit_plugin(void *);
#include "loadstate/loadstate_ext.h"

// sysemu.h has some non-C++-compliant stuff in it :p
void qemu_system_shutdown_request(void);

}

#include <algorithm>
#include <unordered_set>
#include <set>
#include <sstream>
#include <vector>
#include <deque>
#include <map>

#define MAX_GENERATIONS 5

/* Returns an integer in the range [0, n).
 *
 * Uses rand(), and so is affected-by/affects the same seed.
 */
int randint(int n) {
  if ((n - 1) == RAND_MAX) {
    return rand();
  } else {
    // Supporting larger values for n would requires an even more
    // elaborate implementation that combines multiple calls to rand()
    assert (n <= RAND_MAX);

    // Chop off all of the values that would cause skew...
    int end = RAND_MAX / n; // truncate skew
    assert (end > 0);
    end *= n;

    // ... and ignore results from rand() that fall above that limit.
    // (Worst case the loop condition should succeed 50% of the time,
    // so we can expect to bail out of this loop pretty quickly.)
    int r;
    while ((r = rand()) >= end);

    return r % n;
  }
}

#ifdef TARGET_ARM
static target_ulong vbar_addr(CPUState *cs) {
    CPUArchState *env = (CPUArchState *)cs->env_ptr;
    target_ulong addr = 0;
    if (A32_BANKED_CURRENT_REG_GET(env, sctlr) & SCTLR_V) {
        /* High vectors. When enabled, base address cannot be remapped. */
        addr += 0xffff0000;
    } else {
        /* ARM v7 architectures provide a vector base address register to remap
         * the interrupt vector table.
         * This register is only followed in non-monitor mode, and is banked.
         * Note: only bits 31:5 are valid.
         */
        addr += A32_BANKED_CURRENT_REG_GET(env, vbar);
    }
    return addr;
}
#endif

typedef std::pair<target_ulong,target_ulong> edge_t;

// (src,dst) -> hit count
std::map<edge_t,int> edges;
std::set<target_ulong> ioaddrs;
std::set<target_ulong> seen_bbs;

const char *memfile;
const char *cpufile;
const char *outdir;
unsigned long fuzz_timeout;
time_t start;
unsigned long *iovals = NULL;
int num_iovals = 0;
int comm_socket;
bool child = false;
size_t execs = 0;
uint32_t nr_cpu = 16;
bool fiq = false;
bool long_win = false;

#ifndef TARGET_ARM
#define CPU_INTERRUPT_FIQ 0
#endif

#define MAX_BLOCKS_SINCE_NEW_COV 100000
#define MAX_BLOCKS               1000000
int num_blocks_since_new_cov = 0;
int num_blocks_total = 0;

#ifdef DEBUG
#define dbgprintf(...) do { printf(__VA_ARGS__); } while(0)
#else
#define dbgprintf(...) do{ } while (0)
#endif

enum exit_reason {
    REASON_TIMEOUT,
    REASON_MAXBLOCKS,
    REASON_ABORT,
    REASON_NOCOV,
    REASON_STALL
};

enum entry_kind {
    ENTRY_BLOCK,
    ENTRY_IOVAL_READ,
    ENTRY_IOVAL_WRITE,
    ENTRY_EXIT
};

typedef struct _trace_entry {
    uint32_t kind;
    uint32_t pc;
    uint32_t addr;
    uint32_t val;
} trace_entry;

trace_entry make_io_rlog(uint32_t pc, uint32_t addr, uint32_t val) {
    trace_entry t = {ENTRY_IOVAL_READ, pc, addr, val};
    return t;
}

trace_entry make_io_wlog(uint32_t pc, uint32_t addr, uint32_t val) {
    trace_entry t = {ENTRY_IOVAL_WRITE, pc, addr, val};
    return t;
}

trace_entry make_block_log(uint32_t pc, uint32_t size) {
    trace_entry t = {ENTRY_BLOCK, pc, 0, size};
    return t;
}

trace_entry make_exit_log(enum exit_reason e) {
    trace_entry t = {ENTRY_EXIT, 0, 0, e};
    return t;
}

std::vector<trace_entry> trace;

// This function and the one below have to be carefully kept in sync
static void report_coverage(int fd) {
    dbgprintf("Child %d reporting coverage on fd %d...\n", getpid(), fd);
    dbgprintf("Child has %d iovals, %zu ioaddrs, and %zu edges to report.\n",
            num_iovals, ioaddrs.size(), edges.size());
    // Serialize our ioval sequence
    write(fd, &num_iovals, sizeof(num_iovals));
    for (int i = 0; i < num_iovals; i++)
        write(fd, &iovals[i], sizeof(iovals[i]));
    // Serialize our ioaddrs
    size_t n = ioaddrs.size();
    write(fd, &n, sizeof(n));
    for (auto addr : ioaddrs)
        write(fd, &addr, sizeof(addr));
    // Serialize edges
    n = edges.size();
    write(fd, &n, sizeof(n));
    for (auto &kvp : edges) {
        edge_t edge = kvp.first;
        write(fd, &edge.first, sizeof(edge.first));
        write(fd, &edge.second, sizeof(edge.second));
    }
    // Serialize trace
    n = trace.size();
    write(fd, &n, sizeof(n));
    for (auto &te : trace) {
        write(fd, &te, sizeof(trace_entry));
    }
    close(fd);
}

typedef std::pair<std::set<target_ulong>, std::set<edge_t>> covtype;

template <class T>
inline void hash_combine(std::size_t& seed, const T& v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}

struct Hash {
      size_t operator()(const covtype &c) const;
};

size_t Hash::operator()(const covtype &c) const {
    size_t seed = 0;
    for (auto ioaddr : c.first) hash_combine(seed, ioaddr);
    for (auto edge : c.second) {
        hash_combine(seed, edge.first);
        hash_combine(seed, edge.second);
    }
    return seed;
}

void try_jit(target_ulong bb) {
    auto res = seen_bbs.insert(bb);
    if (res.second) {
        CPUArchState *env = (CPUArchState *)first_cpu->env_ptr;
        target_ulong pc, cs_base;
        uint32_t flags;
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        tb_gen_code(first_cpu, bb, 0, flags, 0);
    }
}

// Set of { (io_addrs, edges) } where edges is set of (src,dst)
std::unordered_set<covtype,Hash> coverage;
std::unordered_set<uint32_t> bbcov;

static void save_coverage(
        std::vector<unsigned long> &ioseq,
        const covtype &cov,
        trace_entry *t,
        size_t n_t
        ) {
    std::stringstream s;
    s << outdir << "/";
    for (auto ioi = ioseq.begin() ; ioi != ioseq.end(); ioi++) {
        s << std::hex << *ioi;
        if (ioi != ioseq.end() - 1) s << ",";
    }
    s << ".cov";
    FILE *f = fopen(s.str().c_str(),"w");
    fprintf(f, "IOADDRS:");
    for (auto ioaddr : cov.first) {
        fprintf(f, " " TARGET_FMT_lx, ioaddr);
    }
    fprintf(f, "\n");
    for (auto edge : cov.second) {
        fprintf(f, TARGET_FMT_lx " " TARGET_FMT_lx "\n", edge.first, edge.second);
    }
    fclose(f);
    // Write the binary trace
    s.str("");
    s << outdir << "/";
    for (auto ioi = ioseq.begin() ; ioi != ioseq.end(); ioi++) {
        s << std::hex << *ioi;
        if (ioi != ioseq.end() - 1) s << ",";
    }
    s << ".btrace";
    f = fopen(s.str().c_str(),"wb");
    for (unsigned i = 0; i < n_t; i++) {
        fwrite(&t[i], sizeof(trace_entry), 1, f);
    }
    fclose(f);
}

static bool update_coverage(int fd, std::vector<unsigned long> &ioseq) {
    dbgprintf("Receiving coverage on socket %d...\n", fd);
    // Deserialize ioval sequence
    int num_ioseq;
    read(fd, &num_ioseq, sizeof(num_ioseq));
    for (int i = 0; i < num_ioseq; i++) {
        unsigned long val;
        read(fd, &val, sizeof(val));
        ioseq.push_back(val);
    }
    // Deserialize ioaddrs
    size_t n;
    std::set<target_ulong> local_ioaddrs;
    read(fd, &n, sizeof(n));
    for (unsigned i = 0; i < n; i++) {
        target_ulong addr;
        read(fd, &addr, sizeof(addr));
        local_ioaddrs.insert(addr);
    }
    // Deserialize edges
    std::set<edge_t> local_cov;
    read(fd, &n, sizeof(n));
    for (unsigned i = 0; i < n; i++) {
        target_ulong src, dst;
        read(fd, &src, sizeof(src));
        read(fd, &dst, sizeof(dst));
        local_cov.insert(std::make_pair(src,dst));
        // If we've never seen this bb before, JIT it so future children can benefit
        try_jit(src);
        try_jit(dst);
    }
    // Deserialize trace
    read(fd, &n, sizeof(n));
    trace_entry *child_trace = (trace_entry *)malloc(n*sizeof(trace_entry));
    for (unsigned i = 0; i < n; i++) {
        read(fd, &child_trace[i], sizeof(trace_entry));
    }
    
    dbgprintf("Run produced %zu ioaddrs and %zu edges\n",
            local_ioaddrs.size(), local_cov.size());
    //auto res = coverage.insert(std::make_pair(local_ioaddrs, local_cov));
    // temp: only count I/O addresses as new coverage
    //auto res = coverage.insert(std::make_pair(local_ioaddrs, std::set<edge_t>()));
    bool newcov = false;
    for (auto &kvp : local_cov) {
        auto r1 = bbcov.insert(kvp.first);
        newcov |= r1.second;
        auto r2 = bbcov.insert(kvp.second);
        newcov |= r2.second;
    }
    if (newcov) {
#ifdef DEBUG
        dbgprintf("Woo, we received new coverage!\n");
        dbgprintf("  ioseq: { ");
        for (auto i : ioseq) dbgprintf("%#lx ", i);
        dbgprintf("}\n");
#endif
        save_coverage(ioseq, std::make_pair(local_ioaddrs, local_cov), child_trace, n);
    }
    else {
#ifdef DEBUG
        dbgprintf("No new coverage on this seed.\n");
        dbgprintf("  ioseq: { ");
        for (auto i : ioseq) dbgprintf("%#lx ", i);
        dbgprintf("}\n");
#endif
        // This is going to create a ton of files
        //save_coverage(ioseq, std::make_pair(local_ioaddrs, local_cov), child_trace, n);
        ioseq.clear();
    }
    free(child_trace);
    return newcov;
}

// returns the socket used to communicate with the child
// (or 0 if it's the child returning)
int start_child(CPUState *env) {
    execs++;
    int socks[2] = {};
    socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
    pid_t child_pid;
    if ((child_pid = qemu_fork(NULL)) == 0) {
        start = time(NULL);
        child = true;
        comm_socket = socks[1];
        close(socks[0]);
        dbgprintf("iovals: { ");
        for (int i = 0; i < num_iovals; i++) {
            dbgprintf("%#lx ", iovals[i]);
        }
        dbgprintf("}\n");
        // Kick off the interrupt
        cpu_interrupt(env, CPU_INTERRUPT_HARD |
            (fiq ? CPU_INTERRUPT_FIQ : 0));
        return 0;
    }
    else {
        dbgprintf("Using socket %d to read from child %d who will report on socket %d.\n", socks[0], child_pid, socks[1]);
        free(iovals);
        close(socks[1]);
        return socks[0];
    }
}

// Well-known constants
void genconst(std::vector<uint64_t> &prefix, std::deque<std::vector<uint64_t>> &out) {
    out.push_back(prefix); out.back().push_back(0x0L);
    out.push_back(prefix); out.back().push_back(0xffffffffffffffffL);
    out.push_back(prefix); out.back().push_back(0x0f0f0f0f0f0f0f0fL);
    out.push_back(prefix); out.back().push_back(0xf0f0f0f0f0f0f0f0L);
}

// Sliding windows of bits
void genwin(std::vector<uint64_t> &prefix, std::deque<std::vector<uint64_t>> &out, int mask=4) {
    for (int i = 1; i <= mask; i++) {
        for (int j = 0; j < 32-i+1; j++) {
            out.push_back(prefix); out.back().push_back(((1L << i) - 1) << j);
        }
    }
}

// Random values
void genrand(std::vector<uint64_t> &prefix, std::deque<std::vector<uint64_t>> &out) {
    int fd = open("/dev/urandom", O_RDONLY);
    for (int i = 0; i < 128; i++) {
        uint64_t rv;
        read(fd,&rv,sizeof(rv));
        out.push_back(prefix); out.back().push_back(rv);
    }
}

// Integers up to 256
void genint(std::vector<uint64_t> &prefix, std::deque<std::vector<uint64_t>> &out) {
    for (uint64_t i = 0; i < 256; i++) {
        out.push_back(prefix); out.back().push_back(i);
    }
}

void seq2iovals(std::vector<uint64_t> &seq) {
    num_iovals = seq.size();
    iovals = (unsigned long *)malloc(seq.size()*sizeof(unsigned long));
    for (size_t i = 0; i < seq.size(); i++) iovals[i] = seq[i];
}

#ifdef TARGET_ARM
#define WFI_ENCODING 0xe320f003
static bool block_has_wfi(CPUState *env, TranslationBlock *tb) {
    uint32_t last_insn;  
    panda_virtual_memory_read(env, tb->pc + tb->size - 4, (uint8_t *)&last_insn, 4);
    return last_insn == WFI_ENCODING;
}
#endif

target_ulong prev = -1;
static int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (child) {
        num_blocks_total++;
        dbgprintf("[%d] block %d " TARGET_FMT_lx "\n", getpid(), num_blocks_total, tb->pc);
        // We're in the child, and it's a normal basic block.
        // Update coverage
        if (prev != -1) {
            auto edge = std::make_pair(prev,tb->pc);
            if (edges.find(edge) != edges.end())
                num_blocks_since_new_cov++;
            else
                num_blocks_since_new_cov = 0;
            edges[edge]++;
            trace.push_back(make_block_log(tb->pc, tb->size));
        }
        prev = tb->pc;
        // Termination conditions: timeout or went too long without seeing
        // new coverage.
        // Note the use of _Exit() here. QEMU has many atexit handlers that
        // we want to bypass because they cause deadlocks.
        if ((time(NULL) - start) > fuzz_timeout) {
            dbgprintf("Done with fuzz (timeout), cya\n");
            trace.push_back(make_exit_log(REASON_TIMEOUT));
            report_coverage(comm_socket);
            _Exit(0);
        }
        if (num_blocks_since_new_cov > MAX_BLOCKS_SINCE_NEW_COV) {
            dbgprintf("Done with fuzz (cov fixpoint), cya\n");
            trace.push_back(make_exit_log(REASON_NOCOV));
            report_coverage(comm_socket);
            _Exit(0);
        }
        if (num_blocks_total > MAX_BLOCKS) {
            dbgprintf("Done with fuzz (max blocks), cya\n");
            trace.push_back(make_exit_log(REASON_MAXBLOCKS));
            report_coverage(comm_socket);
            _Exit(0);
        }
#ifdef TARGET_ARM
        // Bail out when we encounter an exception
        target_ulong vbase = vbar_addr(env);
        if (tb->pc == vbase+0x10 || tb->pc == vbase+0x0c) {
            dbgprintf("Done with fuzz (data/prefetch abort), cya\n");
            trace.push_back(make_exit_log(REASON_ABORT));
            report_coverage(comm_socket);
            _Exit(0);
        }

        // This is a bit of a hack around the fact that we don't have a real
        // model of the interrupt controller. In a real system something would
        // ACK the IRQ, but this will never happen here. So instead we just
        // ACK a few basic blocks after seeing the start of IRQ handling
        static int blocks_after_irq = -1;
        if (tb->pc == vbase+0x18) blocks_after_irq = 0;
        if (blocks_after_irq != -1) {
            if (blocks_after_irq < 10) blocks_after_irq++;
            else {
                env->interrupt_request = 0;
                blocks_after_irq = -1;
            }
        }
        
        // WFI will cause a stall. Detect it and abort the trace.
        if (block_has_wfi(env,tb)) {
            dbgprintf("Done with fuzz (wfi), cya\n");
            trace.push_back(make_exit_log(REASON_STALL));
            report_coverage(comm_socket);
            _Exit(0);
        }

#endif
    }
    else {
        dbgprintf("Hello, I'm the parent and I'll be running the show today. My PID is %d\n", getpid());
        //load_states(env, memfile, cpufile);
        
        time_t gen_start_time, gen_end_time;
        std::set<int> allfds;
        fd_set active_fds;
        int generation = 0;
        // Start with an empty seed
        std::vector<std::vector<uint64_t>> seeds;
        seeds.push_back(std::vector<uint64_t>());
        while (true) {
            gen_start_time = time(NULL);
            // Generate seeds for this generation
            std::deque<std::vector<uint64_t>> new_seeds;
	    if (!long_win) {
                for (auto s : seeds) {
                    genconst(s, new_seeds);
                    genwin(s, new_seeds);
                    genrand(s, new_seeds);
                    genint(s, new_seeds);
                }
	    } else {
                genwin(seeds.back(), new_seeds, 1);
		int end = new_seeds.size();
                for (int i = 0; i < end; i++) {
                for (int r = 0; r < 3; r++) {
		    genwin(new_seeds[i], new_seeds, 1);
                    new_seeds[i].push_back(0);
                }}
	    }

            for (int c = 0; c < nr_cpu; c++) {
                seq2iovals(new_seeds.front()); new_seeds.pop_front();
                // Kick off the child. This will free iovals for us.
                int child_fd = start_child(env);
                if (!child_fd) return 0;
                allfds.insert(child_fd);
                if (new_seeds.empty()) break;
            }

            while (true) {
                // Need to reset the active fds every time we return here
                FD_ZERO (&active_fds);
                for (auto ifd : allfds) FD_SET(ifd, &active_fds); 
                dbgprintf("Calling select...\n");
                struct timeval tmout = {10, 0};
                int sr = select(*std::max_element(allfds.begin(),allfds.end())+1, 
                        &active_fds, NULL, NULL, &tmout);
                if (sr == -1) {
                    perror("select");
                    break;
                }
                else if (sr == 0) {
                    dbgprintf("Hmm, no fds claim to be ready after 10 seconds...\n");
                    dbgprintf("Sounds fake but okay\n");
                }
                else {
                    dbgprintf("Select returned and found %d fds ready.\n", sr);
                }

                // Figure out which one...
                dbgprintf("Select fired, checking %zu fds.\n", allfds.size());
                for (auto it = allfds.begin(); it != allfds.end(); ) {
                    dbgprintf ("Checking fd %d... ", *it);
                    if (FD_ISSET(*it, &active_fds)) {
                        dbgprintf("Yes.\n");
                        // Children only call back when they're done
                        // So read the coverage status here, then tear
                        // down the socket wait for the child to finish,
                        // and then spawn a new one.
                        std::vector<unsigned long> this_seed;
                        if (update_coverage(*it, this_seed)) {
                            seeds.push_back(this_seed);
                        }
                        dbgprintf("Finished receiving coverage on socket %d, closing it.\n", *it);
                        // Remove it from the fd set
                        FD_CLR(*it, &active_fds);
                        close(*it);
                        it = allfds.erase(it);
#if DEBUG
                        dbgprintf("Current fds: { ");
                        for (auto ifd: allfds) dbgprintf("%d ", ifd);
                        dbgprintf("}\n");
#endif
                        // Reap the (presumably finished) child
                        wait(NULL);

                        dbgprintf("Remaining seeds: %zu Current fds: %zu\n",
                                new_seeds.size(), allfds.size());

                        if (!new_seeds.empty()) {
                            // Start a new one
                            seq2iovals(new_seeds.front()); new_seeds.pop_front();
                            int child_fd = start_child(env);
                            if (!child_fd) return 0;
                            FD_SET(child_fd, &active_fds); 
                            allfds.insert(child_fd);
                        }
                    }
                    else {
                        dbgprintf("No.\n");
                        it++;
                    }
                }
                if (allfds.empty()) {
                    gen_end_time = time(NULL);
                    printf("Finished generation %d, %zu execs, %ld seconds, %lu execs/sec\n",
                            generation, execs, gen_end_time - gen_start_time,
                            (gen_end_time - gen_start_time) > 0 ? execs / (gen_end_time - gen_start_time) : 0);
                    execs = 0;
                    generation++;
                    break;
                }
            }
            // All done
            if (generation > MAX_GENERATIONS)
                break;
        }

        // Wait for children to finish
        while (wait(NULL) != -1);
        _Exit(0);
    }

    return 0;
}

static void iowrite(CPUState *env, target_ulong pc, hwaddr addr, uint32_t size, uint64_t *val) {
    ioaddrs.insert(addr);
    trace.push_back(make_io_wlog(pc,addr,*val));
}

bool use_consistent_io = false;
double consistent_io_prob = 0.0;
std::map<hwaddr,uint64_t> cached_ioreads;

static void ioread(CPUState *env, target_ulong pc, hwaddr addr, uint32_t size, uint64_t *val) {
    static int cur_ioval = 0;
    static int fd = -1;
    uint64_t fuzz = 0;

    // In "consistency" mode, cache previously returned values for reads
    // and return those instead of picking new ones
    if (use_consistent_io &&
            cached_ioreads.find(addr) != cached_ioreads.end() &&
            randint(100) < consistent_io_prob*100) {
        fuzz = cached_ioreads[addr];
        trace.push_back(make_io_rlog(pc,addr,fuzz));
        *val = fuzz;
        return;
    }

    if (fd == -1) fd = open("/dev/urandom", O_RDONLY);
    if (cur_ioval >= num_iovals) {
        // Randomly do either (1 << i) or a true random value
        int coinflip = randint(2);
        if (coinflip) {
            uint64_t mask = 0xffffffffffffffff;
            int r = read(fd, &fuzz, sizeof(fuzz));
            assert(r > 0);
            mask = mask >> (64 - (size * 8));
            fuzz &= mask;
        }
        else {
            int bitpos = randint(33) - 1;
			if (bitpos == -1) fuzz = 0;
			else fuzz = 1 << bitpos;
		}
        //dbgprintf("IOMEM_READ %u %lx %" PRIx64 "\n", size, addr, fuzz);
    }
    else {
        fuzz = iovals[cur_ioval++];
        //dbgprintf("IOMEM_READ %u %lx %" PRIx64 "\n", size, addr, fuzz);
    }
    ioaddrs.insert(addr);
    *val = fuzz;
    trace.push_back(make_io_rlog(pc,addr,fuzz));
    if (use_consistent_io) {
        cached_ioreads[addr] = fuzz;
    }
}

void after_machine_init(CPUState *env) {
    load_states(env, memfile, cpufile);
}

bool init_plugin(void *self) {
    panda_require("loadstate");
    if (!init_loadstate_api()) return false;
    panda_arg_list *args = panda_get_args("iofuzz2");
    memfile = panda_parse_string(args, "mem", "mem");
    cpufile = panda_parse_string(args, "cpu", "cpu");
    fuzz_timeout = panda_parse_ulong(args, "timeout", 10);
    outdir = panda_parse_string(args, "dir", "irqfuzz");
    nr_cpu = panda_parse_uint32(args, "nproc", 16);
    fiq = panda_parse_bool(args, "fiq");
    consistent_io_prob = panda_parse_double(args, "consistent_io_prob", 0.0);
    use_consistent_io = consistent_io_prob > 0.0;
    long_win = panda_parse_bool(args, "wiiin");

    mkdir(outdir, 0755);

    panda_cb pcb = { .unassigned_io_read = ioread };
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    pcb.unassigned_io_write = iowrite;
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_WRITE, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.after_machine_init = after_machine_init;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);

    panda_disable_tb_chaining();
    panda_enable_precise_pc();

    return true;
}

void uninit_plugin(void *self) { }

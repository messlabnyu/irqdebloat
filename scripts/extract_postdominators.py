from binaryninja import *
import argparse
import time, json, struct
import itertools
import os

'''
This is a script to get the post-dominators for each branch instruction. Note that there might be multiple exit/return points in one function, while the dominator/post-dominiator searching algorithm assumes that there's only one root node. This implementation takes the execution trace, and finds the returning block from the trace (which is fairly intuitive that for each function there's going to be only one returning block given the execution trace.) and then takes this returning block as the root to compute the post-dominators.

The returning block of a function can still be different under different context. In case of that, we keep it a map of different return blocks and post-dominators. When doing the Execution Indexing, we look at the address of the return block in the trace, and look up for a post-dominator.

After we determine the returning block, we build post-dominator tree - dominator algorithm on the reversed CFG. The algorithm to compute the (post-)dominators is described in the [paper](https://www.cs.rice.edu/~keith/EMBED/dom.pdf).

The output will consist of a post-dominator mapping to each basic block, and re-processed traces marked with the certain return block.
Post-dominator mappings are keyed with (function_name, return_block_address), valued with a mapping of (basic_block_address, [address_of_post-dominators])
Trace will be expanded to an array of (instruction_address, function_name, return_block, current_basicblock).
'''


DEBUG = False

def wait(bv):
    # Analyzing
    while bv.analysis_progress.state != AnalysisState.IdleState:
        time.sleep(1)
        print bv.analysis_progress

def wait_analyze(bv, func):
    func.reanalyze()
    wait(bv)

def fix_switch_table(bv, mal_func):
    for bb in mal_func.basic_blocks:
        vpc = bb.start
        for ins in bb:
            addrsize = mal_func.arch.address_size
            tokens, length = ins
            ins_info = mal_func.arch.get_instruction_info(bv.read(vpc, length), vpc)
            # NOTE(hzh): no arch_transition_by_taget_addr, branch_delay slot in x86
            unresolved_branches = [br for br in ins_info.branches \
                    if br.type == BranchType.UnresolvedBranch]
            # start to fix unresolved branches
            if unresolved_branches:
                branches = []
                switch_tab = None
                for token in tokens:
                    token_type = InstructionTextTokenType(token.type)
                    # identify switch table address
                    if token_type == InstructionTextTokenType.PossibleAddressToken:
                        switch_tab = token.value
                        break
                    elif token_type == InstructionTextTokenType.IntegerToken:
                        if token.value >= bv.start and token.value < bv.end:
                            switch_tab = token.value
                            break
                if switch_tab:
                    print "Found Switch Table at {}".format(hex(switch_tab))
                    i = 0
                    # read jump table data
                    while True:
                        data = bv.read(switch_tab + (i * addrsize), addrsize)
                        assert(len(data) == addrsize)
                        if addrsize == 4:
                            ptr = struct.unpack("<I", data)[0]
                        else:
                            ptr = struct.unpack("<Q", data)[0]
                        # make sure the target address is valid
                        if ptr >= bv.start and ptr < bv.end:
                            branches.append((mal_func.arch, ptr))
                        else:
                            break
                        i += 1
                # fix CFG
                mal_func.set_user_indirect_branches(vpc, branches)
            vpc += length

    # re-analyze the function
    wait_analyze(bv, mal_func)

'''
    Return a list of returning blocks, and a map of functions and a list of traces within the function
'''
# TODO(hzh): might have trouble in recursive call - need to verify that later
def get_return_blocks(bv, raw_trace=None, tracefile=None):
    if not raw_trace:
        with open(tracefile, 'rb') as fd:
            trace = json.load(fd)
    else:
        trace = raw_trace

    return_blocks = set()
    image_base = 0 # bv.start
    inst_lookahead = None
    final_traces = {}
    local_trace = {}
    for inst in trace['full_trace']:
        instaddr = inst + image_base
        fun = bv.get_functions_containing(instaddr)
        # this might be unresolved .plt entry
        if not fun:
            for sec in bv.get_sections_at(instaddr):
                if sec.name == '.plt' and instaddr >= sec.start and instaddr < sec.end:
                    bv.add_function(instaddr)
                    bv.update_analysis_and_wait()
                    fun = bv.get_functions_containing(instaddr)
                    break
        # this might be a switch table
        if inst_lookahead and not fun:
            fix_switch_table(bv, bv.get_functions_containing(inst_lookahead)[0])
            fun = bv.get_functions_containing(instaddr)
        # lazy create function
        if not fun:
            print("Add new function at Addr: {}".format(hex(instaddr)))
            bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, instaddr, "sub_{:x}".format(instaddr)))
            bv.add_function(instaddr)
            bv.update_analysis_and_wait()
            fun = bv.get_functions_containing(instaddr)

        assert(fun)
        # NOTE(hzh): BN will get 2 basic blocks given 1 instruction address, we pick one with smaller addr
        #   ```
        #    0808a4c4  f00fb10dd0691408    lock cmpxchg dowrd [syslog_lock], ecx
        #    0808a4c5  0fb10dd0691408      cmpxchg dword [syslog_lock], ecx
        #   ```
        basic_block = None
        for bb in bv.get_basic_blocks_at(instaddr):
            basic_block = bb if not basic_block or bb.start < basic_block.start else basic_block
        # get all the basic blocks of the same start address
        basic_block_all = [basic_block]
        for bb in bv.get_basic_blocks_at(instaddr):
            if bb.start == basic_block.start:
                basic_block_all.append(bb)

        for bb in basic_block_all:
            # the returning/exit block is the block with no outgoing edges
            if not bb.outgoing_edges:
                #print fun[0].name, hex(inst + image_base), hex(basic_block.start), basic_block.outgoing_edges
                return_blocks.add(basic_block)
        inst_lookahead = instaddr

        # check if we are still in the function
        func_matched = False
        for f in fun:
            if f in local_trace:
                func_matched = True
        # stash the local_trace
        if not func_matched and local_trace:
            for prev_fun in local_trace:
                if prev_fun in final_traces:
                    final_traces[prev_fun].append(local_trace[prev_fun][:])
                else:
                    final_traces[prev_fun] = [local_trace[prev_fun][:]]
            local_trace = {}
        # generating local trace per function
        for f in fun:
            if f not in local_trace:
                local_trace[f] = [instaddr]
            else:
                local_trace[f].append(instaddr)

    return_block_map = {}
    for bb in return_blocks:
        if bb.function not in return_block_map:
            return_block_map[bb.function] = [bb]
        else:
            return_block_map[bb.function].append(bb)

    # scan through the final_traces to merge
    for fun in final_traces.keys():
        traces = final_traces.pop(fun)
        final_traces[fun] = []
        merged_trace = traces[0]
        for tr in traces[1:]:
            # check if we have returned fome some inst
            instaddr = merged_trace[-1]
            tokens, length = fun.arch.get_instruction_text(bv.read(instaddr, 16), instaddr)
            if tr[0] == (instaddr + length):
                merged_trace += tr
            else:
                # avoid duplicated traces
                if merged_trace not in final_traces[fun]:
                    final_traces[fun].append(merged_trace[:])
                merged_trace = tr
        # append the last one
        if merged_trace not in final_traces[fun]:
            final_traces[fun].append(merged_trace[:])

    # merge jump-to-another-function
    # NOTE(hzh): basic block at the start of a function don't have incoming_edges, even if there's a branch to it
    for fun in final_traces.keys():
        if fun not in return_block_map:
            # walk through all the functions to see if the next instruction is the start of some func
            target_funcs = set()
            for tr, bb in itertools.product(final_traces[fun], return_blocks):
                tokens, length = fun.arch.get_instruction_text(bv.read(tr[-1], 16), tr[-1])
                if bb.function.start == (tr[-1] + length):
                    target_funcs.add(bb.function)
            if target_funcs:
                return_block_map[fun] = []
                for tf in target_funcs:
                    return_block_map[fun] += return_block_map[tf]
                print "Resolved function:", fun.name, return_block_map[fun]
    # NOTE(hzh): make the last basic block in the trace the return block - in case that might called `exit` directly
    for fun in final_traces.keys():
        if fun not in return_block_map:
            return_block_map[fun] = []
            for tr in final_traces[fun]:
                basic_block = fun.get_basic_block_at(tr[-1])
                if basic_block.start not in [x.start for x in return_block_map[fun]]:
                    return_block_map[fun].append(basic_block)
            print "Truncated function:", fun.name, return_block_map[fun]
    for fun in final_traces.keys():
        if fun not in return_block_map:
            print "Err function:", fun.name, [[hex(addr) for addr in addrs] for addrs in final_traces[fun]]
    return return_block_map, final_traces, [tr + image_base for tr in trace['full_trace']]

# DFS to get nodes in postorder, be sure to call this with `touched_node` set to `set()` to avoid any further trouble
def build_postordering(node, touched_node=set()):
    result = []
    touched_node.add(node)
    for branch in node.incoming_edges:
        bb = branch.source
        if bb in touched_node:
            continue
        result += build_postordering(bb, touched_node)
    result.append(node)
    return result


# this is actually a copy of the [algo](https://www.cs.rice.edu/~keith/EMBED/dom.pdf)
def build_postdominators(exit_node):
    work_nodes = build_postordering(exit_node, set())[::-1]
    dom = {}
    # initialize
    for node in work_nodes:
        dom[node] = set(work_nodes)
    changed = True
    # calculate post-dom
    while changed:
        changed = False
        for node in work_nodes:
            # get immediate predecessors from outgoing_edges
            preds = [branch.target for branch in node.outgoing_edges if branch.target in dom]
            pred_doms = [set(dom[pred]) for pred in preds]
            new_set = set()
            if pred_doms:
                new_set = set.intersection(*pred_doms)
            new_set.add(node)
            if new_set != dom[node]:
                dom[node] = new_set.copy()
                changed = True
    return dom

def output_postdominators(return_block_map, postdom_out):
    for fun in return_block_map:
        for ret_block in return_block_map[fun]:
            key = (fun, ret_block.start)
            if key not in postdom_out:
                postdom = build_postdominators(ret_block)
                out_dom = {}
                for bb in postdom:
                    out_dom[bb.start] = [b.start for b in postdom[bb]]
                postdom_out[key] = out_dom.copy()

def is_call_inst(function, address):
    return function.get_low_level_il_at(address).operation in \
            [LowLevelILOperation.LLIL_CALL, LowLevelILOperation.LLIL_CALL_STACK_ADJUST]

def find_next_callinst(bv, function, address):
    bb = function.get_basic_block_at(address)
    iaddr = address
    while iaddr >= bb.start and iaddr < bb.end:
        if is_call_inst(function, iaddr):
            return iaddr
        iaddr += bv.get_instruction_length(iaddr)
    return None

def reprocess_trace(bv, raw_trace, return_blocks):
    out_trace = []
    scanning_trace = [None]
    trace_index = 0
    prev_func = []
    instr_counter = 0
    cur_function = None
    while trace_index < len(raw_trace):
        instaddr = raw_trace[trace_index]
        functions = bv.get_functions_containing(instaddr)

        # check if we are at the return addr of the prev_func
        if prev_func:
            eos = None
            for i in reversed(range(len(prev_func))):
                if instaddr >= prev_func[i][1].start and instaddr < prev_func[i][1].end:
                    eos = i + 1
                    break
            if eos:
                prev_func = prev_func[:eos]

        # use previous seen function
        if len(set(functions)) > 1:
            func = prev_func[-1][0] if prev_func[-1][0] in functions else cur_function
        else:   # len(set(functions)) == 1
            func = functions[0]
        assert(func != None)
        if func.start == instaddr:
            cur_function = func
        ret_block = func.get_basic_block_at(instaddr)

        # initialize
        if not prev_func:
            prev_func.append([func, ret_block, None])

        # push a guard entry into the trace to indicate a control-flow change
        if prev_func[-1][0] != func and scanning_trace[-1] != None:
            scanning_trace.append(None)

        # check if we're at return block
        # NOTE(hzh): fix to compare BasicBlock with start address, looks like a problem in BN, Version 1.1.1339
        #if ret_block not in return_blocks[func]:
        if ret_block.start not in [bb.start for bb in return_blocks[func]]:
            scanning_trace.append([instaddr, func, None, ret_block.start])
        else:
            # mark the entry to return block in reverse until we reach function start
            for index in reversed(range(len(scanning_trace))):
                if scanning_trace[index] and scanning_trace[index][1] == func and scanning_trace[index][2] == None:
                    scanning_trace[index][2] = ret_block
                if scanning_trace[index] and scanning_trace[index][0] == func.start:
                    break
            scanning_trace.append([instaddr, func, ret_block, ret_block.start])

        # check if inst is a `call`, push a guard entry into the trace, to track recursive call
        ci = find_next_callinst(bv, func, instaddr)
        if ci and prev_func[-1][0] != func:
            if scanning_trace[-1] != None:
                scanning_trace.append(None)
            # push callstack
            prev_func.append([func, ret_block, ci])
        # NOTE: QEMU trace have a different granularity of basicblock than binja,
        #       especially in QEMU basicblock truncates where the last instruction is a `call` but not in binja
        #       there might also be multiple QEMU bbs in one binja bb
        elif ci and prev_func[-1][2] != ci:
            if ci < prev_func[-1][1].end and ci >= prev_func[-1][1].start:
                # update call instr address inside the same basicblock
                prev_func[-1][2] = ci
            else:
                if scanning_trace[-1] != None:
                    scanning_trace.append(None)
                # push callstack
                prev_func.append([func, ret_block, ci])


        if (instr_counter % 10000) == 0:
            print "Re-Processed {COUNT}/{TOTAL}".format(COUNT=instr_counter, TOTAL=len(raw_trace))

        trace_index += 1
        instr_counter += 1

    # verify the return block is in the same function
    for tr in scanning_trace:
        if tr and tr[2] and tr[2].function != tr[1]:
                assert(False)

    if DEBUG:
        for inst in scanning_trace:
            if inst and inst[2]:
                print hex(inst[0]), inst[1].name, inst[2]
            elif inst:
                print hex(inst[0]), inst[1].name, inst[2]
            else:
                print inst
    # walk through the trace again to make sure every inst has a return block tagged
    # e.g.
    #   In this case, the return block of `read` is actually in `__read_nocancel`
    #
    #   08089100 read proc near
    #   08089100                 cmp     large dword ptr gs:0Ch, 0 ; Alternative name is '__libc_read'
    #   08089108                 jnz     short loc_808912F
    #   0808910A __read_nocancel proc near
    #   0808910A                 push    ebx
    #   ...
    #
    prev_bb = None
    for inst in scanning_trace[::-1]:
        if inst and inst[2]:
            prev_bb = inst[2]
        elif inst:
            inst[2] = prev_bb
            print "Fixing {INST}, {FUNC}, {BB}".format(INST=hex(inst[0]), FUNC=inst[1].name, BB=hex(inst[2].start))
    return [[tr[0], tr[1], tr[2].start, tr[3]] for tr in scanning_trace if tr]


def find_immediate_postdominator(postdoms):
    result = {}
    for func, retblock in postdoms:
        if func not in result:
            result[func] = {}
        if retblock not in result[func]:
            result[func][retblock] = {}
        for bb in postdoms[(func, retblock)]:
            pdoms = postdoms[(func, retblock)][bb]
            if len(pdoms) == 1:
                # at the return block itself
                result[func][retblock][bb] = pdoms[0]
                continue
            for pdom in pdoms:
                if set([x for x in pdoms if x != bb]) == set(postdoms[(func, retblock)][pdom]):
                    result[func][retblock][bb] = pdom
                    break
    for func, retblock in postdoms:
        for bb in postdoms[(func, retblock)]:
            if bb not in result[func][retblock]:
                print "MISSING Immediate Postdominator ", func, hex(retblock), hex(bb)

    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-file", "-t", nargs='+')
    parser.add_argument("--output-file", "-o")
    args = parser.parse_args()

    binary = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../build/environment/tftp-hpa-5.2/pkg/sbin/in.tftpd")
    bv = BinaryViewType['ELF'].open(binary)
    bv.store_metadata('ephemeral', {'binaryninja.analysis.max_function_size': 0})

    function_map = {}
    for f in bv.functions:
        assert(f.name not in function_map)
        function_map[f.name] = f

    main = function_map["main"]
    wait_analyze(bv, main)
    bv.update_analysis_and_wait()


    postdom_out = {}
    json_out = {}

    for trace in args.trace_file:
        return_blocks, grouped_traces, raw_trace = get_return_blocks(bv, trace)

        output_postdominators(return_blocks, postdom_out)

        trace_out = reprocess_trace(bv, raw_trace, return_blocks)
        json_out[os.path.abspath(trace)] = trace_out

    immediate_postdoms = find_immediate_postdominator(postdom_out)

    for trace in args.trace_file:
        newtrace_out = {'trace': []}
        trace_out = json_out[os.path.abspath(trace)]
        for tr in trace_out:
            # check if the current instruction is at the beginning of basicblock
            if tr[0] != tr[3]:
                newtrace_out['trace'].append([tr[0], -1])
            else:
                newtrace_out['trace'].append([tr[0], immediate_postdoms[tr[1]][tr[2]][tr[3]]])
        newtrace = os.path.join(os.path.dirname(trace), "newtrace.json")
        with open(os.path.abspath(newtrace), 'w') as fd:
            json.dump(newtrace_out, fd)

    json_out['postdom'] = immediate_postdoms
    #for func, retblock in postdom_out:
    #    if func not in json_out['postdom']:
    #        json_out['postdom'][func] = {}
    #    json_out['postdom'][func][retblock] = postdom_out[(func, retblock)]

    if args.output_file:
        with open(args.output_file, 'w') as fd:
            json.dump(json_out, fd)


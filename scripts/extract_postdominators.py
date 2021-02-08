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
def get_return_blocks(return_block_map, bv, raw_trace=None, tracefile=None, merge_jump=False, infer_return_block=True, vm=None, perf=False):
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
        if vm:
            instaddr = vm.translate(instaddr) - vm.cpu._physical_mem_base
        if perf:
            print(" >[", hex(instaddr), "] ")
            timecheck = time.clock()
        fun = bv.get_functions_containing(instaddr)
        ## this might be unresolved .plt entry
        #if not fun:
        #    for sec in bv.get_sections_at(instaddr):
        #        if sec.name == '.plt' and instaddr >= sec.start and instaddr < sec.end:
        #            bv.add_function(instaddr)
        #            bv.update_analysis_and_wait()
        #            fun = bv.get_functions_containing(instaddr)
        #            break
        # this might be a switch table
        #if inst_lookahead and not fun:
        #    fix_switch_table(bv, bv.get_functions_containing(inst_lookahead)[0])
        #    fun = bv.get_functions_containing(instaddr)
        # lazy create function
        if not fun:
            print("Add new function at Addr: {}".format(hex(instaddr)))
            bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, instaddr, "sub_{:x}".format(instaddr)))
            bv.add_function(instaddr)
            bv.update_analysis_and_wait()
            fun = bv.get_functions_containing(instaddr)

        assert(fun)

        if perf:
            print(" >Found Function ", time.clock()-timecheck)
            timecheck = time.clock()

        # append all "end" nodes of current function
        for f in fun:
            for bb in f.basic_blocks:
                if not bb.outgoing_edges or check_return(bv, f, bb.start):
                    return_blocks.add(bb)

        if perf:
            print(" >> Init Return block Found ", time.clock()-timecheck)
            timecheck = time.clock()

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

        if perf:
            print(" >> Fixing Binja BB ", time.clock()-timecheck)
            timecheck = time.clock()

        for bb in basic_block_all:
            # the returning/exit block is the block with no outgoing edges
            if not bb.outgoing_edges:
                #print fun[0].name, hex(inst + image_base), hex(basic_block.start), basic_block.outgoing_edges
                return_blocks.add(bb)
        inst_lookahead = instaddr

        if perf:
            print(" >Found Return Block ", time.clock()-timecheck)
            timecheck = time.clock()

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

        if perf:
            print(" >Done Fixingup ", time.clock()-timecheck)
            timecheck = time.clock()

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
            #tokens, length = fun.arch.get_instruction_text(bv.read(instaddr, 16), instaddr)
            #if tr[0] == (instaddr + length):
            #    merged_trace += tr
            bb1 = fun.get_basic_block_at(instaddr)
            bb2 = fun.get_basic_block_at(tr[0])
            if bb1 and bb2 and bb1.start == bb2.start:
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
    if merge_jump:
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
    # This might also involve some of the inline functions - IDed as function but inlined in asm
    for fun in final_traces.keys():
        if fun not in return_block_map:
            if infer_return_block:
                return_block_map[fun] = []
                for tr in final_traces[fun]:
                    basic_block = fun.get_basic_block_at(tr[-1])
                    if basic_block.start not in [x.start for x in return_block_map[fun]]:
                        return_block_map[fun].append(basic_block)
                print "Truncated function:", fun.name, return_block_map[fun]
    for fun in final_traces.keys():
        if fun not in return_block_map:
            print "Err function:", fun.name, [[hex(addr) for addr in addrs] for addrs in final_traces[fun]]
            return_block_map[fun] = []
            addrs = sum(final_traces[fun], [])
            addrs.sort()
            for a in addrs:
                if check_return(bv, fun, a):
                    basic_block = fun.get_basic_block_at(a)
                    return_block_map[fun].append(basic_block)
    if vm:
        return final_traces, \
                {'va': [tr + image_base for tr in trace['full_trace']], \
                 'pa': [vm.translate(tr+image_base)-vm.cpu._physical_mem_base for tr in trace['full_trace']]}
    else:
        return final_traces, {'va': [tr + image_base for tr in trace['full_trace']]}

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

            postdom = build_postdominators(ret_block)
            out_dom = {}
            for bb in postdom:
                out_dom[bb.start] = [b.start for b in postdom[bb]]
            if key not in postdom_out:
                postdom_out[key] = out_dom.copy()
            else:
                postdom_out[key].update(out_dom)

def is_call_inst(function, address):
    return function.is_call_instruction(address)

def is_return_inst(function, address):
    for idx in function.get_low_level_il_exits_at(address):
        llil = function.low_level_il[idx]
        if (llil.operation == LowLevelILOperation.LLIL_JUMP_TO or \
                llil.operation == LowLevelILOperation.LLIL_JUMP):
            return True
    return False

def find_next_callinst(bv, function, address):
    bb = function.get_basic_block_at(address)
    if not bb:
        return None
    iaddr = address
    while iaddr >= bb.start and iaddr < bb.end:
        if is_call_inst(function, iaddr):
            return iaddr
        iaddr += bv.get_instruction_length(iaddr)
    return None

def check_return(bv, function, address):
    bb = function.get_basic_block_at(address)
    iaddr = address
    if not bb:
        return None
    while iaddr >= bb.start and iaddr < bb.end:
        if is_return_inst(function, iaddr):
            return iaddr
        iaddr += bv.get_instruction_length(iaddr)
    return None

def reprocess_trace(bv, raw_trace, return_blocks, postdom_out):
    translated = 'pa' in raw_trace
    out_trace = []
    scanning_trace = [None]
    trace_index = 0
    prev_func = []
    fake_trace_cb = []
    shadow_instr = None
    shadow_next_call = None
    instr_counter = 0
    cur_function = None
    intended_return_block = {}
    while trace_index < len(raw_trace['va']):
        next_instr = None
        if translated:
            instaddr = raw_trace['pa'][trace_index]
            if trace_index + 1 < len(raw_trace['va']):
                next_instr = raw_trace['pa'][trace_index+1]
        else:
            instaddr = raw_trace['va'][trace_index]
            if trace_index + 1 < len(raw_trace['va']):
                next_instr = raw_trace['va'][trace_index+1]

        if shadow_instr:
            fp = bv.get_functions_containing(shadow_instr)
            fn = bv.get_functions_containing(next_instr) if next_instr else None
            samefunc = fp and fn and True in [f.start in [x.start for x in fn] for f in fp]
            # Check function returns
            if next_instr != shadow_instr and samefunc:
                instaddr = shadow_instr
            # Check call instruction
            elif shadow_next_call and bv.get_disassembly(shadow_next_call).split()[-1] == hex(next_instr):
                instaddr = shadow_instr
            else:
                shadow_instr = None
                shadow_next_call = None
                trace_index += 1
                instr_counter += 1
                continue
        #shadow_instr = None

        functions = bv.get_functions_containing(instaddr)
        callstack_size = len(prev_func)
        if DEBUG:
            print hex(instaddr), " : ", functions
            print prev_func

        # check if we are at the return addr of the prev_func
        if prev_func:
            eos = None
            for i in reversed(range(len(prev_func))):
                if instaddr >= prev_func[i][1].start and instaddr < prev_func[i][1].end:
                    eos = i
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
        # ughh, just to make sure current trace instr has a basicblock in func
        func_checklist = [f for f in functions]
        while func_checklist and not ret_block:
            func = func_checklist.pop()
            ret_block = func.get_basic_block_at(instaddr)
        if DEBUG:
            print return_blocks[func]
            print ret_block

        # initialize
        if not prev_func:
            prev_func.append([func, ret_block, None, 0])

        if DEBUG:
            print "fake_trace : ", fake_trace_cb
        # check the fixing ups queue
        if fake_trace_cb:
            if DEBUG:
                print fake_trace_cb[0][0], func, callstack_size, len(prev_func)
            # return out of the function
            if fake_trace_cb[0][0] != func and callstack_size >= len(prev_func):
                _, rb = fake_trace_cb.pop(0)
                scanning_trace.append([rb.start, func, rb, rb.start, -1])   # probably fine with vaddr=-1, it's return block anyway. won't be the diverge point

        # push a guard entry into the trace to indicate a control-flow change
        if prev_func[-1][0] != func and scanning_trace[-1] != None:
            scanning_trace.append(None)

        # BN tends to have wanky behavior that truncates a basicblock in a function if another new function is created
        # that have a jump in the middle of that basicblock. The rest part of the basicblock will no longer appear in
        # the original function (also references etc). And that would gives us an entirely new function here which has
        # note previously registered in the `return_blocks`. This is probably caused by inline macros that certain code
        # block have multiple entries.
        if func not in return_blocks:
            temp_ret_blocks = {}
            temp_postdom_out = {}
            get_return_blocks(temp_ret_blocks, bv, raw_trace={'full_trace': [instaddr]})
            output_postdominators(temp_ret_blocks, temp_postdom_out)
            return_blocks[func] = temp_ret_blocks[func]
            for key in temp_postdom_out:
                if key not in postdom_out:
                    postdom_out[key] = temp_postdom_out[key].copy()
                else:   # shouldn't reach this, but anyway
                    postdom_out[key].update(temp_postdom_out[key])

        # check if we're at return block
        # NOTE(hzh): fix to compare BasicBlock with start address, looks like a problem in BN, Version 1.1.1339
        #if ret_block not in return_blocks[func]:
        seen_callframe = False
        if ret_block.start in [bb.start for bb in return_blocks[func]]:
            # mark the entry to return block in reverse until we reach function start
            for index in reversed(range(len(scanning_trace))):
                if not seen_callframe and index == prev_func[-1][3] and prev_func[-1][3] != 0:
                    seen_callframe = True
                if scanning_trace[index] and scanning_trace[index][1] == func and scanning_trace[index][2] == None:
                    scanning_trace[index][2] = ret_block
                if scanning_trace[index] and scanning_trace[index][0] == func.start and seen_callframe:
                    break
            scanning_trace.append([instaddr, func, ret_block, ret_block.start, raw_trace['va'][trace_index]])
            # pop fake trace cb if seen a real return block
            if fake_trace_cb and fake_trace_cb[0][1].start == instaddr:
                fake_trace_cb.pop(0)
        # this is to fix TCG (basicblock) tracing, TCG bb just goes all the way down as long as there's no
        # PC redirection. However, in normal sense, bb shoudl be splited if there's a jump to the middle of that bb.
        elif ret_block.end in [bb.start for bb in return_blocks[func]]:
            # get new return block
            rb = func.get_basic_block_at(ret_block.end)
            if not rb:
                rb = [bb for bb in return_blocks[func] if bb.start == ret_block.end][0]
            assert(rb)
            # mark the entry to return block in reverse until we reach function start
            for index in reversed(range(len(scanning_trace))):
                if not seen_callframe and index == prev_func[-1][3] and prev_func[-1][3] != 0:
                    seen_callframe = True
                if scanning_trace[index] and scanning_trace[index][1] == func and scanning_trace[index][2] == None:
                    scanning_trace[index][2] = rb
                if scanning_trace[index] and scanning_trace[index][0] == func.start and seen_callframe:
                    break
            scanning_trace.append([instaddr, func, rb, ret_block.start, raw_trace['va'][trace_index]])
            # if we seen it in the middle of a basicblock, we might already registered it before, remove the old registary
            for i in reversed(range(len(fake_trace_cb))):
                if fake_trace_cb[i][0] == func and fake_trace_cb[i][1].start == rb.start:
                    fake_trace_cb.pop(i)
                    break
            # register callback when we once again return to this function or ret out of this function
            fake_trace_cb.append([func, rb])
            if DEBUG:
                print "add fake trace : ", hex(instaddr), " : ", func, rb
        else:
            scanning_trace.append([instaddr, func, None, ret_block.start, raw_trace['va'][trace_index]])
            intended_return_block[len(scanning_trace)-1] = return_blocks[func]

            # yet again the TCG bb discrepancy, however, only considering the adjecent next (normal) basicblock here
            #if (not ret_block.outgoing_edges and not check_return(bv, func, instaddr)) or \
            #   (len(ret_block.outgoing_edges) == 1 and ret_block.outgoing_edges[0].target.start == ret_block.end):
            #    # make sure no function calls afterwards (even if there is a call inst, we should be expecting to see
            #    # another TCG bb right after the call)
            #    if not find_next_callinst(bv, func, instaddr) and not bv.get_disassembly(instaddr).startswith("b "):
            #        #print "potential shadow instr ", hex(instaddr), " -> ", hex(ret_block.end)
            #        #if not shadow_instr:
            #        if DEBUG:
            #            print "shadow instr ", hex(instaddr), " -> ", hex(ret_block.end)
            #        shadow_instr = ret_block.end
            if next_instr and next_instr not in [x.target.start for x in ret_block.outgoing_edges]:
                # make sure there's no call or branch in the same basicblock, we probably don't need to worry about return here
                if not find_next_callinst(bv, func, instaddr) and not bv.get_disassembly(instaddr).startswith("b ") \
                        and (next_instr < ret_block.start or next_instr >= ret_block.end):   # also next instr not in the same BB
                    shadow_instr = ret_block.end
                    shadow_next_call = find_next_callinst(bv, func, ret_block.end)

        # check if inst is a `call`, push a guard entry into the trace, to track recursive call
        ci = find_next_callinst(bv, func, instaddr)
        if ci and prev_func[-1][0] != func:
            if scanning_trace[-1] != None:
                scanning_trace.append(None)
            # push callstack
            prev_func.append([func, ret_block, ci, len(scanning_trace)-1])
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
                prev_func.append([func, ret_block, ci, len(scanning_trace)-1])


        if (instr_counter % 10000) == 0:
            print "Re-Processed {COUNT}/{TOTAL}".format(COUNT=instr_counter, TOTAL=len(raw_trace['va']))

        if shadow_instr and shadow_instr == instaddr:
            shadow_instr = None
            shadow_next_call = None
        if not shadow_instr:
            trace_index += 1
            instr_counter += 1

    # verify the return block is in the same function
    #for tr in scanning_trace:
    #    if tr and tr[2] and tr[2].function != tr[1]:
    #        assert(False)

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
    prev_frame = []
    for tridx in reversed(range(len(scanning_trace))):
        inst = scanning_trace[tridx]
        if inst and not prev_frame:
            # Auto append last seen basicblock when stack is empty
            prev_frame.append([inst[1], inst[2].start if inst[2] else inst[0]])
            if not inst[2]:
                scanning_trace[tridx][2] = prev_frame[-1][1]
            else:
                scanning_trace[tridx][2] = scanning_trace[tridx][2].start
        elif inst and prev_frame:
            if prev_frame[-1][0] == inst[1]:    # still in the same function?
                if not inst[2]:
                    scanning_trace[tridx][2] = prev_frame[-1][1]
                else:
                    scanning_trace[tridx][2] = scanning_trace[tridx][2].start
            else:   # see another function?
                prev_frame.append([inst[1], inst[2].start if inst[2] else inst[0]])
                scanning_trace[tridx][2] = prev_frame[-1][1]

            # Function Call start, Pop frame stack
            if prev_frame[-1][0].start == inst[0]:
                prev_frame = prev_frame[:-1]
            print "Fixing {INST}, {FUNC}, {BB}".format(INST=hex(inst[0]), FUNC=inst[1].name, BB=hex(inst[2]))
        assert(not inst or inst[2])
    return [[tr[0], tr[1], tr[2], tr[3], tr[4]] for tr in scanning_trace if tr]


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


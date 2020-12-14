import os
import sys
import json
import time
import itertools
from instrument import vm

from extract_postdominators import *

PERF = False
DEBUG = False

# idea comes from [diffslicing paper](http://bitblaze.cs.berkeley.edu/papers/diffslicing_oakland11.pdf)
class DiffSliceAnalyzer(object):
    def diff(self, outdir, trace_wanted, trace_toremove, logEI = False):
        diverge_ei = []
        trace_ids = [trace_wanted['id'], trace_toremove['id']]
        traces = [trace_wanted['trace'], trace_toremove['trace']]
        vpc = [0 for tr in traces]
        ei = [[] for tr in traces]
        aligned = []
        def endoftrace(pc, tr):
            for x, y in zip(pc, [len(t) for t in tr]):
                if x == y:
                    return True
            return False
        def ipdom(tr, idx):
            return tr[idx][1] if tr[idx][1] != -1 else None
        def iaddr(tr, idx):
            return tr[idx][0]
        def vaddr(tr, idx):
            return tr[idx][0]
        def updateei(ei, pc, ipd):
            while ei and ei[-1][0] == pc:
                ei.pop()
            if ipd and pc != ipd:
                ei.append((ipd, pc))
        def inbasicblock(tr, pc):
            return not ipdom(tr[0], pc[0]) and not ipdom(tr[1], pc[1])
        def proceed(tr, pc, es, i):
            pc[i] += 1
            if not endoftrace(pc, tr):
                updateei(es[i], iaddr(tr[i], pc[i]), ipdom(tr[i], pc[i]))
        updateei(ei[0], iaddr(traces[0], vpc[0]), ipdom(traces[0], vpc[0]))
        updateei(ei[1], iaddr(traces[1], vpc[1]), ipdom(traces[1], vpc[1]))
        while not endoftrace(vpc, traces):
            # walk aligned trace
            while ei[0] == ei[1] and not endoftrace(vpc, traces):
                if iaddr(traces[0], vpc[0]) == iaddr(traces[1], vpc[1]):
                    aligned.append([vpc[0], vpc[1]])
                proceed(traces, vpc, ei, 0)
                proceed(traces, vpc, ei, 1)
                # record the full basicblock if the insts are aligned. since we already know that EIs are equal, as long as the insts match, the traces are aligned.
                while not endoftrace(vpc, traces) and inbasicblock(traces, vpc) and iaddr(traces[0], vpc[0]) == iaddr(traces[1], vpc[1]):
                    aligned.append([vpc[0], vpc[1]])
                    proceed(traces, vpc, ei, 0)
                    proceed(traces, vpc, ei, 1)
            if DEBUG:
                print "EI Miss match"
                print [(hex(x[0]),hex(x[1])) for x in ei[0]], [(hex(x[0]),hex(x[1])) for x in ei[1]]
                if vpc[0] < len(traces[0]):
                    print hex(iaddr(traces[0], vpc[0])),
                else:
                    print "None",
                if vpc[1] < len(traces[1]):
                    print hex(iaddr(traces[1], vpc[1]))
                else:
                    print "None"
            # log EI stack
            if logEI and not endoftrace(vpc, traces):
                ei_index = min(len(ei[0]), len(ei[1]))
                while ei[0][:ei_index] != ei[1][:ei_index]:
                    ei_index -= 1
                diverge_ei.append(ei[0][:ei_index])
            # NOTE(hzh): Sometimes 2 traces exits at different branch, ends up different immediate-postdominators. compare the EI without the last one ipdom
            if ei[0] != ei[1] and ei[0][:-1] == ei[1][:-1]:
                while not endoftrace(vpc, traces) and iaddr(traces[0], vpc[0]) == iaddr(traces[1], vpc[1]):
                    aligned.append([vpc[0], vpc[1]])
                    proceed(traces, vpc, ei, 0)
                    proceed(traces, vpc, ei, 1)
            # walk disaligned trace
            while ei[0] != ei[1] and not endoftrace(vpc, traces):
                # NOTE(hzh): fix the corner case where traces go to complete different branches - we have different EI but the same length
                if len(ei[0]) == len(ei[1]):
                    proceed(traces, vpc, ei, 0)
                    proceed(traces, vpc, ei, 1)
                    continue
                while len(ei[0]) != len(ei[1]) and not endoftrace(vpc, traces):
                    disalign = 0 if len(ei[0]) > len(ei[1]) else 1
                    while len(ei[disalign]) > len(ei[1 - disalign]) and not endoftrace(vpc, traces):
                        proceed(traces, vpc, ei, disalign)
            if DEBUG:
                print "EI Realign"
                print [(hex(x[0]),hex(x[1])) for x in ei[0]], [(hex(x[0]),hex(x[1])) for x in ei[1]]
                if vpc[0] < len(traces[0]):
                    print hex(iaddr(traces[0], vpc[0])),
                else:
                    print "None",
                if vpc[1] < len(traces[1]):
                    print hex(iaddr(traces[1], vpc[1]))
                else:
                    print "None"

        # output divergence point
        branch_targets = set()
        diverge = []
        prev_tr0 = 0
        prev_tr1 = 0
        for tr0, tr1 in aligned:
            if tr0 == 0 or tr0 == prev_tr0 + 1:
                pass
            else:
                assert(iaddr(traces[0], prev_tr0) == iaddr(traces[1], prev_tr1))
                diverge.append((iaddr(traces[0], prev_tr0), vaddr(traces[0], prev_tr0)))
                branch_targets.add((iaddr(traces[1], prev_tr1), iaddr(traces[0], tr0), iaddr(traces[1], prev_tr1 + 1), \
                        vaddr(traces[0], tr0), vaddr(traces[1], prev_tr1 + 1)))
                prev_tr0 = tr0
                prev_tr1 = tr1
                continue
            if tr1 == 0 or tr1 == prev_tr1 + 1:
                prev_tr1 = tr1
                prev_tr0 = tr0
            else:
                assert(iaddr(traces[0], prev_tr0) == iaddr(traces[1], prev_tr1))
                diverge.append((iaddr(traces[0], prev_tr0), vaddr(traces[0], prev_tr0)))
                branch_targets.add((iaddr(traces[1], prev_tr1), iaddr(traces[0], tr0), iaddr(traces[1], prev_tr1 + 1), \
                        vaddr(traces[0], tr0), vaddr(traces[1], prev_tr1 + 1)))
                prev_tr0 = tr0
                prev_tr1 = tr1
        assert(iaddr(traces[0], prev_tr0) == iaddr(traces[1], prev_tr1))
        if not endoftrace([prev_tr0 + 1, prev_tr1 + 1], traces):
            diverge.append((iaddr(traces[0], prev_tr0), vaddr(traces[0], prev_tr0)))
            branch_targets.add((iaddr(traces[1], prev_tr1), iaddr(traces[0], prev_tr0 + 1), iaddr(traces[1], prev_tr1 + 1), \
                    vaddr(traces[0], tr0), vaddr(traces[1], prev_tr1 + 1)))

        # output the aligned pair of traces
        if outdir:
            with open(os.path.join(outdir, "aligned_{:d}_{:d}.json".format(*trace_ids)), 'w') as fd:
                json.dump({'aligned': aligned, 'diverge': diverge}, fd)
        return (diverge, aligned, branch_targets, diverge_ei)

    def analyze(self):
        # load BN output
        tracedb = {'wanted': [], 'toremove': []}
        count = 0
        while os.path.isfile(self.traceFile(count, "newtrace.json")):
            with open(self.traceFile(count, "newtrace.json")) as fd, \
                    open(self.traceFile(count, "trace.json")) as oldfd:
                data = json.load(fd)
                group = json.load(oldfd)['group']
                tracedb[group].append({'id': count, 'trace': data['trace']})
            count += 1

        # Fail safe if the trace is empty
        if (not tracedb['wanted']) or (not tracedb['toremove']):
            print "Cannot perform Diff-Analysis: Traces Incomplete"
            return

        branch_targets = set()
        diverge_points = set()
        # start trace alignment
        for trace_wanted, trace_toremove in itertools.product(tracedb['wanted'], tracedb['toremove']):
            diverge, aligned, targets = self.diff(trace_wanted, trace_toremove)
            print [hex(x) for x in diverge]
            diverge_points.update(diverge)
            branch_targets.update(targets)

        # the idea is to get all the divergence points in the `wanted`-`toremove` pairs, and
        # then remove the ones appeared in the `wanted`-`wanted` pairs, so that we could exclude
        # the divergence points inside each `wanted` traces.
        for tr1, tr2 in itertools.combinations(tracedb['wanted'], 2):
            diverge, aligned, _ = self.diff(tr1, tr2)
            print [hex(x) for x in diverge]
            diverge_points.difference_update(diverge)

        print diverge_points
        patch_points = set([pt[1] for pt in branch_targets if pt[0] in diverge_points])
        print patch_points
        with open(self.outputFile("patch.json"), 'w') as fd:
            json.dump({'locations': [pt for pt in patch_points]}, fd)

    def rawmem_bn_init(self, reg, mem):
        bv = BinaryViewType['Raw'].open(mem)
        bv.store_metadata('ephemeral', {'binaryninja.analysis.max_function_size': 0})
        bv.platform = Architecture['armv7'].standalone_platform
        self.mm = vm.VM(reg, mem)

        #binaryninja.log.log_to_file(0, "log")
        #binaryninja.log.redirect_output_to_log()

        ev = [0xffff0000+i*4 for i in range(8)]
        for va in ev:
            pa = self.mm.translate(va)
            bv.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, pa, "sub_{:x}".format(pa)))
            bv.add_function(pa)
            #bv.create_user_function(pa)
        bv.update_analysis_and_wait()
        return bv

    def bn_init(self, binfile):
        bv = BinaryViewType['ELF'].open(binfile)
        bv.store_metadata('ephemeral', {'binaryninja.analysis.max_function_size': 0})
        self.mm = None
        function_map = {}
        for f in bv.functions:
            assert(f.name not in function_map)
            function_map[f.name] = f

        # build CFG of known exception handler functions
        for f in ["__irq_svc", "__irq_usr", "__irq_invalid", \
                "__dabt_svc", "__dabt_usr", "__dabt_invalid", \
                "__fiq_svc", "__fiq_usr", "__fiq_abt", \
                ]:
            if f in function_map.keys():
                wait_analyze(bv, function_map[f])
        bv.update_analysis_and_wait()
        return bv

    def bn_analyze(self, bv, raw_traces, outdir):
        postdom_out = {}
        final_traces = {}
        trace_out = {}
        new_trace = []

        # Check done list && skip already pre-processed traces
        donelog = os.path.join(outdir, "preprocessed.log")
        pre_trace = {'traces': []}
        if os.path.exists(donelog):
            with open(donelog, 'r') as fd:
                pre_trace = json.load(fd)
        new_traces = [tr for tr in raw_traces if os.path.abspath(tr['dir']) not in pre_trace['traces']]

        # pre load traces
        for tr in pre_trace['traces']:
            with open("{}.pre".format(tr), 'r') as fd:
                final_traces[tr] = json.load(fd)['trace']

        # pre processing new traces
        return_blocks = {}
        translated_trace = {}
        for trace in new_traces:
            print("Processing : " + trace['dir'])
            if PERF:
                tstart = time.clock()
            grouped_traces, raw_trace = get_return_blocks(return_blocks, bv, raw_trace=trace, vm=self.mm, perf=PERF)
            if PERF:
                print("get_return_blocks done: {}".format(time.clock()-tstart))
                tstart = time.clock()
            output_postdominators(return_blocks, postdom_out)
            if PERF:
                print("output_postdominators done: {}".format(time.clock()-tstart))
            translated_trace[trace['dir']] = raw_trace
        for trace in new_traces:
            print("Re-Processing trace : " + trace['dir'])
            if PERF:
                tstart = time.clock()
            trace_out[os.path.abspath(trace['dir'])] = reprocess_trace(bv, translated_trace[trace['dir']], return_blocks, postdom_out)
            if PERF:
                print("reprocess_trace done: {}".format(time.clock()-tstart))

        immediate_postdoms = find_immediate_postdominator(postdom_out)
        for log,trace in trace_out.iteritems():
            final_traces[log] = []
            for tr in trace:
                # make sure any trace inside of a basicblock is marked -1
                if tr[0] != tr[3]:
                    final_traces[log].append([tr[0], -1, tr[4]])
                    continue
                if tr[2] in immediate_postdoms[tr[1]] and tr[3] in immediate_postdoms[tr[1]][tr[2]]:
                    final_traces[log].append([tr[0], immediate_postdoms[tr[1]][tr[2]][tr[3]], tr[4]])
                else:
                    # for incomplete traces, the last few blocks might ended up wrong post-doms
                    print "failed: ", hex(tr[0])
                    final_traces[log].append([tr[0], -1, tr[4]])
            # log new traces
            if log not in pre_trace['traces']:
                pre_trace['traces'].append(log)
                with open("{}.pre".format(log), 'w') as fd:
                    json.dump({'trace': final_traces[log]}, fd)
        # save log
        with open(donelog, 'w') as fd:
            json.dump(pre_trace, fd)

        # load pre-processed traces

        if DEBUG:
            count=0
            for l in final_traces:
                with open("/tmp/d{:d}.log".format(count), 'w') as fd:
                    fd.write(l)
                    for t in final_traces[l]:
                        fd.write(hex(t[0]) + " : " + hex(t[1]) + "\n")
                count += 1
        # diff
        for tr_x,tr_y in itertools.combinations(final_traces, 2):
            diverge_points = set()
            branch_targets = set()

            idx = int(tr_x.split('_')[-1].split('.')[0])
            idy = int(tr_y.split('_')[-1].split('.')[0])
            diverge, aligned, targets, _ = self.diff(
                    outdir,
                    {'trace': final_traces[tr_x], 'id': idx},
                    {'trace': final_traces[tr_y], 'id': idy})
            print [[hex(x) for x in xl] for xl in diverge]
            diverge_points.difference_update(diverge)
            branch_targets.update(targets)

            #patch_points = set([pt[1] for pt in branch_targets if pt[0] in diverge_points])
            #with open(os.path.join(outdir, "patch.json"), 'w') as fd:
            #    json.dump({'locations': [pt for pt in patch_points]}, fd)
            with open(os.path.join(outdir, "diverge_{:d}_{:d}.json".format(idx, idy)), 'w') as fd:
                jout = {'diverge': [pt for pt in diverge], 'target': {}}
                for xl in branch_targets:
                    if xl[0] not in jout['target']:
                        jout['target'][xl[0]] = []
                    jout['target'][xl[0]] = [e for e in set(list(xl[1:]) + jout['target'][xl[0]])]
                json.dump(jout, fd)
                print [[hex(x) for x in xl] for xl in branch_targets]


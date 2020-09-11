import os
import sys
import json
import itertools

from extract_postdominators import *

# idea comes from [diffslicing paper](http://bitblaze.cs.berkeley.edu/papers/diffslicing_oakland11.pdf)
class DiffSliceAnalyzer(object):
    def diff(self, outdir, trace_wanted, trace_toremove):
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
        def updateei(ei, pc, ipd):
            while ei and ei[-1] == pc:
                ei.pop()
            if ipd and pc != ipd:
                ei.append(ipd)
        def inbasicblock(tr, pc):
            return not ipdom(tr[0], pc[0]) and not ipdom(tr[1], pc[1])
        def proceed(tr, pc, es, i):
            pc[i] += 1
            if not endoftrace(pc, tr):
                updateei(es[i], iaddr(tr[i], pc[i]), ipdom(tr[i], pc[i]))
        updateei(ei[0], iaddr(traces[0], vpc[0]), ipdom(traces[0], vpc[0]))
        updateei(ei[1], iaddr(traces[1], vpc[1]), ipdom(traces[1], vpc[1]))
        while not endoftrace(vpc, traces):
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
            # NOTE(hzh): Sometimes 2 traces exits at different branch, ends up different immediate-postdominators. compare the EI without the last one ipdom
            if ei[0] != ei[1] and ei[0][:-1] == ei[1][:-1]:
                while not endoftrace(vpc, traces) and iaddr(traces[0], vpc[0]) == iaddr(traces[1], vpc[1]):
                    aligned.append([vpc[0], vpc[1]])
                    proceed(traces, vpc, ei, 0)
                    proceed(traces, vpc, ei, 1)
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
                diverge.append(iaddr(traces[0], prev_tr0))
                branch_targets.add((iaddr(traces[1], prev_tr1), iaddr(traces[1], prev_tr1 + 1)))
                prev_tr0 = tr0
                prev_tr1 = tr1
                continue
            if tr1 == 0 or tr1 == prev_tr1 + 1:
                prev_tr1 = tr1
                prev_tr0 = tr0
            else:
                assert(iaddr(traces[0], prev_tr0) == iaddr(traces[1], prev_tr1))
                diverge.append(iaddr(traces[0], prev_tr0))
                branch_targets.add((iaddr(traces[1], prev_tr1), iaddr(traces[1], prev_tr1 + 1)))
                prev_tr0 = tr0
                prev_tr1 = tr1
        assert(iaddr(traces[0], prev_tr0) == iaddr(traces[1], prev_tr1))
        if not endoftrace([prev_tr0 + 1, prev_tr1 + 1], traces):
            diverge.append(iaddr(traces[0], prev_tr0))
            branch_targets.add((iaddr(traces[1], prev_tr1), iaddr(traces[1], prev_tr1 + 1)))

        # output the aligned pair of traces
        with open(os.path.join(outdir, "aligned_{:d}_{:d}.json".format(*trace_ids)), 'w') as fd:
            json.dump({'aligned': aligned, 'diverge': diverge}, fd)
        return (diverge, aligned, branch_targets)

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

    def bn_init(self, binfile):
        bv = BinaryViewType['ELF'].open(binfile)
        bv.store_metadata('ephemeral', {'binaryninja.analysis.max_function_size': 0})
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

    def bn_analyze(self, bv, raw_traces, binfile, outdir):
        postdom_out = {}
        trace_out = {}

        return_blocks = {}
        for trace in raw_traces:
            grouped_traces, raw_trace = get_return_blocks(return_blocks, bv, raw_trace=trace)
            output_postdominators(return_blocks, postdom_out)
        for trace in raw_traces:
            trace_out[os.path.abspath(trace['dir'])] = reprocess_trace(bv, trace['full_trace'], return_blocks)

        immediate_postdoms = find_immediate_postdominator(postdom_out)
        final_traces = {}
        for log,trace in trace_out.iteritems():
            final_traces[log] = []
            for tr in trace:
                if tr[2] in immediate_postdoms[tr[1]] and tr[3] in immediate_postdoms[tr[1]][tr[2]]:
                    final_traces[log].append([tr[0], immediate_postdoms[tr[1]][tr[2]][tr[3]]])
                else:
                    # for incomplete traces, the last few blocks might ended up wrong post-doms
                    print "failed: ", hex(tr[0])
                    final_traces[log].append([tr[0], -1])
        # diff
        diverge_points = set()
        branch_targets = set()
        for tr_x,tr_y in itertools.combinations(final_traces, 2):
            idx = int(tr_x.split('_')[-1].split('.')[0])
            idy = int(tr_y.split('_')[-1].split('.')[0])
            diverge, aligned, targets = self.diff(
                    outdir,
                    {'trace': final_traces[tr_x], 'id': idx},
                    {'trace': final_traces[tr_y], 'id': idy})
            print [hex(x) for x in diverge]
            diverge_points.difference_update(diverge)
            branch_targets.update(targets)
        patch_points = set([pt[1] for pt in branch_targets if pt[0] in diverge_points])
        #with open(os.path.join(outdir, "patch.json"), 'w') as fd:
        #    json.dump({'locations': [pt for pt in patch_points]}, fd)
        with open(os.path.join(outdir, "diverge_{:d}_{:d}.json".format(idx, idy)), 'w') as fd:
            json.dump({'diverge': [pt for pt in diverge]}, fd)


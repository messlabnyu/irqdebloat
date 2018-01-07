#!/usr/bin/env python

import argparse
import bisect

peripheral_list = {}
peripheral_list['raspi2'] = [
	(0x000000003f007000, 0x000000003f007fff, 'bcm2835-dma'),
	(0x000000003f00b200, 0x000000003f00b3ff, 'bcm2835-ic'),
	(0x000000003f00b800, 0x000000003f00bbff, 'bcm2835-mbox'),
	(0x000000003f104000, 0x000000003f10400f, 'bcm2835-rng'),
	(0x000000003f200000, 0x000000003f200fff, 'bcm2835_gpio'),
	(0x000000003f201000, 0x000000003f201fff, 'pl011'),
	(0x000000003f202000, 0x000000003f202fff, 'bcm2835-sdhost'),
	(0x000000003f215000, 0x000000003f2150ff, 'bcm2835-aux'),
	(0x000000003f300000, 0x000000003f3000ff, 'sdhci'),
	(0x000000003fe05000, 0x000000003fe050ff, 'bcm2835-dma-chan15'),
	(0x0000000040000000, 0x00000000400000ff, 'bcm2836-control'),
]

parser = argparse.ArgumentParser(description='Identify I/O addresses for a system.')
parser.add_argument('addresses', metavar='ADDR', type=lambda x: int(x,16), nargs='+',
	help='an address to look up')
parser.add_argument('--machine', '-m', type=str, default='raspi2', choices=peripheral_list.keys(),
	help='machine def to use')
args = parser.parse_args()

plist = peripheral_list[args.machine]
starts = [p[0] for p in plist]

for a in args.addresses:
	idx = bisect.bisect_right(starts, a) - 1
	if idx == -1 or not \
		(plist[idx][0] <= a <= plist[idx][1]):
		print "%08x" % a, 'unknown'
	else:
		print "%08x" % a, plist[idx][2]

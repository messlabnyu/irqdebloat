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
#ifndef __PROG_POINT_H
#define __PROG_POINT_H
struct prog_point {
    target_ulong caller;
    target_ulong pc;
    target_ulong cr3;
#ifdef __cplusplus
    bool operator <(const prog_point &p) const {
        return (this->pc < p.pc) || \
               (this->pc == p.pc && this->caller < p.caller) || \
               (this->pc == p.pc && this->caller == p.caller && this->cr3 < p.cr3);
    }
    bool operator ==(const prog_point &p) const {
        return (this->pc == p.pc && this->caller == p.caller && this->cr3 == p.cr3);
    }
#endif
};

#endif

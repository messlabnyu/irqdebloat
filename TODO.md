* remove unnecessary memory region types (basically anything that's not MEM, GIC\*)
* figure out how to communicate from the unassigned memory callbacks to the master
    * is just writing a well-formatted string to stdout enough?
* determine how the runners can determine if they did something "interesting"
    * have the master collect call traces from the runners and do some graph comparison stuff?


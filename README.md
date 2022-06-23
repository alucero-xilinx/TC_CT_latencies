# TC_CT_latencies

This repo contains the work about studying TC and CT latencies.

It consists of:

- Ansible scripts for launching latencies tests
- Multithreads client/server programs for taking timestamps at different points in a TCP exchange
- Driver instrumentation for obtaining latencies per MCDI command
- Driver instrumentation for obtaining latencies per TC and CT commands
- kprobe kernel module for obtaining latencies in the conntrack workqueues processing by the kernel


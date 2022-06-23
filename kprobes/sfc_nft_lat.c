// SPDX-License-Identifier: GPL-2.0-only
/*
 * This kernel module uses the kernel kprobes interface for obtaining the
 * latency between netfilter code triggering offloads of established conntrack
 * flows, which is done through work items added to a kernel workqueue, and
 * when the kernel worker serving those work items invokes SFC driver code,
 * specifically efx_tc_flow_block.
 *
 * The module keeps those latencies and uses the kernel trace mechanism for
 * logging those points where latencies are calculated, and, when the module
 * is removed, the latencies of the flows/cookies offloaded.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/flow_offload.h>
#include <net/netfilter/nf_flow_table.h>

#define SFC_CT_MAX_LATS 1000

struct sfc_nft_lat {
	long unsigned int cookie;
	u64 start;
	u64 end;
};

struct sfc_nft_lat sfc_nft_add_lats[SFC_CT_MAX_LATS];
struct sfc_nft_lat sfc_nft_del_lats[SFC_CT_MAX_LATS];

/* Each time a CT flow is offload, the first instrumented function reserves two
 * entries in the latency array initialising them with the current timestamp
 * and related TC cookie. Using an atomic is necessary here since such a
 * function can be executed concurrently by different threads. Since each CT
 * flow requires two entries, one for each direction, and the atomic increment
 * happens first, the initialization needs to count on first invocation getting
 * index 0 and 1.
 */
static atomic_t lat_t0_add_inx = ATOMIC_INIT(-2);
static atomic_t lat_t0_del_inx = ATOMIC_INIT(-2);

#define MAX_SYMBOL_LEN	64

static char symbol_ct_add[MAX_SYMBOL_LEN] = "nf_flow_offload_add";
static struct kprobe kp_ct_add = {
	.symbol_name	= symbol_ct_add,
};

static char symbol_ct_del[MAX_SYMBOL_LEN] = "nf_flow_offload_del";
static struct kprobe kp_ct_del = {
	.symbol_name	= symbol_ct_del,
};

static char symbol_sfc[MAX_SYMBOL_LEN] = "efx_tc_flow_block";
static struct kprobe kp_sfc = {
	.symbol_name	= symbol_sfc,
};

static int __kprobes handler_ct_add_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct flow_offload *flow;
	unsigned long dir = 0;
	u64 now;
	int t0_inx;

	flow = (struct flow_offload *)regs->si;
	//dir = (unsigned long)regs->cx;

	t0_inx = atomic_add_return(2, &lat_t0_add_inx);
	if (t0_inx >= SFC_CT_MAX_LATS)
		return 0;

	now = ktime_get();
	trace_printk("<%s> cookie: 0x%lx, 0x%lx. Dir %lx (index: %d)(time: %llu)\n", p->symbol_name,
			(long unsigned int)&flow->tuplehash[0].tuple,
			(long unsigned int)&flow->tuplehash[1].tuple, dir, t0_inx, now);

	/* Each established conntrack flow installs a different flow in each
	 * direction.
	 */
	sfc_nft_add_lats[t0_inx].cookie = (long unsigned int)&flow->tuplehash[0].tuple;
	sfc_nft_add_lats[t0_inx].start= now;
	sfc_nft_add_lats[t0_inx + 1].cookie = (long unsigned int)&flow->tuplehash[1].tuple;
	sfc_nft_add_lats[t0_inx + 1].start= now;
	return 0;
}

static int __kprobes handler_ct_del_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct flow_offload *flow;
	unsigned long dir = 0;
	u64 now;
	int t0_inx;

	flow = (struct flow_offload *)regs->si;
	//dir = (unsigned long)regs->cx;

	t0_inx = atomic_add_return(2, &lat_t0_del_inx);
	if (t0_inx >= SFC_CT_MAX_LATS)
		return 0;

	now = ktime_get();
	trace_printk("<%s> cookie: 0x%lx, 0x%lx. Dir %lx (index: %d)(time: %llu)\n", p->symbol_name,
			(long unsigned int)&flow->tuplehash[0].tuple,
			(long unsigned int)&flow->tuplehash[1].tuple, dir, t0_inx, now);

	/* Each established conntrack flow installs a different flow in each
	 * direction.
	 */
	sfc_nft_del_lats[t0_inx].cookie = (long unsigned int)&flow->tuplehash[0].tuple;
	sfc_nft_del_lats[t0_inx].start= now;
	sfc_nft_del_lats[t0_inx + 1].cookie = (long unsigned int)&flow->tuplehash[1].tuple;
	sfc_nft_del_lats[t0_inx + 1].start= now;
	return 0;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}
NOKPROBE_SYMBOL(handler_fault);

static int __kprobes handler_sfc_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct flow_cls_offload *offload;
	int t1_inx;
	u64 now;
	int cnt = 0;

	offload = (struct flow_cls_offload *)regs->si;
	if (offload->command == FLOW_CLS_REPLACE) {

		now = ktime_get();
	       	trace_printk("<%s> FLOW_CLS_REPLACE, cookie: %lx, time: %llu\n", symbol_sfc, offload->cookie, now);

		t1_inx = atomic_read(&lat_t0_add_inx) + 1;

		/* This leaves some last entries uncomplete, but this is simple and 
		 * we already got a lot of data to work with.
		 */
		if (t1_inx >= SFC_CT_MAX_LATS)
			return 0;

		/* This is a bit ugly, but because queued work items added by
		 * nf_flow_offload_add can be processed in a different order, how to 
		 * update the latency data with the related t1 obtained here is not
		 * easy. This code assumes the unordered handling can happen but the
		 * index to update will be close. Concurrency makes things harder.
		 *
		 * Updating using the cookie as a key hash could be better but it needs
		 * to deal with repeated cookies. And missing one measurement from time
		 * to time should not be a big problem.
		 */
		//while (cnt < 5 && t1_inx >= 0) {
		while (t1_inx >= 0) {
			if (sfc_nft_add_lats[t1_inx].cookie == offload->cookie) {
				trace_printk("Updating %d (%lx)\n", t1_inx, offload->cookie);
				sfc_nft_add_lats[t1_inx].end= now;
				break;
			}
			t1_inx--;
			//cnt++;
		}
	} else if (offload->command == FLOW_CLS_DESTROY) {

		now = ktime_get();
	       	trace_printk("<%s> FLOW_CLS_DESTROY, cookie: %lx, time: %llu\n", symbol_sfc, offload->cookie, now);

		t1_inx = atomic_read(&lat_t0_del_inx) + 1;

		/* This leaves some last entries uncomplete, but this is simple and 
		 * we already got a lot of data to work with.
		 */
		if (t1_inx >= SFC_CT_MAX_LATS)
			return 0;

		/* This is a bit ugly, but because queued work items added by
		 * nf_flow_offload_add can be processed in a different order, how to 
		 * update the latency data with the related t1 obtained here is not
		 * easy. This code assumes the unordered handling can happen but the
		 * index to update will be close. Concurrency makes things harder.
		 *
		 * Updating using the cookie as a key hash could be better but it needs
		 * to deal with repeated cookies. And missing one measurement from time
		 * to time should not be a big problem.
		 */
		//while (cnt < 5 && t1_inx >= 0) {
		while (t1_inx >= 0) {
			if (sfc_nft_del_lats[t1_inx].cookie == offload->cookie) {
				trace_printk("Updating %d (%lx)\n", t1_inx, offload->cookie);
				sfc_nft_del_lats[t1_inx].end = now;
				break;
			}
			t1_inx--;
			//cnt++;
		}
	}

	return 0;
}

static int __init sfc_nft_lat_init(void)
{
	int ret;


	memset(sfc_nft_add_lats, 0, sizeof(sfc_nft_add_lats));

	kp_ct_add.pre_handler = handler_ct_add_pre;
	kp_ct_add.fault_handler = handler_fault;

	ret = register_kprobe(&kp_ct_add);
	if (ret < 0) {
		pr_err("register_kprobe CT add failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe cT add at %p\n", kp_ct_add.addr);

	memset(sfc_nft_del_lats, 0, sizeof(sfc_nft_del_lats));

	kp_ct_del.pre_handler = handler_ct_del_pre;
	kp_ct_del.fault_handler = handler_fault;

	ret = register_kprobe(&kp_ct_del);
	if (ret < 0) {
		pr_err("register_kprobe CT del failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe cT del at %p\n", kp_ct_del.addr);

	kp_sfc.pre_handler = handler_sfc_pre;
	kp_sfc.fault_handler = handler_fault;

	ret = register_kprobe(&kp_sfc);
	if (ret < 0) {
		pr_err("register_krobe SFC failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe SFC at %p\n", kp_sfc.addr);
	return 0;
}

static void __exit sfc_nft_lat_exit(void)
{
	int i = 0;
	int t0_inx;

	unregister_kprobe(&kp_ct_add);
	unregister_kprobe(&kp_ct_del);
	unregister_kprobe(&kp_sfc);

	t0_inx = atomic_read(&lat_t0_add_inx);

	while (i < (t0_inx + 2)) {
		trace_printk("SFC_NFT_ADD_LAT[%d]: %llu (%llu, %llu)\n", i, sfc_nft_add_lats[i].end - sfc_nft_add_lats[i].start,
				sfc_nft_add_lats[i].start, sfc_nft_add_lats[i].end);
		i++;
	}
	i = 0;
	t0_inx = atomic_read(&lat_t0_del_inx);

	while (i < (t0_inx + 2)) {
		trace_printk("SFC_NFT_DEL_LAT[%d]: %llu (%llu, %llu)\n", i, sfc_nft_del_lats[i].end - sfc_nft_del_lats[i].start,
				sfc_nft_del_lats[i].start, sfc_nft_del_lats[i].end);
		i++;
	}
	pr_info("kprobe at %p unregistered\n", kp_ct_add.addr);
	pr_info("kprobe at %p unregistered\n", kp_ct_del.addr);
	pr_info("kprobe at %p unregistered\n", kp_sfc.addr);
}

module_init(sfc_nft_lat_init)
module_exit(sfc_nft_lat_exit)
MODULE_LICENSE("GPL");

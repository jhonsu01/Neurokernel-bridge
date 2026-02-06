#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

/* ===== EVENT TYPE CONSTANTS ===== */
#define EVT_EXEC        1
#define EVT_FILE        2
#define EVT_NET_CONN    3
#define EVT_NET_ACCEPT  4
#define EVT_NET_DNS     5
#define EVT_RESOURCE    6
#define EVT_SUSPICIOUS  7

/* ===== SUSPICIOUS SUBTYPES ===== */
#define SUSP_PTRACE      1
#define SUSP_MMAP_EXEC   2
#define SUSP_MPROTECT    3
#define SUSP_MODULE_LOAD 4

/* ===== RESOURCE SUBTYPES ===== */
#define RES_OOM          1

/* ===== PER-DIMENSION EVENT STRUCTURES ===== */

struct exec_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct file_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int flags;
};

struct net_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  direction;   /* 0=outbound, 1=inbound */
    u8  protocol;    /* 6=TCP, 17=UDP */
};

struct resource_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u8  subtype;
    u64 value;
};

struct suspicious_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 target_pid;
    char comm[TASK_COMM_LEN];
    u8  subtype;
    u64 flags;
};

/* ===== PERF OUTPUT BUFFERS ===== */
BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(net_events);
BPF_PERF_OUTPUT(resource_events);
BPF_PERF_OUTPUT(suspicious_events);

/* ===== RATE LIMITING & FILTERING ===== */
BPF_HASH(pid_filter, u32, u8, 256);
BPF_HASH(file_throttle, u32, u64, 10240);

/* ===== CONNECTION TRACKING ===== */
struct connect_args_t {
    u32 daddr;
    u16 dport;
};
BPF_HASH(active_connects, u32, struct connect_args_t, 4096);

/* ===== HELPER: check if pid is filtered ===== */
static inline int is_filtered(u32 pid) {
    u8 *val = pid_filter.lookup(&pid);
    return val != NULL;
}

/* ========================================================
 * DIMENSION 1: PROCESS EXECUTION
 * ======================================================== */

int trace_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct exec_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&evt.ppid, sizeof(evt.ppid), &parent->tgid);

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    exec_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 2: FILE ACCESS
 * ======================================================== */

int trace_openat2(struct pt_regs *ctx, int dfd,
                  const char __user *filename) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    /* Rate limit: max one file event per PID per 100ms */
    u64 now = bpf_ktime_get_ns();
    u64 *last = file_throttle.lookup(&pid);
    if (last && (now - *last) < 100000000ULL) return 0;
    file_throttle.update(&pid, &now);

    struct file_event_t evt = {};
    evt.timestamp_ns = now;
    evt.pid = pid;
    evt.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user(&evt.filename, sizeof(evt.filename), filename);

    file_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 3: NETWORK - OUTBOUND TCP
 * ======================================================== */

int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct connect_args_t args = {};
    bpf_probe_read(&args.daddr, sizeof(args.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&args.dport, sizeof(args.dport), &sk->__sk_common.skc_dport);
    active_connects.update(&tid, &args);
    return 0;
}

int trace_tcp_connect_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct connect_args_t *args = active_connects.lookup(&tid);
    if (!args) return 0;

    /* Only emit on success or EINPROGRESS (async connect) */
    if (ret != 0 && ret != -115) {
        active_connects.delete(&tid);
        return 0;
    }

    struct net_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = tid;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.daddr = args->daddr;
    evt.dport = ntohs(args->dport);
    evt.direction = 0;  /* outbound */
    evt.protocol = 6;   /* TCP */

    net_events.perf_submit(ctx, &evt, sizeof(evt));
    active_connects.delete(&tid);
    return 0;
}

/* ========================================================
 * DIMENSION 3: NETWORK - INBOUND TCP
 * ======================================================== */

int trace_tcp_accept(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct net_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read(&evt.saddr, sizeof(evt.saddr), &newsk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&evt.daddr, sizeof(evt.daddr), &newsk->__sk_common.skc_daddr);
    bpf_probe_read(&evt.sport, sizeof(evt.sport), &newsk->__sk_common.skc_num);
    u16 dport_be = 0;
    bpf_probe_read(&dport_be, sizeof(dport_be), &newsk->__sk_common.skc_dport);
    evt.dport = ntohs(dport_be);
    evt.direction = 1;  /* inbound */
    evt.protocol = 6;   /* TCP */

    net_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 3: NETWORK - DNS (UDP port 53)
 * ======================================================== */

int trace_udp_send(struct pt_regs *ctx, struct sock *sk) {
    u16 dport_be = 0;
    bpf_probe_read(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);
    if (ntohs(dport_be) != 53) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct net_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read(&evt.daddr, sizeof(evt.daddr), &sk->__sk_common.skc_daddr);
    evt.dport = 53;
    evt.direction = 0;  /* outbound */
    evt.protocol = 17;  /* UDP */

    net_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 4: RESOURCE MONITORING
 * ======================================================== */

int trace_oom(struct pt_regs *ctx) {
    struct resource_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.subtype = RES_OOM;

    resource_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 5: SUSPICIOUS SYSCALLS - PTRACE
 * ======================================================== */

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct suspicious_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.subtype = SUSP_PTRACE;
    evt.flags = args->request;
    evt.target_pid = args->pid;

    suspicious_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 5: SUSPICIOUS SYSCALLS - MMAP WITH PROT_EXEC
 * ======================================================== */

int trace_mmap_exec(struct pt_regs *ctx) {
    unsigned long prot = PT_REGS_PARM2(ctx);
    unsigned long flags_val = PT_REGS_PARM3(ctx);

    /* Only care about PROT_EXEC (0x4) + MAP_ANONYMOUS (0x20) */
    if (!(prot & 0x4)) return 0;
    if (!(flags_val & 0x20)) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct suspicious_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.subtype = SUSP_MMAP_EXEC;
    evt.flags = prot | (flags_val << 32);

    suspicious_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ========================================================
 * DIMENSION 5: SUSPICIOUS SYSCALLS - KERNEL MODULE LOADING
 * ======================================================== */

int trace_module_load(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (is_filtered(pid)) return 0;

    struct suspicious_event_t evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = pid;
    evt.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.subtype = SUSP_MODULE_LOAD;

    suspicious_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

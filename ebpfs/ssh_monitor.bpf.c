//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

// 运行时配置（通过 BPF_MAP_ARRAY 实现动态热更新）
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct runtime_config);
} config_map SEC(".maps");

// 运行时配置结构体（存入 config_map，支持运行时热更新）
struct runtime_config {
	__u8  aggressive_mode;        // 0=normal, 1=aggressive
	__u64 preauth_short_conn_ns;  // preauth 短连接判定阈值（纳秒）
};

enum ssh_event_type {
    EVENT_AUTH_RESULT = 1,
    EVENT_PREAUTH_SHORT_CONN = 2,
};

struct ssh_event {
    __u32 type;
    __u32 pid;
    __u32 remote_ip;
    __u32 ret_code;
    __u64 duration_ns;
};

struct pid_ctx {
    __u32 remote_ip;
    __u64 start_ns;
    __u8 auth_attempted;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u16);
    __type(value, __u8);
} monitored_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pid_ctx);
} pid_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} events SEC(".maps");

// --- A. 记录新连接 (kretprobe，跨版本兼容) ---
// 注：inet_csk_accept 的输入参数签名在 6.12 内核发生断裂式变化
// (旧版 4 参数 → 新版 2 参数 struct proto_accept_arg*)，fexit 无法跨版本
// 统一匹配。本处理函数仅使用返回值 newsk (struct sock*)，该返回值类型
// 跨所有内核版本不变，因此 kretprobe 天然兼容 6.1 ~ 7.1+，无需 CO-RE 探测。
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_accept_kretprobe, struct sock *newsk) {
    if (!newsk) {
        return 0;
    }

    __u16 lport = BPF_CORE_READ(newsk, __sk_common.skc_num);

    if (!bpf_map_lookup_elem(&monitored_ports, &lport)) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
    struct pid_ctx conn_ctx = {
        .remote_ip = daddr,
        .start_ns = bpf_ktime_get_ns(),
        .auth_attempted = 0,
    };

    bpf_map_update_elem(&pid_ctx_map, &pid, &conn_ctx, BPF_ANY);

    return 0;
}

// --- B. 子进程继承关系 (处理 sshd fork) ---
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    struct pid_ctx *parent_ctx = bpf_map_lookup_elem(&pid_ctx_map, &parent_pid);
    if (parent_ctx) {
        bpf_map_update_elem(&pid_ctx_map, &child_pid, parent_ctx, BPF_ANY);
    }
    return 0;
}

// --- C. PAM 认证判定 ---
SEC("uretprobe/pam_authenticate")
int BPF_KRETPROBE(handle_pam_auth, int ret) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pid_ctx *conn_ctx = bpf_map_lookup_elem(&pid_ctx_map, &pid);
    __u32 remote_ip = 0;
    if (conn_ctx) {
        conn_ctx->auth_attempted = 1;
        remote_ip = conn_ctx->remote_ip;
    }

    struct ssh_event e = {
        .type = EVENT_AUTH_RESULT,
        .pid = pid,
        .remote_ip = remote_ip,
        .ret_code = (__u32)ret,
        .duration_ns = 0,
    };
	void *ring = bpf_ringbuf_reserve(&events, sizeof(e), 0);
	if (!ring) {
		return 0;
	}
	__builtin_memcpy(ring, &e, sizeof(e));
	bpf_ringbuf_submit(ring, 0);
	return 0;
}

// --- D. 进程退出清理 ---
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pid_ctx *conn_ctx = bpf_map_lookup_elem(&pid_ctx_map, &pid);
    if (!conn_ctx) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int raw_exit_code = BPF_CORE_READ(task, exit_code);

    __u32 exit_status = (raw_exit_code >> 8) & 0xFF;
    __u32 exit_signal = raw_exit_code & 0x7F;

    __u32 cfg_key = 0;
    struct runtime_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg && cfg->aggressive_mode) {
        if (conn_ctx->auth_attempted == 0) {
            __u64 duration_ns = bpf_ktime_get_ns() - conn_ctx->start_ns;

            if (duration_ns < cfg->preauth_short_conn_ns || exit_status != 0 || exit_signal != 0) {
                struct ssh_event e = {
                    .type = EVENT_PREAUTH_SHORT_CONN,
                    .pid = pid,
                    .remote_ip = conn_ctx->remote_ip,
                    .ret_code = exit_status | (exit_signal << 16),
                    .duration_ns = duration_ns,
                };
			void *ring = bpf_ringbuf_reserve(&events, sizeof(e), 0);
			if (!ring) {
			} else {
				__builtin_memcpy(ring, &e, sizeof(e));
				bpf_ringbuf_submit(ring, 0);
			}
            }
        }
    }

    bpf_map_delete_elem(&pid_ctx_map, &pid);
    return 0;
}

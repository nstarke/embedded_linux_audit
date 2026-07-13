// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke

#include "linux_audit_util.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#define PROFILE_BOTH (ELA_LINUX_AUDIT_PROFILE_EMBEDDED | ELA_LINUX_AUDIT_PROFILE_HARDENED)

// clang-format off
const struct ela_linux_audit_rule ela_linux_audit_rules[] = {
	{
		"ELA-LINUX-001", "Address-space randomization", "kernel", "high",
		"Kernel address-space randomization should protect process mappings.",
		"Set kernel.randomize_va_space=2, or at least 1 where full randomization is unsupported.",
		"/proc/sys/kernel/randomize_va_space", PROFILE_BOTH, 1, 2, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-002", "Kernel pointer restriction", "kernel", "medium",
		"Unprivileged users should not receive kernel pointers through procfs and related interfaces.",
		"Set kernel.kptr_restrict=2 (1 is accepted by the embedded profile).",
		"/proc/sys/kernel/kptr_restrict", PROFILE_BOTH, 1, 2, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-003", "Kernel log restriction", "kernel", "medium",
		"Kernel logs can disclose addresses, devices, and security-sensitive runtime state.",
		"Set kernel.dmesg_restrict=1 and grant log access only to trusted diagnostics components.",
		"/proc/sys/kernel/dmesg_restrict", PROFILE_BOTH, 1, 1, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-004", "Protected hardlinks", "filesystem", "medium",
		"Hardlink protections reduce link-based privilege escalation attacks in writable directories.",
		"Set fs.protected_hardlinks=1.",
		"/proc/sys/fs/protected_hardlinks", PROFILE_BOTH, 1, 1, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-005", "Protected symlinks", "filesystem", "medium",
		"Symlink protections reduce time-of-check/time-of-use attacks in sticky writable directories.",
		"Set fs.protected_symlinks=1.",
		"/proc/sys/fs/protected_symlinks", PROFILE_BOTH, 1, 1, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-006", "Performance event restriction", "kernel", "medium",
		"Performance events can expose process and kernel execution details to unprivileged users.",
		"Set kernel.perf_event_paranoid=2 or higher.",
		"/proc/sys/kernel/perf_event_paranoid", ELA_LINUX_AUDIT_PROFILE_HARDENED, 2, 2, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-007", "Ptrace restriction", "process", "high",
		"Same-user ptrace access should be restricted to reduce credential and process-memory theft.",
		"Enable Yama and set kernel.yama.ptrace_scope=1 or higher.",
		"/proc/sys/kernel/yama/ptrace_scope", ELA_LINUX_AUDIT_PROFILE_HARDENED, 1, 1, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		"ELA-LINUX-008", "Unprivileged BPF restriction", "kernel", "high",
		"Unprivileged BPF expands kernel attack surface and should be disabled on production appliances.",
		"Set kernel.unprivileged_bpf_disabled=1 (or 2 where supported).",
		"/proc/sys/kernel/unprivileged_bpf_disabled", ELA_LINUX_AUDIT_PROFILE_HARDENED, 1, 1, ELA_LINUX_AUDIT_CHECK_INTEGER_MIN, NULL,
	},
	{
		.id = "ELA-LINUX-009", .title = "KASLR boot override", .category = "kernel", .severity = "high",
		.description = "The kernel command line must not explicitly disable address-space randomization.",
		.remediation = "Remove nokaslr from the boot command line and enforce the expected boot policy.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "nokaslr",
	},
	{
		.id = "ELA-LINUX-010", .title = "Forced kernel module signatures", .category = "modules", .severity = "high",
		.description = "Unsigned kernel modules must not be loadable on a production target.",
		.remediation = "Build with CONFIG_MODULE_SIG=y and CONFIG_MODULE_SIG_FORCE=y, then deploy signed modules.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_MODULE_SIG_FORCE=y",
	},
	{
		.id = "ELA-LINUX-011", .title = "Kernel lockdown", .category = "kernel", .severity = "high",
		.description = "Kernel lockdown should prevent privileged interfaces from bypassing measured boot policy.",
		.remediation = "Enable integrity or confidentiality lockdown through the trusted boot chain.",
		.path = "/sys/kernel/security/lockdown", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_LOCKDOWN,
	},
	{
		.id = "ELA-LINUX-012", .title = "Enforcing Linux security module", .category = "lsm", .severity = "high",
		.description = "At least one supported Linux security module must be active in enforcing mode.",
		.remediation = "Enable SELinux enforcing mode, AppArmor with an active policy, or an equivalent enforcing LSM.",
		.path = "/sys/kernel/security/lsm", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_LSM_ENFORCING,
	},
	{
		.id = "ELA-LINUX-013", .title = "Kexec load restriction", .category = "kernel", .severity = "high",
		.description = "Runtime kexec loading should be disabled to prevent replacing the measured kernel.",
		.remediation = "Set kernel.kexec_load_disabled=1 before untrusted workloads start.",
		.path = "/proc/sys/kernel/kexec_load_disabled", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.embedded_minimum = 1, .hardened_minimum = 1,
	},
	{
		.id = "ELA-LINUX-014", .title = "User namespace restriction", .category = "kernel", .severity = "medium",
		.description = "Unprivileged user namespaces expand the kernel attack surface on appliance targets.",
		.remediation = "Set user.max_user_namespaces=0 unless container workloads explicitly require user namespaces.",
		.path = "/proc/sys/user/max_user_namespaces", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-015", .title = "Debugfs not exposed", .category = "debug", .severity = "medium",
		.description = "Mounted debugfs exposes powerful kernel debugging and inspection interfaces.",
		.remediation = "Do not mount debugfs on production targets, or restrict it to a trusted diagnostic mode.",
		.path = "/proc/mounts", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_MOUNT_ABSENT, .expected = "debugfs",
	},
	{
		.id = "ELA-LINUX-016", .title = "Magic SysRq disabled", .category = "kernel", .severity = "medium",
		.description = "Magic SysRq can provide privileged recovery and debugging operations from a local console.",
		.remediation = "Set kernel.sysrq=0 except during an explicitly authorized diagnostic session.",
		.path = "/proc/sys/kernel/sysrq", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-017", .title = "Restricted /dev/mem", .category = "debug", .severity = "high",
		.description = "Direct physical-memory access must not be available to ordinary users.",
		.remediation = "Remove /dev/mem where possible; otherwise restrict it to root with mode 0600 and strict kernel devmem settings.",
		.path = "/dev/mem", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_DEVICE_MODE,
	},
	{
		.id = "ELA-LINUX-018", .title = "Controlled core dumps", .category = "process", .severity = "medium",
		.description = "Uncontrolled process core files can disclose credentials and sensitive memory.",
		.remediation = "Disable core dumps or route them to an authenticated, access-controlled collector.",
		.path = "/proc/sys/kernel/core_pattern", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CORE_PATTERN,
	},
	{
		.id = "ELA-LINUX-019", .title = "Kexec disabled in kernel", .category = "kernel", .severity = "high",
		.description = "Kexec support should be absent when the device relies on measured or verified boot.",
		.remediation = "Build the production kernel with CONFIG_KEXEC disabled, and keep the runtime kexec load restriction enabled.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "# CONFIG_KEXEC is not set",
	},
	{
		.id = "ELA-LINUX-020", .title = "Protected FIFOs", .category = "filesystem", .severity = "medium",
		.description = "FIFO protections stop tricked writes through attacker-created FIFOs in sticky world-writable directories.",
		.remediation = "Set fs.protected_fifos=1, or 2 to also cover group-writable directories.",
		.path = "/proc/sys/fs/protected_fifos", .profiles = PROFILE_BOTH,
		.embedded_minimum = 1, .hardened_minimum = 2,
	},
	{
		.id = "ELA-LINUX-021", .title = "Protected regular files", .category = "filesystem", .severity = "medium",
		.description = "Regular-file protections stop tricked writes through attacker-created files in sticky world-writable directories.",
		.remediation = "Set fs.protected_regular=1, or 2 to also cover group-writable directories.",
		.path = "/proc/sys/fs/protected_regular", .profiles = PROFILE_BOTH,
		.embedded_minimum = 1, .hardened_minimum = 2,
	},
	{
		.id = "ELA-LINUX-022", .title = "SUID core dumps disabled", .category = "process", .severity = "medium",
		.description = "Core dumps of set-uid programs can disclose privileged memory contents.",
		.remediation = "Set fs.suid_dumpable=0.",
		.path = "/proc/sys/fs/suid_dumpable", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-023", .title = "Module loading locked", .category = "modules", .severity = "medium",
		.description = "Locking module loading prevents new kernel code from being introduced after boot.",
		.remediation = "Set kernel.modules_disabled=1 once all required modules are loaded.",
		.path = "/proc/sys/kernel/modules_disabled", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.embedded_minimum = 1, .hardened_minimum = 1,
	},
	{
		.id = "ELA-LINUX-024", .title = "Minimum mmap address", .category = "kernel", .severity = "medium",
		.description = "A low mmap floor lets user mappings reach page zero, aiding kernel NULL-dereference exploitation.",
		.remediation = "Set vm.mmap_min_addr=65536, or at least 4096 where legacy software requires lower mappings.",
		.path = "/proc/sys/vm/mmap_min_addr", .profiles = PROFILE_BOTH,
		.embedded_minimum = 4096, .hardened_minimum = 65536,
	},
	{
		.id = "ELA-LINUX-025", .title = "Unprivileged userfaultfd disabled", .category = "kernel", .severity = "medium",
		.description = "Unprivileged userfaultfd makes kernel use-after-free races far easier to exploit.",
		.remediation = "Set vm.unprivileged_userfaultfd=0.",
		.path = "/proc/sys/vm/unprivileged_userfaultfd", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-026", .title = "TTY line-discipline autoload disabled", .category = "kernel", .severity = "medium",
		.description = "Automatic TTY line-discipline loading exposes rarely audited kernel modules to unprivileged users.",
		.remediation = "Set dev.tty.ldisc_autoload=0.",
		.path = "/proc/sys/dev/tty/ldisc_autoload", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-027", .title = "io_uring restriction", .category = "kernel", .severity = "medium",
		.description = "Unprivileged io_uring access has produced a steady stream of kernel privilege-escalation bugs.",
		.remediation = "Set kernel.io_uring_disabled=2, or 1 to limit io_uring to privileged processes.",
		.path = "/proc/sys/kernel/io_uring_disabled", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.embedded_minimum = 1, .hardened_minimum = 1,
	},
	{
		.id = "ELA-LINUX-028", .title = "IP forwarding disabled", .category = "network", .severity = "medium",
		.description = "Hosts that are not routers should not forward packets between interfaces.",
		.remediation = "Set net.ipv4.ip_forward=0 unless the device intentionally routes traffic.",
		.path = "/proc/sys/net/ipv4/ip_forward", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-029", .title = "ICMP redirects not accepted", .category = "network", .severity = "medium",
		.description = "Accepting ICMP redirects lets an on-path host alter this device's routing.",
		.remediation = "Set net.ipv4.conf.all.accept_redirects=0 (and the default.accept_redirects variant).",
		.path = "/proc/sys/net/ipv4/conf/all/accept_redirects", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-030", .title = "ICMP redirects not sent", .category = "network", .severity = "low",
		.description = "Sending ICMP redirects discloses topology and is unnecessary on non-routing hosts.",
		.remediation = "Set net.ipv4.conf.all.send_redirects=0.",
		.path = "/proc/sys/net/ipv4/conf/all/send_redirects", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-031", .title = "Source-routed packets rejected", .category = "network", .severity = "medium",
		.description = "Source-routed packets let remote senders steer traffic around routing policy.",
		.remediation = "Set net.ipv4.conf.all.accept_source_route=0.",
		.path = "/proc/sys/net/ipv4/conf/all/accept_source_route", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_INTEGER_MAX, .expected = "0",
	},
	{
		.id = "ELA-LINUX-032", .title = "Reverse-path filtering", .category = "network", .severity = "medium",
		.description = "Reverse-path filtering drops packets with spoofed source addresses.",
		.remediation = "Set net.ipv4.conf.all.rp_filter=1, or 2 where asymmetric routing is required.",
		.path = "/proc/sys/net/ipv4/conf/all/rp_filter", .profiles = PROFILE_BOTH,
		.embedded_minimum = 1, .hardened_minimum = 1,
	},
	{
		.id = "ELA-LINUX-033", .title = "TCP SYN cookies", .category = "network", .severity = "medium",
		.description = "SYN cookies keep TCP services reachable during SYN-flood attacks.",
		.remediation = "Set net.ipv4.tcp_syncookies=1.",
		.path = "/proc/sys/net/ipv4/tcp_syncookies", .profiles = PROFILE_BOTH,
		.embedded_minimum = 1, .hardened_minimum = 1,
	},
	{
		.id = "ELA-LINUX-034", .title = "CPU mitigations boot override", .category = "kernel", .severity = "high",
		.description = "The kernel command line must not disable CPU speculative-execution mitigations.",
		.remediation = "Remove mitigations=off from the boot command line and enforce the expected boot policy.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "mitigations=off",
	},
	{
		.id = "ELA-LINUX-035", .title = "SMEP boot override", .category = "kernel", .severity = "high",
		.description = "The kernel command line must not disable supervisor-mode execution prevention.",
		.remediation = "Remove nosmep from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "nosmep",
	},
	{
		.id = "ELA-LINUX-036", .title = "SMAP boot override", .category = "kernel", .severity = "high",
		.description = "The kernel command line must not disable supervisor-mode access prevention.",
		.remediation = "Remove nosmap from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "nosmap",
	},
	{
		.id = "ELA-LINUX-037", .title = "Page-table isolation boot override", .category = "kernel", .severity = "high",
		.description = "The kernel command line must not disable kernel page-table isolation.",
		.remediation = "Remove nopti from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "nopti",
	},
	{
		.id = "ELA-LINUX-038", .title = "Init shell boot override", .category = "kernel", .severity = "high",
		.description = "Booting directly into a shell bypasses the init system and any access control.",
		.remediation = "Remove init=/bin/sh from the boot command line and enforce the expected boot policy.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "init=/bin/sh",
	},
	{
		.id = "ELA-LINUX-039", .title = "Initramfs shell boot override", .category = "kernel", .severity = "high",
		.description = "Booting the initramfs into a shell bypasses the init system and any access control.",
		.remediation = "Remove rdinit=/bin/sh from the boot command line and enforce the expected boot policy.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "rdinit=/bin/sh",
	},
	{
		.id = "ELA-LINUX-040", .title = "SELinux boot override", .category = "lsm", .severity = "high",
		.description = "The kernel command line must not disable SELinux where it is part of the security policy.",
		.remediation = "Remove selinux=0 from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "selinux=0",
	},
	{
		.id = "ELA-LINUX-041", .title = "AppArmor boot override", .category = "lsm", .severity = "high",
		.description = "The kernel command line must not disable AppArmor where it is part of the security policy.",
		.remediation = "Remove apparmor=0 from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "apparmor=0",
	},
	{
		.id = "ELA-LINUX-042", .title = "LSM enforcing boot override", .category = "lsm", .severity = "high",
		.description = "The kernel command line must not force the security module into permissive mode.",
		.remediation = "Remove enforcing=0 from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "enforcing=0",
	},
	{
		.id = "ELA-LINUX-043", .title = "Module signature boot override", .category = "modules", .severity = "high",
		.description = "The kernel command line must not disable kernel module signature enforcement.",
		.remediation = "Remove module.sig_enforce=0 from the boot command line.",
		.path = "/proc/cmdline", .profiles = PROFILE_BOTH,
		.check_type = ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN, .expected = "module.sig_enforce=0",
	},
	{
		.id = "ELA-LINUX-044", .title = "Strict kernel memory permissions", .category = "kernel", .severity = "high",
		.description = "Kernel text and read-only data must not be writable at runtime.",
		.remediation = "Build with CONFIG_STRICT_KERNEL_RWX=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_STRICT_KERNEL_RWX=y",
	},
	{
		.id = "ELA-LINUX-045", .title = "Strong kernel stack protector", .category = "kernel", .severity = "medium",
		.description = "Stack canaries should protect kernel functions against stack-buffer overflows.",
		.remediation = "Build with CONFIG_STACKPROTECTOR_STRONG=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_STACKPROTECTOR_STRONG=y",
	},
	{
		.id = "ELA-LINUX-046", .title = "Hardened usercopy", .category = "kernel", .severity = "medium",
		.description = "Usercopy hardening bounds-checks copies between kernel and user space.",
		.remediation = "Build with CONFIG_HARDENED_USERCOPY=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_HARDENED_USERCOPY=y",
	},
	{
		.id = "ELA-LINUX-047", .title = "Fortified kernel string functions", .category = "kernel", .severity = "medium",
		.description = "FORTIFY_SOURCE detects common kernel buffer overflows in string and memory functions.",
		.remediation = "Build with CONFIG_FORTIFY_SOURCE=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_FORTIFY_SOURCE=y",
	},
	{
		.id = "ELA-LINUX-048", .title = "Strict /dev/mem access", .category = "debug", .severity = "high",
		.description = "Strict devmem limits /dev/mem to device memory ranges rather than all of RAM.",
		.remediation = "Build with CONFIG_STRICT_DEVMEM=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_STRICT_DEVMEM=y",
	},
	{
		.id = "ELA-LINUX-049", .title = "Debugfs compiled out", .category = "debug", .severity = "medium",
		.description = "Debugfs support should be absent from production kernels rather than merely unmounted.",
		.remediation = "Build the production kernel with CONFIG_DEBUG_FS disabled.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "# CONFIG_DEBUG_FS is not set",
	},
	{
		.id = "ELA-LINUX-050", .title = "Hardened SLAB freelists", .category = "kernel", .severity = "medium",
		.description = "Freelist hardening makes kernel heap corruption harder to turn into code execution.",
		.remediation = "Build with CONFIG_SLAB_FREELIST_HARDENED=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_SLAB_FREELIST_HARDENED=y",
	},
	{
		.id = "ELA-LINUX-051", .title = "Zero-initialized allocations", .category = "kernel", .severity = "medium",
		.description = "Zeroing allocations by default closes most uninitialized-memory disclosure bugs.",
		.remediation = "Build with CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y or boot with init_on_alloc=1.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y",
	},
	{
		.id = "ELA-LINUX-052", .title = "Seccomp support", .category = "process", .severity = "medium",
		.description = "Seccomp lets services reduce their kernel attack surface with syscall filters.",
		.remediation = "Build with CONFIG_SECCOMP=y.",
		.path = "/boot/config-<release>", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION, .expected = "CONFIG_SECCOMP=y",
	},
	{
		.id = "ELA-LINUX-053", .title = "Tracefs not exposed", .category = "debug", .severity = "medium",
		.description = "Mounted tracefs exposes kernel function tracing that can leak addresses and runtime behavior.",
		.remediation = "Do not mount tracefs on production targets, or restrict it to a trusted diagnostic mode.",
		.path = "/proc/mounts", .profiles = ELA_LINUX_AUDIT_PROFILE_HARDENED,
		.check_type = ELA_LINUX_AUDIT_CHECK_MOUNT_ABSENT, .expected = "tracefs",
	},
};
// clang-format on

const size_t ela_linux_audit_rule_count = sizeof(ela_linux_audit_rules) / sizeof(ela_linux_audit_rules[0]);

const char *ela_linux_audit_profile_name(enum ela_linux_audit_profile profile)
{
	return profile == ELA_LINUX_AUDIT_PROFILE_HARDENED ? "hardened" : "embedded";
}

int ela_linux_audit_parse_profile(const char *text, enum ela_linux_audit_profile *profile_out)
{
	if (!text || !profile_out)
		return -1;
	if (!strcmp(text, "embedded"))
		*profile_out = ELA_LINUX_AUDIT_PROFILE_EMBEDDED;
	else if (!strcmp(text, "hardened"))
		*profile_out = ELA_LINUX_AUDIT_PROFILE_HARDENED;
	else
		return -1;
	return 0;
}

const char *ela_linux_audit_status_name(enum ela_linux_audit_status status)
{
	switch (status) {
	case ELA_LINUX_AUDIT_PASS:
		return "pass";
	case ELA_LINUX_AUDIT_FAIL:
		return "fail";
	case ELA_LINUX_AUDIT_NOT_APPLICABLE:
		return "not-applicable";
	case ELA_LINUX_AUDIT_UNKNOWN:
	default:
		return "unknown";
	}
}

int ela_linux_audit_rule_enabled(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile)
{
	return rule && (rule->profiles & (unsigned int)profile) != 0;
}

const struct ela_linux_audit_rule *ela_linux_audit_find_rule(const char *id)
{
	size_t i;

	if (!id)
		return NULL;
	for (i = 0; i < ela_linux_audit_rule_count; i++) {
		if (!strcmp(ela_linux_audit_rules[i].id, id))
			return &ela_linux_audit_rules[i];
	}
	return NULL;
}

int ela_linux_audit_evaluate(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile,
			     const char *raw_value, struct ela_linux_audit_result *result)
{
	char *end;
	long actual;
	long minimum;
	long maximum;

	if (!rule || !raw_value || !result || !ela_linux_audit_rule_enabled(rule, profile))
		return -1;

	errno = 0;
	actual = strtol(raw_value, &end, 10);
	while (end && isspace((unsigned char)*end))
		end++;
	if (errno || end == raw_value || !end || *end != '\0') {
		result->status = ELA_LINUX_AUDIT_UNKNOWN;
		snprintf(result->evidence, sizeof(result->evidence), "%s contains an invalid integer: %.160s",
			 rule->path, raw_value);
		return 0;
	}

	if (rule->check_type == ELA_LINUX_AUDIT_CHECK_INTEGER_MAX) {
		char *max_end = NULL;
		errno = 0;
		maximum = strtol(rule->expected ? rule->expected : "0", &max_end, 10);
		if (errno || max_end == (rule->expected ? rule->expected : "0") || !max_end || *max_end != '\0') {
			result->status = ELA_LINUX_AUDIT_UNKNOWN;
			snprintf(result->evidence, sizeof(result->evidence), "%s has an invalid rule threshold",
				 rule->path);
			return 0;
		}
		result->status = actual <= maximum ? ELA_LINUX_AUDIT_PASS : ELA_LINUX_AUDIT_FAIL;
		snprintf(result->evidence, sizeof(result->evidence), "%s=%ld; expected <= %ld", rule->path, actual,
			 maximum);
		return 0;
	}

	minimum = profile == ELA_LINUX_AUDIT_PROFILE_HARDENED ? rule->hardened_minimum : rule->embedded_minimum;
	result->status = actual >= minimum ? ELA_LINUX_AUDIT_PASS : ELA_LINUX_AUDIT_FAIL;
	snprintf(result->evidence, sizeof(result->evidence), "%s=%ld; expected >= %ld", rule->path, actual, minimum);
	return 0;
}

static int build_probe_path(const char *root, const char *relative, char *path, size_t path_len)
{
	const char *prefix = (root && strcmp(root, "/")) ? root : "";

	if (!relative || !path || !path_len || snprintf(path, path_len, "%s%s", prefix, relative) >= (int)path_len)
		return -1;
	return 0;
}

static int read_probe_file(const char *root, const char *relative, char *buf, size_t buf_len, char *path,
			   size_t path_len)
{
	FILE *fp;
	size_t got;
	int saved_errno;

	if (build_probe_path(root, relative, path, path_len) != 0 || !buf || buf_len < 2)
		return -1;
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	got = fread(buf, 1, buf_len - 1, fp);
	saved_errno = ferror(fp) ? errno : 0;
	fclose(fp);
	if (saved_errno)
		return -saved_errno;
	buf[got] = '\0';
	return (int)got;
}

static void set_unknown(struct ela_linux_audit_result *result, const char *path)
{
	result->status = ELA_LINUX_AUDIT_UNKNOWN;
	snprintf(result->evidence, sizeof(result->evidence), "unable to read %.430s", path);
}

static bool config_contains_option(const char *text, const char *expected)
{
	const char *line = text;
	size_t expected_len;

	if (!text || !expected)
		return false;
	expected_len = strlen(expected);
	while (line && *line) {
		const char *end = strchr(line, '\n');
		size_t len = end ? (size_t)(end - line) : strlen(line);
		while (len && isspace((unsigned char)*line)) {
			line++;
			len--;
		}
		if (len == expected_len && !strncmp(line, expected, expected_len))
			return true;
		if (!end)
			break;
		line = end + 1;
	}
	return false;
}

static int run_config_option(const struct ela_linux_audit_rule *rule, const char *root,
			     struct ela_linux_audit_result *result)
{
	char release[128] = { 0 };
	char path[1024];
	char config_path[1024];
	char text[65536];
	const char *candidates[4];
	char boot_candidate[1024];
	char module_candidate[1024];
	char proc_candidate[1024];
	int readable = 0;
	int n;
	size_t i;

	if (read_probe_file(root, "/proc/sys/kernel/osrelease", release, sizeof(release), path, sizeof(path)) > 0) {
		char *newline = strchr(release, '\n');
		if (newline)
			*newline = '\0';
	}
	if (!release[0]) {
		struct utsname uts;
		if (uname(&uts) == 0)
			snprintf(release, sizeof(release), "%s", uts.release);
	}
	snprintf(boot_candidate, sizeof(boot_candidate), "/boot/config-%s", release);
	snprintf(module_candidate, sizeof(module_candidate), "/usr/lib/modules/%s/config", release);
	snprintf(proc_candidate, sizeof(proc_candidate), "/proc/config");
	candidates[0] = boot_candidate;
	candidates[1] = module_candidate;
	candidates[2] = proc_candidate;
	candidates[3] = NULL;

	for (i = 0; candidates[i]; i++) {
		n = read_probe_file(root, candidates[i], text, sizeof(text), config_path, sizeof(config_path));
		if (n < 0)
			continue;
		readable = 1;
		if (config_contains_option(text, rule->expected)) {
			result->status = ELA_LINUX_AUDIT_PASS;
			snprintf(result->evidence, sizeof(result->evidence), "found %s in %.430s", rule->expected,
				 config_path);
			return 0;
		}
	}
	if (readable) {
		result->status = ELA_LINUX_AUDIT_FAIL;
		snprintf(result->evidence, sizeof(result->evidence),
			 "required option %s was not found in available kernel config", rule->expected);
	} else {
		set_unknown(result, rule->path);
	}
	return 0;
}

static int run_special_rule(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile,
			    const char *root, struct ela_linux_audit_result *result)
{
	char text[65536];
	char path[1024];
	int n;

	(void)profile;
	if (rule->check_type == ELA_LINUX_AUDIT_CHECK_CONFIG_OPTION)
		return run_config_option(rule, root, result);
	if (rule->check_type == ELA_LINUX_AUDIT_CHECK_DEVICE_MODE) {
		struct stat st;
		if (build_probe_path(root, rule->path, path, sizeof(path)) != 0)
			return -1;
		if (stat(path, &st) != 0) {
			if (errno == ENOENT) {
				result->status = ELA_LINUX_AUDIT_NOT_APPLICABLE;
				snprintf(result->evidence, sizeof(result->evidence), "%.480s is absent", path);
			} else {
				set_unknown(result, path);
			}
			return 0;
		}
		result->status = (st.st_mode & 0077) == 0 ? ELA_LINUX_AUDIT_PASS : ELA_LINUX_AUDIT_FAIL;
		snprintf(result->evidence, sizeof(result->evidence),
			 "%.420s mode=%04o; expected no group/other permissions", path, st.st_mode & 0777);
		return 0;
	}
	n = read_probe_file(root, rule->path, text, sizeof(text), path, sizeof(path));
	if (n < 0) {
		set_unknown(result, path);
		return 0;
	}

	switch (rule->check_type) {
	case ELA_LINUX_AUDIT_CHECK_CMDLINE_FORBIDDEN:
		result->status =
			(rule->expected && strstr(text, rule->expected)) ? ELA_LINUX_AUDIT_FAIL : ELA_LINUX_AUDIT_PASS;
		snprintf(result->evidence, sizeof(result->evidence), "cmdline%s forbidden token %s",
			 result->status == ELA_LINUX_AUDIT_FAIL ? " contains" : " does not contain",
			 rule->expected ? rule->expected : "");
		return 0;
	case ELA_LINUX_AUDIT_CHECK_LOCKDOWN:
		if (strstr(text, "[integrity]") || strstr(text, "[confidentiality]"))
			result->status = ELA_LINUX_AUDIT_PASS;
		else if (strstr(text, "[none]"))
			result->status = ELA_LINUX_AUDIT_FAIL;
		else
			result->status = ELA_LINUX_AUDIT_UNKNOWN;
		snprintf(result->evidence, sizeof(result->evidence), "lockdown state: %.430s", text);
		return 0;
	case ELA_LINUX_AUDIT_CHECK_LSM_ENFORCING: {
		char enforce[128];
		char enabled[128];
		char aux_path[1024];
		bool selinux = strstr(text, "selinux") != NULL;
		bool apparmor = strstr(text, "apparmor") != NULL;
		if (selinux &&
		    read_probe_file(root, "/sys/fs/selinux/enforce", enforce, sizeof(enforce), aux_path,
				    sizeof(aux_path)) > 0 &&
		    enforce[0] == '1') {
			result->status = ELA_LINUX_AUDIT_PASS;
		} else if (apparmor &&
			   read_probe_file(root, "/sys/module/apparmor/parameters/enabled", enabled, sizeof(enabled),
					   aux_path, sizeof(aux_path)) > 0 &&
			   (enabled[0] == 'Y' || enabled[0] == 'y')) {
			result->status = ELA_LINUX_AUDIT_PASS;
		} else if (selinux || apparmor || strstr(text, "smack")) {
			result->status = ELA_LINUX_AUDIT_FAIL;
		} else {
			result->status = ELA_LINUX_AUDIT_UNKNOWN;
		}
		snprintf(result->evidence, sizeof(result->evidence), "active LSMs: %.430s", text);
		return 0;
	}
	case ELA_LINUX_AUDIT_CHECK_MOUNT_ABSENT: {
		char source[256], mountpoint[256], fstype[128], options[512];
		const char *forbidden = rule->expected ? rule->expected : "debugfs";
		char *line = text;
		bool found = false;
		while (line && *line) {
			char *end = strchr(line, '\n');
			if (end)
				*end = '\0';
			if (sscanf(line, "%255s %255s %127s %511s", source, mountpoint, fstype, options) == 4 &&
			    !strcmp(fstype, forbidden))
				found = true;
			if (!end)
				break;
			line = end + 1;
		}
		result->status = found ? ELA_LINUX_AUDIT_FAIL : ELA_LINUX_AUDIT_PASS;
		snprintf(result->evidence, sizeof(result->evidence), "%s mount %s", forbidden,
			 found ? "present" : "absent");
		return 0;
	}
	case ELA_LINUX_AUDIT_CHECK_DEVICE_MODE:
		return -1;
	case ELA_LINUX_AUDIT_CHECK_CORE_PATTERN:
		result->status = text[0] == '|' ? ELA_LINUX_AUDIT_PASS
						: (text[0] == 'c' ? ELA_LINUX_AUDIT_FAIL : ELA_LINUX_AUDIT_UNKNOWN);
		snprintf(result->evidence, sizeof(result->evidence), "core_pattern=%.430s", text);
		return 0;
	default:
		return ela_linux_audit_evaluate(rule, profile, text, result);
	}
}

int ela_linux_audit_run_rule(const struct ela_linux_audit_rule *rule, enum ela_linux_audit_profile profile,
			     const char *root, struct ela_linux_audit_result *result)
{
	char path[1024];
	char value[128];
	const char *prefix = (root && strcmp(root, "/")) ? root : "";
	FILE *fp;
	int saved_errno;

	if (!rule || !result || !ela_linux_audit_rule_enabled(rule, profile))
		return -1;
	if (rule->check_type != ELA_LINUX_AUDIT_CHECK_INTEGER_MIN &&
	    rule->check_type != ELA_LINUX_AUDIT_CHECK_INTEGER_MAX)
		return run_special_rule(rule, profile, root, result);
	if (snprintf(path, sizeof(path), "%s%s", prefix, rule->path) >= (int)sizeof(path))
		return -1;

	fp = fopen(path, "r");
	if (!fp) {
		saved_errno = errno;
		result->status = ELA_LINUX_AUDIT_UNKNOWN;
		snprintf(result->evidence, sizeof(result->evidence), "unable to read %.400s: %.80s", path,
			 strerror(saved_errno));
		return 0;
	}
	if (!fgets(value, sizeof(value), fp)) {
		saved_errno = errno;
		fclose(fp);
		result->status = ELA_LINUX_AUDIT_UNKNOWN;
		snprintf(result->evidence, sizeof(result->evidence), "unable to read %.400s: %.80s", path,
			 saved_errno ? strerror(saved_errno) : "empty value");
		return 0;
	}
	fclose(fp);
	return ela_linux_audit_evaluate(rule, profile, value, result);
}

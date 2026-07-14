#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x9aa6980d, "mutex_lock" },
	{ 0x4f1e5fd0, "__list_del_entry_valid_or_report" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x9aa6980d, "mutex_unlock" },
	{ 0x8a3b1b6c, "register_mtd_user" },
	{ 0x4e804fe8, "misc_register" },
	{ 0x5324ea59, "unregister_mtd_user" },
	{ 0xe8213e80, "_printk" },
	{ 0x9479a1e8, "strnlen" },
	{ 0xfbe7861b, "memcpy" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xda44517b, "simple_strtol" },
	{ 0x63dfcf33, "get_mtd_device" },
	{ 0x0b75318f, "spi_bus_type" },
	{ 0xae2aab36, "put_mtd_device" },
	{ 0x782fe919, "bdev_file_open_by_dev" },
	{ 0x0cd7e023, "file_bdev" },
	{ 0x073a519b, "bdev_fput" },
	{ 0x2435d559, "strncmp" },
	{ 0xdaec6c5f, "usb_get_dev" },
	{ 0xe5c58151, "usb_hub_find_child" },
	{ 0x6852c1a0, "usb_put_dev" },
	{ 0x89bc945d, "usb_control_msg" },
	{ 0xe2c88a3c, "__netdev_alloc_skb" },
	{ 0xf51381e1, "skb_put" },
	{ 0x0e9cab28, "memset" },
	{ 0x5a844b26, "__x86_indirect_thunk_r12" },
	{ 0x66f7b997, "sk_skb_reason_drop" },
	{ 0x57db2cdf, "bus_for_each_dev" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xf3012780, "device_for_each_child" },
	{ 0x706acf9a, "usb_for_each_dev" },
	{ 0x2de0a194, "unregister_kprobe" },
	{ 0xf3d07ab4, "misc_deregister" },
	{ 0x5cb46e6d, "validate_usercopy_range" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0xcb5bc4b5, "memcpy_toio" },
	{ 0xacac6336, "memcpy_fromio" },
	{ 0xb1ad3f2f, "boot_cpu_data" },
	{ 0x7851be11, "__SCT__might_resched" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0x211f9d4e, "mem_section" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0xd272d446, "__SCT__preempt_schedule" },
	{ 0xdc352a3b, "__list_add_valid_or_report" },
	{ 0x1b60315e, "copy_from_kernel_nofault" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x02e1dca7, "free_pages" },
	{ 0xa200ecb1, "usb_lock_device_for_reset" },
	{ 0x38b88d7c, "usb_reset_device" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x35caf9af, "mtd_block_isbad" },
	{ 0x92239da3, "mtd_read" },
	{ 0x4b84e3a3, "pci_get_device" },
	{ 0xe7fba34d, "pci_map_rom" },
	{ 0x50f84f51, "pci_unmap_rom" },
	{ 0xf5bae445, "__virt_addr_valid" },
	{ 0x334e7b26, "memdup_user" },
	{ 0x5a844b26, "__x86_indirect_thunk_r10" },
	{ 0x2985858a, "__kvmalloc_node_noprof" },
	{ 0xf1de9e85, "kvfree" },
	{ 0x56d7bf45, "kernel_read" },
	{ 0x6bded543, "get_free_pages_noprof" },
	{ 0x67628f51, "msleep" },
	{ 0xb6377019, "register_kprobe" },
	{ 0xbd03ed67, "phys_base" },
	{ 0x82fd7238, "__ubsan_handle_shift_out_of_bounds" },
	{ 0xd272d446, "__fentry__" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x11f4259a, "_raw_spin_lock_irqsave" },
	{ 0x444885a7, "_raw_spin_unlock_irqrestore" },
	{ 0x0c161ddc, "capable" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0x5f878bdd, "kmalloc_caches" },
	{ 0x7a5d3ece, "__kmalloc_cache_noprof" },
	{ 0x9aa6980d, "mutex_init_generic" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x97dd6ca9, "ioremap" },
	{ 0xa442ce88, "iowrite16" },
	{ 0x12ad300e, "iounmap" },
	{ 0x7e2232fb, "ioread16" },
	{ 0x7e2232fb, "ioread8" },
	{ 0x01da6614, "iowrite8" },
	{ 0xfad8f384, "iowrite32" },
	{ 0x7e2232fb, "ioread32" },
	{ 0x95ac4947, "pci_get_domain_bus_and_slot" },
	{ 0xf4281837, "pci_write_config_byte" },
	{ 0x79a44b32, "pci_dev_put" },
	{ 0x212fdcc0, "pci_read_config_byte" },
	{ 0x2e7632b4, "pci_read_config_dword" },
	{ 0xa56d0c62, "pci_write_config_dword" },
	{ 0x268d8f4e, "pci_write_config_word" },
	{ 0xa5942dae, "pci_read_config_word" },
	{ 0xb0c84d61, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x9aa6980d,
	0x4f1e5fd0,
	0xcb8b6ec6,
	0x9aa6980d,
	0x8a3b1b6c,
	0x4e804fe8,
	0x5324ea59,
	0xe8213e80,
	0x9479a1e8,
	0xfbe7861b,
	0xe54e0a6b,
	0xda44517b,
	0x63dfcf33,
	0x0b75318f,
	0xae2aab36,
	0x782fe919,
	0x0cd7e023,
	0x073a519b,
	0x2435d559,
	0xdaec6c5f,
	0xe5c58151,
	0x6852c1a0,
	0x89bc945d,
	0xe2c88a3c,
	0xf51381e1,
	0x0e9cab28,
	0x5a844b26,
	0x66f7b997,
	0x57db2cdf,
	0xe4de56b4,
	0xf3012780,
	0x706acf9a,
	0x2de0a194,
	0xf3d07ab4,
	0x5cb46e6d,
	0xa61fd7aa,
	0xcb5bc4b5,
	0xacac6336,
	0xb1ad3f2f,
	0x7851be11,
	0xbd03ed67,
	0xbd03ed67,
	0x211f9d4e,
	0x7ec472ba,
	0xd272d446,
	0xdc352a3b,
	0x1b60315e,
	0x90a48d82,
	0x02e1dca7,
	0xa200ecb1,
	0x38b88d7c,
	0xd710adbf,
	0x35caf9af,
	0x92239da3,
	0x4b84e3a3,
	0xe7fba34d,
	0x50f84f51,
	0xf5bae445,
	0x334e7b26,
	0x5a844b26,
	0x2985858a,
	0xf1de9e85,
	0x56d7bf45,
	0x6bded543,
	0x67628f51,
	0xb6377019,
	0xbd03ed67,
	0x82fd7238,
	0xd272d446,
	0x5a844b26,
	0xd272d446,
	0x11f4259a,
	0x444885a7,
	0x0c161ddc,
	0xbd03ed67,
	0x5f878bdd,
	0x7a5d3ece,
	0x9aa6980d,
	0xbd03ed67,
	0x092a35a2,
	0x092a35a2,
	0xd272d446,
	0x97dd6ca9,
	0xa442ce88,
	0x12ad300e,
	0x7e2232fb,
	0x7e2232fb,
	0x01da6614,
	0xfad8f384,
	0x7e2232fb,
	0x95ac4947,
	0xf4281837,
	0x79a44b32,
	0x212fdcc0,
	0x2e7632b4,
	0xa56d0c62,
	0x268d8f4e,
	0xa5942dae,
	0xb0c84d61,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"mutex_lock\0"
	"__list_del_entry_valid_or_report\0"
	"kfree\0"
	"mutex_unlock\0"
	"register_mtd_user\0"
	"misc_register\0"
	"unregister_mtd_user\0"
	"_printk\0"
	"strnlen\0"
	"memcpy\0"
	"__fortify_panic\0"
	"simple_strtol\0"
	"get_mtd_device\0"
	"spi_bus_type\0"
	"put_mtd_device\0"
	"bdev_file_open_by_dev\0"
	"file_bdev\0"
	"bdev_fput\0"
	"strncmp\0"
	"usb_get_dev\0"
	"usb_hub_find_child\0"
	"usb_put_dev\0"
	"usb_control_msg\0"
	"__netdev_alloc_skb\0"
	"skb_put\0"
	"memset\0"
	"__x86_indirect_thunk_r12\0"
	"sk_skb_reason_drop\0"
	"bus_for_each_dev\0"
	"__ubsan_handle_load_invalid_value\0"
	"device_for_each_child\0"
	"usb_for_each_dev\0"
	"unregister_kprobe\0"
	"misc_deregister\0"
	"validate_usercopy_range\0"
	"__check_object_size\0"
	"memcpy_toio\0"
	"memcpy_fromio\0"
	"boot_cpu_data\0"
	"__SCT__might_resched\0"
	"vmemmap_base\0"
	"page_offset_base\0"
	"mem_section\0"
	"__preempt_count\0"
	"__SCT__preempt_schedule\0"
	"__list_add_valid_or_report\0"
	"copy_from_kernel_nofault\0"
	"__ubsan_handle_out_of_bounds\0"
	"free_pages\0"
	"usb_lock_device_for_reset\0"
	"usb_reset_device\0"
	"__kmalloc_noprof\0"
	"mtd_block_isbad\0"
	"mtd_read\0"
	"pci_get_device\0"
	"pci_map_rom\0"
	"pci_unmap_rom\0"
	"__virt_addr_valid\0"
	"memdup_user\0"
	"__x86_indirect_thunk_r10\0"
	"__kvmalloc_node_noprof\0"
	"kvfree\0"
	"kernel_read\0"
	"get_free_pages_noprof\0"
	"msleep\0"
	"register_kprobe\0"
	"phys_base\0"
	"__ubsan_handle_shift_out_of_bounds\0"
	"__fentry__\0"
	"__x86_indirect_thunk_rax\0"
	"__x86_return_thunk\0"
	"_raw_spin_lock_irqsave\0"
	"_raw_spin_unlock_irqrestore\0"
	"capable\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"mutex_init_generic\0"
	"__ref_stack_chk_guard\0"
	"_copy_from_user\0"
	"_copy_to_user\0"
	"__stack_chk_fail\0"
	"ioremap\0"
	"iowrite16\0"
	"iounmap\0"
	"ioread16\0"
	"ioread8\0"
	"iowrite8\0"
	"iowrite32\0"
	"ioread32\0"
	"pci_get_domain_bus_and_slot\0"
	"pci_write_config_byte\0"
	"pci_dev_put\0"
	"pci_read_config_byte\0"
	"pci_read_config_dword\0"
	"pci_write_config_dword\0"
	"pci_write_config_word\0"
	"pci_read_config_word\0"
	"module_layout\0"
;

MODULE_INFO(depends, "mtd");


MODULE_INFO(srcversion, "8FDE9481CDACCE8BE8B9889");

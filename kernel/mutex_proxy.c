// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-level Proxy Control (MUTEX_PROXY)
 * Syscall implementation for mutex_proxy_create
 *
 * Copyright (C) 2025 MUTEX Team
 */

#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex_proxy.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <uapi/linux/mutex_proxy.h>

/* Module parameters */
static bool debug_enabled = false;
module_param_named(debug, debug_enabled, bool, 0644);
MODULE_PARM_DESC(debug, "Enable debug logging (default: false)");

static unsigned int default_conn_table_size = 1024;
module_param_named(conn_table_size, default_conn_table_size, uint, 0444);
MODULE_PARM_DESC(conn_table_size, "Default connection table size (default: 1024)");

/* Logging macros */
#define mpx_debug(fmt, ...) \
	do { \
		if (debug_enabled) \
			pr_debug("mutex_proxy: " fmt, ##__VA_ARGS__); \
	} while (0)

#define mpx_info(fmt, ...) \
	pr_info("mutex_proxy: " fmt, ##__VA_ARGS__)

#define mpx_warn(fmt, ...) \
	pr_warn("mutex_proxy: " fmt, ##__VA_ARGS__)

#define mpx_err(fmt, ...) \
	pr_err("mutex_proxy: " fmt, ##__VA_ARGS__)

/* Forward declarations */
struct mutex_proxy_context;

/**
 * is_valid_proxy_config - Validate proxy configuration structure
 * @cfg: Configuration to validate
 *
 * Performs comprehensive validation of proxy configuration including:
 * - Version number (must be 1)
 * - Number of servers (1-8)
 * - Selection strategy (valid type)
 * - Per-server validation (type, port)
 *
 * Return: true if configuration is valid, false otherwise
 */
static bool is_valid_proxy_config(const struct mutex_proxy_config *cfg)
{
	unsigned int i;

	if (!cfg) {
		mpx_err("NULL config pointer\n");
		return false;
	}

	/* Check version */
	if (cfg->version != 1) {
		mpx_warn("unsupported config version %u (expected 1)\n",
			cfg->version);
		return false;
	}

	/* Validate at least one server is configured */
	if (cfg->num_servers == 0 || cfg->num_servers > MUTEX_PROXY_MAX_SERVERS) {
		mpx_warn("invalid num_servers %u (valid range: 1-%u)\n",
			cfg->num_servers, MUTEX_PROXY_MAX_SERVERS);
		return false;
	}

	/* Validate selection strategy */
	if (cfg->selection_strategy < PROXY_SELECT_ROUND_ROBIN ||
	    cfg->selection_strategy > PROXY_SELECT_RANDOM) {
		mpx_warn("invalid selection_strategy %u\n", cfg->selection_strategy);
		return false;
	}

	/* Validate each configured server */
	for (i = 0; i < cfg->num_servers; i++) {
		const struct mutex_proxy_server *srv = &cfg->servers[i];
		
		/* Validate proxy type */
		if (srv->proxy_type == 0 || srv->proxy_type > PROXY_TYPE_MAX) {
			mpx_warn("invalid proxy type %u for server %u\n",
				srv->proxy_type, i);
			return false;
		}

		/* Validate port number */
		if (srv->proxy_port == 0 || srv->proxy_port > 65535) {
			mpx_warn("invalid proxy port %u for server %u\n",
				srv->proxy_port, i);
			return false;
		}
	}

	return true;
}

/**
 * struct mutex_proxy_context - Per-fd proxy state
 * @config: Current proxy configuration
 * @stats: Connection and traffic statistics
 * @lock: Spinlock protecting config and stats
 * @enabled: Atomic flag indicating if proxy is active
 * @owner_pid: PID of the process that created this fd
 * @owner_uid: UID of the owner
 * @owner_gid: GID of the owner
 * @flags: Creation flags (CLOEXEC, NONBLOCK, GLOBAL)
 * @conn_table: Hash table of active connections
 * @conn_table_size: Size of the hash table
 * @wait: Wait queue for poll/select/epoll
 * @event_count: Event counter for notifications
 * @rcu: RCU head for safe destruction
 * @refcount: Reference count for the context
 */
struct mutex_proxy_context {
	struct mutex_proxy_config config;
	struct mutex_proxy_stats stats;
	spinlock_t lock;
	atomic_t enabled;

	pid_t owner_pid;
	kuid_t owner_uid;
	kgid_t owner_gid;
	unsigned int flags;

	/* Connection tracking */
	struct hlist_head *conn_table;
	unsigned int conn_table_size;

	/* Event notification support */
	wait_queue_head_t wait;		/* For poll/select/epoll */
	unsigned int event_count;	/* Event counter */

	struct rcu_head rcu;		/* For RCU-safe destruction */
	atomic_t refcount;		/* Reference counting */
};

/* Function prototypes */
static struct mutex_proxy_context *mutex_proxy_ctx_alloc(unsigned int flags);
static void mutex_proxy_ctx_put(struct mutex_proxy_context *ctx);
bool mutex_proxy_applies_to_current(struct mutex_proxy_context *ctx);
EXPORT_SYMBOL(mutex_proxy_applies_to_current);

/**
 * mutex_proxy_ctx_alloc - Allocate and initialize a new proxy context
 * @flags: Creation flags
 *
 * Return: Pointer to allocated context, or NULL on failure
 */
static struct mutex_proxy_context *mutex_proxy_ctx_alloc(unsigned int flags)
{
	struct mutex_proxy_context *ctx;
	unsigned int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		mpx_err("Failed to allocate context\n");
		return NULL;
	}

	/* Initialize spinlock */
	spin_lock_init(&ctx->lock);

	/* Initialize atomic flags and refcount */
	atomic_set(&ctx->enabled, 0);  /* Disabled by default */
	atomic_set(&ctx->refcount, 1);  /* Start with refcount 1 */

	/* Store owner credentials */
	ctx->owner_pid = current->pid;
	ctx->owner_uid = current_uid();
	ctx->owner_gid = current_gid();
	ctx->flags = flags;

	/* Initialize default configuration */
	ctx->config.version = 1;
	ctx->config.num_servers = 1;
	ctx->config.selection_strategy = PROXY_SELECT_ROUND_ROBIN;
	ctx->config.current_server = 0;
	
	/* Initialize first server with defaults */
	ctx->config.servers[0].proxy_type = PROXY_TYPE_SOCKS5;
	ctx->config.servers[0].proxy_port = 1080;
	ctx->config.servers[0].flags = PROXY_CONFIG_ACTIVE;
	ctx->config.servers[0].priority = 10;
	memset(ctx->config.servers[0].proxy_addr, 0, sizeof(ctx->config.servers[0].proxy_addr));
	memset(ctx->config.servers[0].username, 0, sizeof(ctx->config.servers[0].username));
	memset(ctx->config.servers[0].password, 0, sizeof(ctx->config.servers[0].password));
	memset(ctx->config.reserved, 0, sizeof(ctx->config.reserved));

	/* Initialize statistics */
	memset(&ctx->stats, 0, sizeof(ctx->stats));

	/* Allocate connection tracking hash table (use module parameter) */
	ctx->conn_table_size = default_conn_table_size;

	/* Validate conn_table_size to prevent overflow */
	if (ctx->conn_table_size > 65536) {
		mpx_err("conn_table_size %u exceeds maximum, using 65536\n",
			ctx->conn_table_size);
		ctx->conn_table_size = 65536;
	}

	if (ctx->conn_table_size == 0) {
		mpx_err("conn_table_size cannot be 0, using default 1024\n");
		ctx->conn_table_size = 1024;
	}

	ctx->conn_table = kcalloc(ctx->conn_table_size, sizeof(*ctx->conn_table),
				  GFP_KERNEL);
	if (!ctx->conn_table) {
		mpx_err("Failed to allocate connection table\n");
		kfree(ctx);
		return NULL;
	}

	/* Initialize hash table buckets */
	for (i = 0; i < ctx->conn_table_size; i++)
		INIT_HLIST_HEAD(&ctx->conn_table[i]);

	/* Initialize wait queue for poll() support */
	init_waitqueue_head(&ctx->wait);
	ctx->event_count = 0;

	mpx_debug("allocated context for PID %d (UID %u, GID %u, conn_table_size=%u)\n",
		  ctx->owner_pid, from_kuid(&init_user_ns, ctx->owner_uid),
		  from_kgid(&init_user_ns, ctx->owner_gid),
		  ctx->conn_table_size);

	return ctx;
}

/**
 * mutex_proxy_ctx_destroy_rcu - RCU callback to destroy context
 * @rcu: RCU head
 */
static void mutex_proxy_ctx_destroy_rcu(struct rcu_head *rcu)
{
	struct mutex_proxy_context *ctx;

	ctx = container_of(rcu, struct mutex_proxy_context, rcu);

	mpx_debug("destroying context for PID %d\n", ctx->owner_pid);

	/* Free connection table */
	kfree(ctx->conn_table);

	/* Free the context itself */
	kfree(ctx);
}

/**
 * mutex_proxy_ctx_put - Decrement reference count and free if zero
 * @ctx: Context to dereference
 */
static void mutex_proxy_ctx_put(struct mutex_proxy_context *ctx)
{
	if (atomic_dec_and_test(&ctx->refcount)) {
		/* Use RCU to safely free the context */
		call_rcu(&ctx->rcu, mutex_proxy_ctx_destroy_rcu);
	}
}

/**
 * mutex_proxy_read - Read statistics from proxy file descriptor
 * @file: File structure for the fd
 * @buf: User buffer to read data into
 * @count: Number of bytes to read
 * @ppos: File position
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t mutex_proxy_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_stats stats_copy;
	unsigned long flags;
	size_t to_copy;
	size_t offset;

	/* Validate file pointer */
	if (unlikely(!file)) {
		mpx_err("NULL file pointer in read()\n");
		return -EINVAL;
	}

	/* Validate context */
	if (unlikely(!ctx)) {
		mpx_err("NULL context in read()\n");
		return -EINVAL;
	}

	/* Validate user buffer pointer */
	if (unlikely(!buf)) {
		mpx_err("NULL buffer pointer in read()\n");
		return -EINVAL;
	}

	/* Validate position pointer */
	if (unlikely(!ppos)) {
		mpx_err("NULL position pointer in read()\n");
		return -EINVAL;
	}

	/* Check for integer overflow in position */
	if (unlikely(*ppos < 0)) {
		mpx_err("negative position %lld in read()\n", *ppos);
		return -EINVAL;
	}

	/* If already at EOF, return 0 */
	if (*ppos >= sizeof(struct mutex_proxy_stats))
		return 0;

	/* Validate count to prevent overflow */
	if (unlikely(count > INT_MAX)) {
		mpx_warn("read count %zu exceeds maximum\n", count);
		count = INT_MAX;
	}

	/* Copy stats under lock protection */
	spin_lock_irqsave(&ctx->lock, flags);
	memcpy(&stats_copy, &ctx->stats, sizeof(stats_copy));
	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Calculate how much to copy */
	offset = *ppos;
	to_copy = min(count, sizeof(stats_copy) - offset);

	/* Copy to userspace */
	if (copy_to_user(buf, ((char *)&stats_copy) + offset, to_copy))
		return -EFAULT;

	*ppos += to_copy;

	mpx_debug("read %zu bytes of statistics for PID %d\n",
		 to_copy, ctx->owner_pid);

	return to_copy;
}

/**
 * mutex_proxy_write - Write configuration to proxy file descriptor
 * @file: File structure for the fd
 * @buf: User buffer containing configuration data
 * @count: Number of bytes to write
 * @ppos: File position
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t mutex_proxy_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_config *new_config;
	unsigned long flags;
	ssize_t ret;

	/* Validate file pointer */
	if (unlikely(!file)) {
		mpx_err("NULL file pointer in write()\n");
		return -EINVAL;
	}

	/* Validate context */
	if (unlikely(!ctx)) {
		mpx_err("NULL context in write()\n");
		return -EINVAL;
	}

	/* Validate user buffer pointer */
	if (unlikely(!buf)) {
		mpx_err("NULL buffer pointer in write()\n");
		return -EINVAL;
	}

	/* Only accept writes of exact config structure size */
	if (count != sizeof(struct mutex_proxy_config)) {
		mpx_warn("invalid write size %zu (expected %zu)\n",
			count, sizeof(struct mutex_proxy_config));
		return -EINVAL;
	}

	/* Allocate config structure dynamically to avoid large stack frame */
	new_config = kmalloc(sizeof(*new_config), GFP_KERNEL);
	if (!new_config)
		return -ENOMEM;

	/* Copy config from userspace */
	if (copy_from_user(new_config, buf, sizeof(*new_config))) {
		ret = -EFAULT;
		goto out_free;
	}

	/* Validate configuration using helper */
	if (!is_valid_proxy_config(new_config)) {
		mpx_warn("configuration validation failed for PID %d\n",
			current->pid);
		ret = -EINVAL;
		goto out_free;
	}

	/* Update configuration atomically */
	spin_lock_irqsave(&ctx->lock, flags);
	memcpy(&ctx->config, new_config, sizeof(ctx->config));
	spin_unlock_irqrestore(&ctx->lock, flags);

	mpx_debug("updated config for PID %d (servers=%u, strategy=%u)\n",
		 ctx->owner_pid, new_config->num_servers, new_config->selection_strategy);

	ret = count;

out_free:
	kfree(new_config);
	return ret;
}

/**
 * mutex_proxy_ioctl - Handle ioctl commands for proxy file descriptor
 * @file: File structure for the fd
 * @cmd: ioctl command
 * @arg: ioctl argument
 *
 * Return: 0 on success, negative error code on failure
 */
static long mutex_proxy_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_config *config_copy;
	struct mutex_proxy_stats stats_copy;
	unsigned long flags;
	void __user *argp = (void __user *)arg;
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	switch (cmd) {
	case MUTEX_PROXY_IOC_ENABLE:
		/* Enable the proxy */
		atomic_set(&ctx->enabled, 1);
		mpx_debug("enabled proxy for PID %d\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_DISABLE:
		/* Disable the proxy */
		atomic_set(&ctx->enabled, 0);
		mpx_debug("disabled proxy for PID %d\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_SET_CONFIG:
		/* Set configuration via ioctl */
		if (!argp) {
			mpx_err("NULL argument in SET_CONFIG ioctl\n");
			return -EINVAL;
		}

		/* Allocate config structure dynamically */
		config_copy = kmalloc(sizeof(*config_copy), GFP_KERNEL);
		if (!config_copy)
			return -ENOMEM;

		if (copy_from_user(config_copy, argp, sizeof(*config_copy))) {
			kfree(config_copy);
			return -EFAULT;
		}

		/* Validate configuration using helper */
		if (!is_valid_proxy_config(config_copy)) {
			mpx_warn("SET_CONFIG validation failed for PID %d\n",
				current->pid);
			kfree(config_copy);
			return -EINVAL;
		}

		/* Update atomically */
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&ctx->config, config_copy, sizeof(ctx->config));
		spin_unlock_irqrestore(&ctx->lock, flags);

		kfree(config_copy);
		mpx_debug("set config for PID %d via ioctl\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_GET_CONFIG:
		/* Get current configuration */
		if (!argp) {
			mpx_err("NULL argument in GET_CONFIG ioctl\n");
			return -EINVAL;
		}

		/* Allocate config structure dynamically */
		config_copy = kmalloc(sizeof(*config_copy), GFP_KERNEL);
		if (!config_copy)
			return -ENOMEM;

		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(config_copy, &ctx->config, sizeof(*config_copy));
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (copy_to_user(argp, config_copy, sizeof(*config_copy)))
			ret = -EFAULT;

		kfree(config_copy);

		if (ret == 0)
			mpx_debug("get config for PID %d via ioctl\n",
				 ctx->owner_pid);
		return ret;

	case MUTEX_PROXY_IOC_GET_STATS:
		/* Get current statistics */
		if (!argp) {
			mpx_err("NULL argument in GET_STATS ioctl\n");
			return -EINVAL;
		}
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&stats_copy, &ctx->stats, sizeof(stats_copy));
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (copy_to_user(argp, &stats_copy, sizeof(stats_copy)))
			return -EFAULT;

		mpx_debug("get stats for PID %d via ioctl\n",
			 ctx->owner_pid);
		return 0;

	default:
		mpx_warn("unknown ioctl command 0x%x from PID %d\n",
			cmd, ctx->owner_pid);
		return -ENOTTY;
	}
}

/**
 * mutex_proxy_poll - poll handler for proxy file descriptor
 * @file: File structure for the fd
 * @wait: poll_table for registration
 *
 * Return: Poll event mask
 */
static __poll_t mutex_proxy_poll(struct file *file, poll_table *wait)
{
	struct mutex_proxy_context *ctx = file->private_data;
	__poll_t events = 0;

	if (!ctx)
		return POLLERR;

	/* Register with wait queue */
	poll_wait(file, &ctx->wait, wait);

	/* Always readable - stats are always available */
	events |= POLLIN | POLLRDNORM;

	/* Always writable - can always accept configuration */
	events |= POLLOUT | POLLWRNORM;

	/* Signal hangup if proxy is disabled */
	if (!atomic_read(&ctx->enabled))
		events |= POLLHUP;

	mpx_debug("poll() for PID %d, events=0x%x\n",
		 ctx->owner_pid, events);

	return events;
}

/**
 * mutex_proxy_release - Release handler for proxy file descriptor
 * @inode: Inode associated with the file
 * @file: File structure being released
 *
 * Handles proper cleanup when fd is closed. Respects O_CLOEXEC semantics:
 * - Without CLOEXEC: fd can be inherited by child processes (fork)
 * - With CLOEXEC: fd is closed on exec, proxy disabled
 *
 * Return: 0 on success
 */
static int mutex_proxy_release(struct inode *inode, struct file *file)
{
	struct mutex_proxy_context *ctx = file->private_data;

	if (!ctx)
		return 0;

	mpx_debug("releasing fd for PID %d (opened by PID %d)\n",
		 current->pid, ctx->owner_pid);

	/*
	 * Check if this is close-on-exec.
	 * For CLOEXEC fds, explicitly disable the proxy on close.
	 * For regular fds, children inherit the proxy state via fork.
	 * Reference counting ensures context stays alive as long as
	 * any process holds the fd.
	 */
	if (ctx->flags & MUTEX_PROXY_CLOEXEC) {
		mpx_debug("CLOEXEC set, disabling proxy on close\n");
		atomic_set(&ctx->enabled, 0);
	} else {
		/*
		 * For non-CLOEXEC fds, leave the proxy enabled.
		 * Children who inherited this fd will share the same
		 * proxy configuration and state.
		 */
		mpx_debug("fd inherited, maintaining proxy state\n");
	}

	/* Release our reference to the context */
	mutex_proxy_ctx_put(ctx);

	return 0;
}

/**
 * mutex_proxy_applies_to_current - Check if proxy applies to current process
 * @ctx: Proxy context to check
 *
 * Determines if the proxy configuration should apply to the current process.
 * This considers:
 * - Whether the proxy is enabled
 * - GLOBAL flag (applies to all system processes)
 * - fd inheritance (if we have the ctx, we have the fd)
 *
 * Return: true if proxy applies, false otherwise
 */
bool mutex_proxy_applies_to_current(struct mutex_proxy_context *ctx)
{
	if (!ctx || !atomic_read(&ctx->enabled))
		return false;

	/*
	 * GLOBAL flag: proxy applies to all processes system-wide.
	 * This is useful for system-level proxy configuration.
	 */
	if (ctx->flags & MUTEX_PROXY_GLOBAL) {
		mpx_debug("GLOBAL flag set, applies to all processes\n");
		return true;
	}

	/*
	 * Otherwise, proxy only applies to processes that have the fd.
	 * This includes:
	 * - The original owner (creator)
	 * - Children who inherited the fd via fork()
	 * - Processes that received the fd via Unix domain socket (SCM_RIGHTS)
	 *
	 * If we have access to the context, we have the fd.
	 */
	mpx_debug("proxy applies to PID %d (has fd)\n", current->pid);
	return true;
}

static const struct file_operations mutex_proxy_fops = {
	.owner		= THIS_MODULE,
	.release	= mutex_proxy_release,
	.read		= mutex_proxy_read,
	.write		= mutex_proxy_write,
	.unlocked_ioctl	= mutex_proxy_ioctl,
	.compat_ioctl	= mutex_proxy_ioctl,
	.poll		= mutex_proxy_poll,
	.llseek		= noop_llseek,
};

/**
 * mutex_proxy_create_fd - Create file descriptor with anonymous inode
 * @ctx: Proxy context to associate with the fd
 * @flags: Creation flags
 *
 * Return: File descriptor number on success, negative error code on failure
 */
static int mutex_proxy_create_fd(struct mutex_proxy_context *ctx,
				  unsigned int flags)
{
	int fd;
	int o_flags = O_RDWR;

	/* Convert mutex_proxy flags to file flags */
	if (flags & MUTEX_PROXY_CLOEXEC)
		o_flags |= O_CLOEXEC;
	if (flags & MUTEX_PROXY_NONBLOCK)
		o_flags |= O_NONBLOCK;

	/* Create anonymous inode with our file operations */
	fd = anon_inode_getfd("[mutex_proxy]", &mutex_proxy_fops, ctx, o_flags);
	if (fd < 0) {
		mpx_err("Failed to create anon_inode fd: %d\n", fd);
		return fd;
	}

	mpx_debug("created fd %d for PID %d\n", fd, ctx->owner_pid);

	return fd;
}

/**
 * sys_mutex_proxy_create - Create a new proxy control file descriptor
 * @flags: Creation flags (MUTEX_PROXY_CLOEXEC, MUTEX_PROXY_NONBLOCK, etc.)
 *
 * This syscall creates a file descriptor that can be used to control
 * kernel-level proxy behavior. It requires CAP_NET_ADMIN capability.
 *
 * Return: File descriptor on success, negative error code on failure
 */
SYSCALL_DEFINE1(mprox_create, unsigned int, flags)
{
	struct mutex_proxy_context *ctx;
	int fd;

	/* Check for CAP_NET_ADMIN capability */
	if (!capable(CAP_NET_ADMIN)) {
		mpx_warn("Process %d (%s) lacks CAP_NET_ADMIN\n",
			current->pid, current->comm);
		return -EPERM;
	}

	/* Validate flags */
	if (flags & ~MUTEX_PROXY_ALL_FLAGS) {
		mpx_warn("Invalid flags 0x%x from process %d\n",
			flags, current->pid);
		return -EINVAL;
	}

	/* Allocate and initialize proxy context */
	ctx = mutex_proxy_ctx_alloc(flags);
	if (!ctx) {
		mpx_err("Failed to allocate context for process %d\n",
		       current->pid);
		return -ENOMEM;
	}

	/* Create file descriptor with anonymous inode */
	fd = mutex_proxy_create_fd(ctx, flags);
	if (fd < 0) {
		mpx_err("Failed to create fd for process %d: %d\n",
		       current->pid, fd);
		/* Release the context reference */
		mutex_proxy_ctx_put(ctx);
		return fd;
	}

	mpx_info("Created fd %d for process %d (%s) with flags 0x%x\n",
		fd, current->pid, current->comm, flags);

	return fd;
}

/**
 * mutex_proxy_init - Module initialization
 *
 * Called when the module is loaded into the kernel.
 * Performs any necessary one-time setup and parameter validation.
 *
 * Return: 0 on success, negative error code on failure
 */
static int __init mutex_proxy_init(void)
{
	mpx_info("initializing mutex_proxy kernel module\n");
	mpx_info("debug logging: %s\n", debug_enabled ? "enabled" : "disabled");
	mpx_info("default conn_table_size: %u\n", default_conn_table_size);

	/* Validate module parameters */
	if (default_conn_table_size == 0) {
		mpx_warn("conn_table_size cannot be 0, using default 1024\n");
		default_conn_table_size = 1024;
	}

	if (default_conn_table_size > 65536) {
		mpx_warn("conn_table_size %u exceeds maximum, capping at 65536\n",
			 default_conn_table_size);
		default_conn_table_size = 65536;
	}

	mpx_info("mutex_proxy module loaded successfully\n");
	return 0;
}

/**
 * mutex_proxy_exit - Module cleanup
 *
 * Called when the module is unloaded from the kernel.
 * Note: Active file descriptors will keep their contexts alive
 * via reference counting. Contexts are freed via RCU when all
 * references are dropped (all fds closed).
 */
static void __exit mutex_proxy_exit(void)
{
	mpx_info("unloading mutex_proxy module\n");
	mpx_info("note: active fds will remain valid until closed\n");
	mpx_info("contexts will be freed via RCU when all references drop\n");
	mpx_info("mutex_proxy module unloaded\n");
}

module_init(mutex_proxy_init);
module_exit(mutex_proxy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Team <mutex@example.com>");
MODULE_DESCRIPTION("Kernel-level proxy control via file descriptor");
MODULE_VERSION("0.1.0");

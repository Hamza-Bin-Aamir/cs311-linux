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
#include <linux/mutex_proxy.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <uapi/linux/mutex_proxy.h>

/* Forward declarations */
struct mutex_proxy_context;

/**
 * is_valid_proxy_config - Validate proxy configuration structure
 * @cfg: Configuration to validate
 *
 * Performs comprehensive validation of proxy configuration including:
 * - Version number (must be 1)
 * - Proxy type (must be 1-3)
 * - Port number (must be 1-65535)
 * - Address validation (at least one byte must be non-zero)
 *
 * Return: true if configuration is valid, false otherwise
 */
static bool is_valid_proxy_config(const struct mutex_proxy_config *cfg)
{
	unsigned int i;
	bool addr_set = false;

	if (!cfg) {
		pr_err("mutex_proxy: NULL config pointer\n");
		return false;
	}

	/* Check version */
	if (cfg->version != 1) {
		pr_warn("mutex_proxy: unsupported config version %u (expected 1)\n",
			cfg->version);
		return false;
	}

	/* Validate proxy type */
	if (cfg->proxy_type < 1 || cfg->proxy_type > PROXY_TYPE_MAX) {
		pr_warn("mutex_proxy: invalid proxy type %u (valid range: 1-%u)\n",
			cfg->proxy_type, PROXY_TYPE_MAX);
		return false;
	}

	/* Validate port number (1-65535, 0 is reserved) */
	if (cfg->proxy_port == 0 || cfg->proxy_port > 65535) {
		pr_warn("mutex_proxy: invalid proxy port %u (valid range: 1-65535)\n",
			cfg->proxy_port);
		return false;
	}

	/* Check if proxy address is set (at least one byte non-zero) */
	for (i = 0; i < ARRAY_SIZE(cfg->proxy_addr); i++) {
		if (cfg->proxy_addr[i] != 0) {
			addr_set = true;
			break;
		}
	}

	if (!addr_set) {
		pr_warn("mutex_proxy: proxy address not set (all zeros)\n");
		return false;
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
static void mutex_proxy_ctx_get(struct mutex_proxy_context *ctx);
static void mutex_proxy_ctx_put(struct mutex_proxy_context *ctx);

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
		pr_err("mutex_proxy: Failed to allocate context\n");
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
	ctx->config.proxy_type = PROXY_TYPE_SOCKS5;
	ctx->config.proxy_port = 1080;
	ctx->config.flags = 0;
	memset(ctx->config.proxy_addr, 0, sizeof(ctx->config.proxy_addr));
	memset(ctx->config.reserved, 0, sizeof(ctx->config.reserved));

	/* Initialize statistics */
	memset(&ctx->stats, 0, sizeof(ctx->stats));

	/* Allocate connection tracking hash table (1024 buckets) */
	ctx->conn_table_size = 1024;

	/* Validate conn_table_size to prevent overflow */
	if (ctx->conn_table_size > 65536) {
		pr_err("mutex_proxy: conn_table_size %u exceeds maximum\n",
		       ctx->conn_table_size);
		kfree(ctx);
		return NULL;
	}

	ctx->conn_table = kcalloc(ctx->conn_table_size, sizeof(*ctx->conn_table),
				  GFP_KERNEL);
	if (!ctx->conn_table) {
		pr_err("mutex_proxy: Failed to allocate connection table\n");
		kfree(ctx);
		return NULL;
	}

	/* Initialize hash table buckets */
	for (i = 0; i < ctx->conn_table_size; i++)
		INIT_HLIST_HEAD(&ctx->conn_table[i]);

	/* Initialize wait queue for poll() support */
	init_waitqueue_head(&ctx->wait);
	ctx->event_count = 0;

	pr_debug("mutex_proxy: allocated context for PID %d (UID %u, GID %u)\n",
		 ctx->owner_pid, from_kuid(&init_user_ns, ctx->owner_uid),
		 from_kgid(&init_user_ns, ctx->owner_gid));

	return ctx;
}

/**
 * mutex_proxy_ctx_get - Increment reference count
 * @ctx: Context to reference
 */
static void mutex_proxy_ctx_get(struct mutex_proxy_context *ctx)
{
	atomic_inc(&ctx->refcount);
}

/**
 * mutex_proxy_ctx_destroy_rcu - RCU callback to destroy context
 * @rcu: RCU head
 */
static void mutex_proxy_ctx_destroy_rcu(struct rcu_head *rcu)
{
	struct mutex_proxy_context *ctx;

	ctx = container_of(rcu, struct mutex_proxy_context, rcu);

	pr_debug("mutex_proxy: destroying context for PID %d\n", ctx->owner_pid);

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
		pr_err("mutex_proxy: NULL file pointer in read()\n");
		return -EINVAL;
	}

	/* Validate context */
	if (unlikely(!ctx)) {
		pr_err("mutex_proxy: NULL context in read()\n");
		return -EINVAL;
	}

	/* Validate user buffer pointer */
	if (unlikely(!buf)) {
		pr_err("mutex_proxy: NULL buffer pointer in read()\n");
		return -EINVAL;
	}

	/* Validate position pointer */
	if (unlikely(!ppos)) {
		pr_err("mutex_proxy: NULL position pointer in read()\n");
		return -EINVAL;
	}

	/* Check for integer overflow in position */
	if (unlikely(*ppos < 0)) {
		pr_err("mutex_proxy: negative position %lld in read()\n", *ppos);
		return -EINVAL;
	}

	/* If already at EOF, return 0 */
	if (*ppos >= sizeof(struct mutex_proxy_stats))
		return 0;

	/* Validate count to prevent overflow */
	if (unlikely(count > INT_MAX)) {
		pr_warn("mutex_proxy: read count %zu exceeds maximum\n", count);
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

	pr_debug("mutex_proxy: read %zu bytes of statistics for PID %d\n",
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
	struct mutex_proxy_config new_config;
	unsigned long flags;

	/* Validate file pointer */
	if (unlikely(!file)) {
		pr_err("mutex_proxy: NULL file pointer in write()\n");
		return -EINVAL;
	}

	/* Validate context */
	if (unlikely(!ctx)) {
		pr_err("mutex_proxy: NULL context in write()\n");
		return -EINVAL;
	}

	/* Validate user buffer pointer */
	if (unlikely(!buf)) {
		pr_err("mutex_proxy: NULL buffer pointer in write()\n");
		return -EINVAL;
	}

	/* Only accept writes of exact config structure size */
	if (count != sizeof(struct mutex_proxy_config)) {
		pr_warn("mutex_proxy: invalid write size %zu (expected %zu)\n",
			count, sizeof(struct mutex_proxy_config));
		return -EINVAL;
	}

	/* Copy config from userspace */
	if (copy_from_user(&new_config, buf, sizeof(new_config)))
		return -EFAULT;

	/* Validate configuration using helper */
	if (!is_valid_proxy_config(&new_config)) {
		pr_warn("mutex_proxy: configuration validation failed for PID %d\n",
			current->pid);
		return -EINVAL;
	}

	/* Update configuration atomically */
	spin_lock_irqsave(&ctx->lock, flags);
	memcpy(&ctx->config, &new_config, sizeof(ctx->config));
	spin_unlock_irqrestore(&ctx->lock, flags);

	pr_debug("mutex_proxy: updated config for PID %d (type=%u, port=%u)\n",
		 ctx->owner_pid, new_config.proxy_type, new_config.proxy_port);

	return count;
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
	struct mutex_proxy_config config_copy;
	struct mutex_proxy_stats stats_copy;
	unsigned long flags;
	void __user *argp = (void __user *)arg;

	if (!ctx)
		return -EINVAL;

	switch (cmd) {
	case MUTEX_PROXY_IOC_ENABLE:
		/* Enable the proxy */
		atomic_set(&ctx->enabled, 1);
		pr_debug("mutex_proxy: enabled proxy for PID %d\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_DISABLE:
		/* Disable the proxy */
		atomic_set(&ctx->enabled, 0);
		pr_debug("mutex_proxy: disabled proxy for PID %d\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_SET_CONFIG:
		/* Set configuration via ioctl */
		if (!argp) {
			pr_err("mutex_proxy: NULL argument in SET_CONFIG ioctl\n");
			return -EINVAL;
		}

		if (copy_from_user(&config_copy, argp, sizeof(config_copy)))
			return -EFAULT;

		/* Validate configuration using helper */
		if (!is_valid_proxy_config(&config_copy)) {
			pr_warn("mutex_proxy: SET_CONFIG validation failed for PID %d\n",
				current->pid);
			return -EINVAL;
		}

		/* Update atomically */
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&ctx->config, &config_copy, sizeof(ctx->config));
		spin_unlock_irqrestore(&ctx->lock, flags);

		pr_debug("mutex_proxy: set config for PID %d via ioctl\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_GET_CONFIG:
		/* Get current configuration */
		if (!argp) {
			pr_err("mutex_proxy: NULL argument in GET_CONFIG ioctl\n");
			return -EINVAL;
		}

		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&config_copy, &ctx->config, sizeof(config_copy));
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (copy_to_user(argp, &config_copy, sizeof(config_copy)))
			return -EFAULT;

		pr_debug("mutex_proxy: get config for PID %d via ioctl\n",
			 ctx->owner_pid);
		return 0;

	case MUTEX_PROXY_IOC_GET_STATS:
		/* Get current statistics */
		if (!argp) {
			pr_err("mutex_proxy: NULL argument in GET_STATS ioctl\n");
			return -EINVAL;
		}
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&stats_copy, &ctx->stats, sizeof(stats_copy));
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (copy_to_user(argp, &stats_copy, sizeof(stats_copy)))
			return -EFAULT;

		pr_debug("mutex_proxy: get stats for PID %d via ioctl\n",
			 ctx->owner_pid);
		return 0;

	default:
		pr_warn("mutex_proxy: unknown ioctl command 0x%x from PID %d\n",
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

	pr_debug("mutex_proxy: poll() for PID %d, events=0x%x\n",
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

	pr_debug("mutex_proxy: releasing fd for PID %d (opened by PID %d)\n",
		 current->pid, ctx->owner_pid);

	/*
	 * Check if this is close-on-exec.
	 * For CLOEXEC fds, explicitly disable the proxy on close.
	 * For regular fds, children inherit the proxy state via fork.
	 * Reference counting ensures context stays alive as long as
	 * any process holds the fd.
	 */
	if (ctx->flags & MUTEX_PROXY_CLOEXEC) {
		pr_debug("mutex_proxy: CLOEXEC set, disabling proxy on close\n");
		atomic_set(&ctx->enabled, 0);
	} else {
		/*
		 * For non-CLOEXEC fds, leave the proxy enabled.
		 * Children who inherited this fd will share the same
		 * proxy configuration and state.
		 */
		pr_debug("mutex_proxy: fd inherited, maintaining proxy state\n");
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
		pr_debug("mutex_proxy: GLOBAL flag set, applies to all processes\n");
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
	pr_debug("mutex_proxy: proxy applies to PID %d (has fd)\n", current->pid);
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
		pr_err("mutex_proxy: Failed to create anon_inode fd: %d\n", fd);
		return fd;
	}

	pr_debug("mutex_proxy: created fd %d for PID %d\n", fd, ctx->owner_pid);

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
SYSCALL_DEFINE1(mutex_proxy_create, unsigned int, flags)
{
	struct mutex_proxy_context *ctx;
	int fd;

	/* Check for CAP_NET_ADMIN capability */
	if (!capable(CAP_NET_ADMIN)) {
		pr_warn("mutex_proxy: Process %d (%s) lacks CAP_NET_ADMIN\n",
			current->pid, current->comm);
		return -EPERM;
	}

	/* Validate flags */
	if (flags & ~MUTEX_PROXY_ALL_FLAGS) {
		pr_warn("mutex_proxy: Invalid flags 0x%x from process %d\n",
			flags, current->pid);
		return -EINVAL;
	}

	/* Allocate and initialize proxy context */
	ctx = mutex_proxy_ctx_alloc(flags);
	if (!ctx) {
		pr_err("mutex_proxy: Failed to allocate context for process %d\n",
		       current->pid);
		return -ENOMEM;
	}

	/* Create file descriptor with anonymous inode */
	fd = mutex_proxy_create_fd(ctx, flags);
	if (fd < 0) {
		pr_err("mutex_proxy: Failed to create fd for process %d: %d\n",
		       current->pid, fd);
		/* Release the context reference */
		mutex_proxy_ctx_put(ctx);
		return fd;
	}

	pr_info("mutex_proxy: Created fd %d for process %d (%s) with flags 0x%x\n",
		fd, current->pid, current->comm, flags);

	return fd;
}

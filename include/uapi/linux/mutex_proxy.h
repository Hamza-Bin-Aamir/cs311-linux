/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * mutex_proxy.h - MUTEX kernel-level proxy UAPI header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This header defines the userspace-visible API for the MUTEX proxy
 * file descriptor interface. It can be included by userspace programs.
 */

#ifndef _UAPI_LINUX_MUTEX_PROXY_H
#define _UAPI_LINUX_MUTEX_PROXY_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* Flags for mutex_proxy_create() syscall */
#define MUTEX_PROXY_CLOEXEC	(1 << 0)  /* Set close-on-exec */
#define MUTEX_PROXY_NONBLOCK	(1 << 1)  /* Set O_NONBLOCK */
#define MUTEX_PROXY_GLOBAL	(1 << 2)  /* Global proxy (all processes) */

#define MUTEX_PROXY_ALL_FLAGS	(MUTEX_PROXY_CLOEXEC | \
				 MUTEX_PROXY_NONBLOCK | \
				 MUTEX_PROXY_GLOBAL)

/* ioctl commands */
#define MUTEX_PROXY_IOC_MAGIC	'M'

#define MUTEX_PROXY_IOC_ENABLE		_IO(MUTEX_PROXY_IOC_MAGIC, 1)
#define MUTEX_PROXY_IOC_DISABLE		_IO(MUTEX_PROXY_IOC_MAGIC, 2)
#define MUTEX_PROXY_IOC_SET_CONFIG	_IOW(MUTEX_PROXY_IOC_MAGIC, 3, struct mutex_proxy_config)
#define MUTEX_PROXY_IOC_GET_CONFIG	_IOR(MUTEX_PROXY_IOC_MAGIC, 4, struct mutex_proxy_config)
#define MUTEX_PROXY_IOC_GET_STATS	_IOR(MUTEX_PROXY_IOC_MAGIC, 5, struct mutex_proxy_stats)

/* Proxy types */
#define PROXY_TYPE_SOCKS5	1
#define PROXY_TYPE_HTTP		2
#define PROXY_TYPE_HTTPS	3
#define PROXY_TYPE_MAX		3

/* Maximum number of proxy servers per configuration */
#define MUTEX_PROXY_MAX_SERVERS	8

/* Proxy selection strategies */
#define PROXY_SELECT_ROUND_ROBIN	1
#define PROXY_SELECT_FAILOVER		2
#define PROXY_SELECT_RANDOM		3

/* Server configuration flags */
#define PROXY_CONFIG_IPV6		(1 << 0)	/* Server uses IPv6 */
#define PROXY_CONFIG_ACTIVE		(1 << 1)	/* Server is active */
#define PROXY_CONFIG_AUTH		(1 << 2)	/* Authentication required */

/* Proxy server configuration */
struct mutex_proxy_server {
	__u32 proxy_type;		/* SOCKS5, HTTP, etc. */
	__u32 proxy_port;		/* Proxy server port */
	__u32 flags;			/* PROXY_CONFIG_* flags */
	__u32 priority;			/* Priority for failover (lower = higher priority) */
	__u8  proxy_addr[16];		/* IPv4/IPv6 address */
	__u8  username[64];		/* Authentication username */
	__u8  password[64];		/* Authentication password */
	__u8  reserved[32];		/* Reserved for future use */
};

/* Configuration structure for proxy settings (multi-server support) */
struct mutex_proxy_config {
	__u32 version;			/* API version, currently 1 */
	__u32 num_servers;		/* Number of configured servers */
	__u32 selection_strategy;	/* PROXY_SELECT_* */
	__u32 current_server;		/* Currently selected server index */
	struct mutex_proxy_server servers[MUTEX_PROXY_MAX_SERVERS];
	__u8  reserved[64];		/* Reserved for future use */
};

/* Statistics structure for proxy monitoring */
struct mutex_proxy_stats {
	__u64 bytes_sent;		/* Total bytes sent through proxy */
	__u64 bytes_received;		/* Total bytes received from proxy */
	__u64 packets_sent;		/* Total packets sent */
	__u64 packets_received;		/* Total packets received */
	__u64 connections_active;	/* Currently active connections */
	__u64 connections_total;	/* Total connections since creation */
};

#endif /* _UAPI_LINUX_MUTEX_PROXY_H */

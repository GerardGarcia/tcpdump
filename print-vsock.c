/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>
#include <stddef.h>

#include "netdissect.h"
#include "extract.h"

static const char tstr[] = " [|vsock]";

enum af_vsockmon_type {
	AF_VSOCK_GENERIC = 1,
    AF_VSOCK_VIRTIO = 2,
};

static const struct tok vsock_type[] = {
    {AF_VSOCK_GENERIC, "GENERIC"},
    {AF_VSOCK_VIRTIO, "VIRTIO"},
	{ 0, NULL }
};


enum af_vsockmon_g_ops {
	AF_VSOCK_G_OP_UNKNOWN = 0,
	AF_VSOCK_G_OP_CONNECT = 1,
	AF_VSOCK_G_OP_DISCONNECT = 2,
	AF_VSOCK_G_OP_CONTROL = 3,
	AF_VSOCK_G_OP_PAYLOAD = 4,
};

static const struct tok vsock_op[] = {
    {AF_VSOCK_G_OP_UNKNOWN, "UNKNOWN"},
    {AF_VSOCK_G_OP_CONNECT, "CONNECT"},
    {AF_VSOCK_G_OP_DISCONNECT, "DISCONNECT"},
    {AF_VSOCK_G_OP_CONTROL, "CONTROL"},
    {AF_VSOCK_G_OP_PAYLOAD, "PAYLOAD"},
	{ 0, NULL }
};


// CPU-endian
struct af_vsockmon_g {
	uint16_t op; /* enum af_vsock_g_ops */
	uint32_t src_cid;
	uint32_t src_port;
	uint32_t dst_cid;
	uint32_t dst_port;
};

enum virtio_vsock_type {
	VIRTIO_VSOCK_TYPE_STREAM = 1,
};

static const struct tok virtio_type[] = {
    {VIRTIO_VSOCK_TYPE_STREAM, "STREAM"},
	{ 0, NULL }
};

enum virtio_vsock_op {
	VIRTIO_VSOCK_OP_INVALID = 0,
	VIRTIO_VSOCK_OP_REQUEST = 1,
	VIRTIO_VSOCK_OP_RESPONSE = 2,
	VIRTIO_VSOCK_OP_RST = 3,
	VIRTIO_VSOCK_OP_SHUTDOWN = 4,
	VIRTIO_VSOCK_OP_RW = 5,
	VIRTIO_VSOCK_OP_CREDIT_UPDATE = 6,
	VIRTIO_VSOCK_OP_CREDIT_REQUEST = 7,
};

static const struct tok virtio_op[] = {
    {VIRTIO_VSOCK_OP_INVALID, "INVALID"},
    {VIRTIO_VSOCK_OP_REQUEST, "REQUEST"},
    {VIRTIO_VSOCK_OP_RESPONSE, "RESPNOSE"},
    {VIRTIO_VSOCK_OP_RST, "RST"},
    {VIRTIO_VSOCK_OP_SHUTDOWN, "SHUTDOWN"},
    {VIRTIO_VSOCK_OP_RW, "RW"},
    {VIRTIO_VSOCK_OP_CREDIT_UPDATE, "CREDIT UPDATE"},
    {VIRTIO_VSOCK_OP_CREDIT_REQUEST, "CREDIT REQUEST"},
	{ 0, NULL }
};

// Little-endian
struct virtio_vsock_hdr {
	uint64_t	src_cid;
	uint64_t	dst_cid;
	uint32_t	src_port;
	uint32_t	dst_port;
	uint32_t	len;
	uint16_t	type;		/* enum virtio_vsock_type */
	uint16_t	op;		/* enum virtio_vsock_op */
	uint32_t	flags;
	uint32_t	buf_alloc;
	uint32_t	fwd_cnt;
};

struct af_vsockmon_hdr {
	uint16_t type;  /* enum af_vosck_type */
	struct af_vsockmon_g g_hdr;
	union {
		struct virtio_vsock_hdr virtio_hdr;
	} t_hdr;
};

static void
vsock_virtio_hdr_print(netdissect_options *ndo, const struct virtio_vsock_hdr *hdr)
{
    uint16_t u16_v;
    uint32_t u32_v;

    u32_v = EXTRACT_LE_32BITS(&hdr->len);
    ND_PRINT((ndo, "len %u", u32_v));

    u16_v = EXTRACT_LE_16BITS(&hdr->type);
    ND_PRINT((ndo, ", type %s", tok2str(virtio_type, "Invalid type (%hu)", u16_v)));

    u16_v = EXTRACT_LE_16BITS(&hdr->op);
    ND_PRINT((ndo, ", op %s", tok2str(virtio_op, "Invalid op (%hu)", u16_v)));

    u32_v = EXTRACT_LE_32BITS(&hdr->flags);
    ND_PRINT((ndo, ", flags %x", u32_v));

    u32_v = EXTRACT_LE_32BITS(&hdr->buf_alloc);
    ND_PRINT((ndo, ", buf_alloc %u", u32_v));

    u32_v = EXTRACT_LE_32BITS(&hdr->fwd_cnt);
    ND_PRINT((ndo, ", fwd_cnt %u", u32_v));

}


static void
vsock_hdr_print(netdissect_options *ndo, const u_char *p, const u_int len)
{

    const struct af_vsockmon_hdr *hdr = (struct af_vsockmon_hdr *) p;
    const struct af_vsockmon_g *g_hdr = &hdr->g_hdr;
    const struct virtio_vsock_hdr *virtio_hdr;
    const u_char *payload;

	ND_PRINT((ndo, "%s", tok2str(vsock_type, "Invalid type (%u)", hdr->type)));

    /* If verbose level is more than 0 print
     * transport details */
    if (ndo->ndo_vflag) {
        switch (hdr->type) {
            case AF_VSOCK_VIRTIO:
                ND_PRINT((ndo, " ("));
                vsock_virtio_hdr_print(ndo, &hdr->t_hdr.virtio_hdr);
                ND_PRINT((ndo, ")"));
                break;
            default:
                break;
        }

        ND_PRINT((ndo, "\n\t"));
    } else {
        ND_PRINT((ndo, " "));
    }

    ND_PRINT((ndo, "%u.%hu > %u.%hu %s, length %u",
                g_hdr->src_cid, g_hdr->src_port,
                g_hdr->dst_cid, g_hdr->dst_port,
	            tok2str(vsock_op, " invalid op (%u)", g_hdr->op),
                len));

    /* If debug level is more than 1 print payload contents */
    if (ndo->ndo_vflag > 1 &&
            g_hdr->op == AF_VSOCK_G_OP_PAYLOAD &&
            len > sizeof(struct af_vsockmon_hdr)) {
        ND_PRINT((ndo, "\n"));
        payload = p + sizeof(struct af_vsockmon_hdr);
        print_unknown_data(ndo, payload, "\t", len - sizeof(struct af_vsockmon_hdr));
    }
}

u_int
vsock_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *cp)
{
    u_int len = h->len;

    if (len < sizeof(struct af_vsockmon_hdr)) {
        ND_PRINT((ndo, "%s", tstr));
    } else {
        vsock_hdr_print(ndo, cp, len);
    }

    return len;
}

/*
 * wfp.c — Windows Filtering Platform LAN-only setup.
 *
 * Installs filters at the ALE auth-connect / auth-recv-accept layers that
 * permit only RFC1918 + link-local destinations (so the printer on the LAN
 * works) and block everything else, including DNS to non-LAN resolvers.
 * No callouts — we rely on built-in FWP_ACTION_PERMIT / FWP_ACTION_BLOCK
 * with FWPM_CONDITION_IP_REMOTE_ADDRESS conditions.
 */

#include "lockguard.h"

// Sublayer + filter GUIDs (generated; stable for this driver's lifetime).
// {3b2c0e9e-9f48-4f6e-9c7d-1a1f9d4c2c10}
DEFINE_GUID(LG_SUBLAYER_GUID,
    0x3b2c0e9e, 0x9f48, 0x4f6e, 0x9c, 0x7d, 0x1a, 0x1f, 0x9d, 0x4c, 0x2c, 0x10);

static HANDLE  gEngine = NULL;
static UINT64  gFilterIds[32];
static ULONG   gFilterCount = 0;

#define ADD_FILTER_ID(id) do { gFilterIds[gFilterCount++] = (id); } while (0)

// Convert a /CIDR pair into an FWP_V4_ADDR_AND_MASK.
static VOID LgMakeMask(FWP_V4_ADDR_AND_MASK* out, UINT32 net, UINT32 mask)
{
    out->addr = net;
    out->mask = mask;
}

// Add a single ALE filter with up to two conditions and an explicit weight.
static NTSTATUS LgAddFilter(const GUID* layer,
                            UINT8 action,           // FWP_ACTION_PERMIT or _BLOCK
                            FWPM_FILTER_CONDITION* conds, UINT32 nconds,
                            UINT64 weight,
                            PCWSTR name)
{
    FWPM_FILTER f = { 0 };
    FWP_VALUE w = { 0 };
    w.type = FWP_UINT64;
    w.uint64 = &weight;

    f.layerKey               = *layer;
    f.subLayerKey            = LG_SUBLAYER_GUID;
    f.weight                 = w;
    f.numFilterConditions    = nconds;
    f.filterCondition        = conds;
    f.action.type            = action;
    f.displayData.name       = (wchar_t*)name;
    f.displayData.description = (wchar_t*)L"Lockguard LAN-only filter";

    UINT64 id = 0;
    NTSTATUS s = FwpmFilterAdd(gEngine, &f, NULL, &id);
    if (NT_SUCCESS(s)) ADD_FILTER_ID(id);
    return s;
}

// Build LAN-permit conditions (one filter per CIDR; FWP only ANDs conditions).
static NTSTATUS LgInstallV4LanPermit(const GUID* layer, UINT64 weight)
{
    struct { UINT32 net; UINT32 mask; } ranges[] = {
        { 0x0A000000, 0xFF000000 },   // 10.0.0.0/8
        { 0xAC100000, 0xFFF00000 },   // 172.16.0.0/12
        { 0xC0A80000, 0xFFFF0000 },   // 192.168.0.0/16
        { 0xA9FE0000, 0xFFFF0000 },   // 169.254.0.0/16 link-local
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(ranges); ++i) {
        FWP_V4_ADDR_AND_MASK m;
        LgMakeMask(&m, ranges[i].net, ranges[i].mask);

        FWPM_FILTER_CONDITION cond = { 0 };
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_V4_ADDR_MASK;
        cond.conditionValue.v4AddrMask = &m;

        NTSTATUS s = LgAddFilter(layer, FWP_ACTION_PERMIT, &cond, 1, weight,
                                 L"Lockguard LAN permit v4");
        if (!NT_SUCCESS(s)) return s;
    }
    return STATUS_SUCCESS;
}

// IPv6 LAN: link-local fe80::/10 and unique-local fc00::/7. (Most home
// printers use IPv4; we still permit local v6 for completeness.)
static NTSTATUS LgInstallV6LanPermit(const GUID* layer, UINT64 weight)
{
    struct { UCHAR net[16]; UCHAR mask[16]; } ranges[] = {
        // fe80::/10
        { {0xFE,0x80, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0},
          {0xFF,0xC0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0} },
        // fc00::/7
        { {0xFC,   0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0},
          {0xFE,   0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0} },
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(ranges); ++i) {
        FWP_V6_ADDR_AND_MASK m6 = { 0 };
        RtlCopyMemory(m6.addr, ranges[i].net, 16);
        // Prefix length from mask
        UINT8 prefix = 0;
        for (int b = 0; b < 16; ++b) {
            UCHAR v = ranges[i].mask[b];
            while (v & 0x80) { ++prefix; v <<= 1; }
            if (ranges[i].mask[b] != 0xFF) break;
        }
        m6.prefixLength = prefix;

        FWPM_FILTER_CONDITION cond = { 0 };
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_V6_ADDR_MASK;
        cond.conditionValue.v6AddrMask = &m6;

        NTSTATUS s = LgAddFilter(layer, FWP_ACTION_PERMIT, &cond, 1, weight,
                                 L"Lockguard LAN permit v6");
        if (!NT_SUCCESS(s)) return s;
    }
    return STATUS_SUCCESS;
}

// Permit UDP to mDNS (224.0.0.251:5353) + SSDP (239.255.255.250:1900)
// for printer discovery.
static NTSTATUS LgInstallMulticastDiscovery(const GUID* layer, UINT64 weight)
{
    struct { UINT32 addr; UINT16 port; } targets[] = {
        { 0xE00000FB, 5353 },   // 224.0.0.251 mDNS
        { 0xEFFFFFFA, 1900 },   // 239.255.255.250 SSDP
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(targets); ++i) {
        FWP_V4_ADDR_AND_MASK m;
        LgMakeMask(&m, targets[i].addr, 0xFFFFFFFF);

        FWPM_FILTER_CONDITION conds[2] = { 0 };
        conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conds[0].matchType = FWP_MATCH_EQUAL;
        conds[0].conditionValue.type = FWP_V4_ADDR_MASK;
        conds[0].conditionValue.v4AddrMask = &m;

        conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[1].matchType = FWP_MATCH_EQUAL;
        conds[1].conditionValue.type = FWP_UINT16;
        conds[1].conditionValue.uint16 = targets[i].port;

        NTSTATUS s = LgAddFilter(layer, FWP_ACTION_PERMIT, conds, 2, weight,
                                 L"Lockguard multicast discovery");
        if (!NT_SUCCESS(s)) return s;
    }
    return STATUS_SUCCESS;
}

// Default-deny at lowest weight so allows above win.
static NTSTATUS LgInstallDefaultDeny(const GUID* layer)
{
    return LgAddFilter(layer, FWP_ACTION_BLOCK, NULL, 0, 0x100,
                       L"Lockguard default deny");
}

NTSTATUS LgWfpInitialize(VOID)
{
    NTSTATUS status;
    FWPM_SESSION  session  = { 0 };
    FWPM_SUBLAYER subLayer = { 0 };
    BOOLEAN inTx = FALSE;

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // auto-cleanup if engine handle drops

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmTransactionBegin(gEngine, 0);
    if (!NT_SUCCESS(status)) goto fail;
    inTx = TRUE;

    subLayer.subLayerKey      = LG_SUBLAYER_GUID;
    subLayer.displayData.name = L"Lockguard sublayer";
    subLayer.weight           = 0xFFFF;
    status = FwpmSubLayerAdd(gEngine, &subLayer, NULL);
    if (!NT_SUCCESS(status)) goto fail;

    const UINT64 PERMIT_W = 0xF000;
    const UINT64 DENY_W   = 0x0100;

    // V4 outbound + inbound
    if (!NT_SUCCESS(status = LgInstallV4LanPermit(&FWPM_LAYER_ALE_AUTH_CONNECT_V4,     PERMIT_W))) goto fail;
    if (!NT_SUCCESS(status = LgInstallV4LanPermit(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, PERMIT_W))) goto fail;
    if (!NT_SUCCESS(status = LgInstallMulticastDiscovery(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, PERMIT_W))) goto fail;

    // V6 outbound + inbound
    if (!NT_SUCCESS(status = LgInstallV6LanPermit(&FWPM_LAYER_ALE_AUTH_CONNECT_V6,     PERMIT_W))) goto fail;
    if (!NT_SUCCESS(status = LgInstallV6LanPermit(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, PERMIT_W))) goto fail;

    // Default deny everywhere
    UNREFERENCED_PARAMETER(DENY_W);
    if (!NT_SUCCESS(status = LgInstallDefaultDeny(&FWPM_LAYER_ALE_AUTH_CONNECT_V4)))     goto fail;
    if (!NT_SUCCESS(status = LgInstallDefaultDeny(&FWPM_LAYER_ALE_AUTH_CONNECT_V6)))     goto fail;
    if (!NT_SUCCESS(status = LgInstallDefaultDeny(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4))) goto fail;
    if (!NT_SUCCESS(status = LgInstallDefaultDeny(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6))) goto fail;
    // Block bind() too — kills servers/listeners
    if (!NT_SUCCESS(status = LgInstallDefaultDeny(&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4))) goto fail;
    if (!NT_SUCCESS(status = LgInstallDefaultDeny(&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6))) goto fail;

    status = FwpmTransactionCommit(gEngine);
    if (!NT_SUCCESS(status)) goto fail;
    return STATUS_SUCCESS;

fail:
    if (inTx) FwpmTransactionAbort(gEngine);
    if (gEngine) { FwpmEngineClose(gEngine); gEngine = NULL; }
    return status;
}

VOID LgWfpFinalize(VOID)
{
    if (gEngine == NULL) return;
    FwpmTransactionBegin(gEngine, 0);
    for (ULONG i = 0; i < gFilterCount; ++i)
        FwpmFilterDeleteById(gEngine, gFilterIds[i]);
    FwpmSubLayerDeleteByKey(gEngine, &LG_SUBLAYER_GUID);
    FwpmTransactionCommit(gEngine);
    FwpmEngineClose(gEngine);
    gEngine = NULL;
    gFilterCount = 0;
}

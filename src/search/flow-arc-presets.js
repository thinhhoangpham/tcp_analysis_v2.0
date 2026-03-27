// ─── Flow Arc Pattern Presets ─────────────────────────────────────────────────
//
// Kill-chain organized preset library for Level 4 close-type pattern matching.

// ─── Vocabulary mapping ──────────────────────────────────────────────────────

export const CLOSE_TYPE_TOKENS = {
    'graceful':              'GRACEFUL',
    'abortive':              'ABORTIVE',
    'rst_during_handshake':  'RST_HANDSHAKE',
    'incomplete_no_synack':  'INCOMPLETE',
    'incomplete_no_ack':     'INCOMPLETE_ACK',
    'invalid_ack':           'INVALID_ACK',
    'invalid_synack':        'INVALID_SYNACK',
    'unknown_invalid':       'UNKNOWN',
};

export const TOKEN_TO_CLOSE_TYPE = Object.fromEntries(
    Object.entries(CLOSE_TYPE_TOKENS).map(([ct, tok]) => [tok, ct])
);

// ─── Kill chain phases ───────────────────────────────────────────────────────

export const KILL_CHAIN_PHASES = [
    { id: 'recon',        label: 'Reconnaissance', color: '#5c6bc0' },
    { id: 'delivery',     label: 'Delivery',       color: '#ff9800' },
    { id: 'exploitation', label: 'Exploitation',    color: '#e53935' },
    { id: 'impact',       label: 'Impact',          color: '#b71c1c' },
    { id: 'recovery',     label: 'Recovery',        color: '#43a047' },
];

// ─── Presets ─────────────────────────────────────────────────────────────────

export const FLOW_ARC_PRESETS = [
    // ── Reconnaissance ──
    {
        id: 'recon_scan',
        label: 'Recon Scan',
        pattern: 'INCOMPLETE{3,}',
        description: 'Repeated incomplete connections (no SYN-ACK) — port scan or host discovery',
        killChainPhase: 'recon',
    },
    {
        id: 'recon_rst_probe',
        label: 'RST Probe',
        pattern: 'RST_HANDSHAKE{3,}',
        description: 'Repeated RST during handshake — active probing',
        killChainPhase: 'recon',
    },
    {
        id: 'recon_invalid_ack',
        label: 'ACK Probe',
        pattern: 'INVALID_ACK{2,}',
        description: 'Invalid ACK packets — ACK scanning or firewall probing',
        killChainPhase: 'recon',
    },

    // ── Delivery / Lateral Movement ──
    {
        id: 'delivery_probe_connect',
        label: 'Probe then Connect',
        pattern: 'INCOMPLETE+ -> GRACEFUL',
        description: 'Probing followed by successful connection — found open port',
        killChainPhase: 'delivery',
        withinMinutes: 10,
    },
    {
        id: 'delivery_fail_connect',
        label: 'Failures then Success',
        pattern: '(RST_HANDSHAKE | INCOMPLETE | INCOMPLETE_ACK)+ -> GRACEFUL+',
        description: 'Failed attempts followed by established connections',
        killChainPhase: 'delivery',
    },

    // ── Exploitation ──
    {
        id: 'exploit_graceful_to_rst',
        label: 'Session Disrupted',
        pattern: 'GRACEFUL+ -> RST_HANDSHAKE+',
        description: 'Normal sessions followed by RST — possible exploit or MITM',
        killChainPhase: 'exploitation',
        withinMinutes: 5,
    },
    {
        id: 'exploit_abortive_burst',
        label: 'Abortive Burst',
        pattern: 'ABORTIVE{3,}',
        description: 'Repeated abortive closes — connection failures under exploitation',
        killChainPhase: 'exploitation',
    },
    {
        id: 'exploit_spoofed_synack',
        label: 'SYN-ACK Spoofing',
        pattern: 'INVALID_SYNACK+',
        description: 'Spoofed SYN-ACK responses — reflection attack indicator',
        killChainPhase: 'exploitation',
    },
    {
        id: 'exploit_success_then_blocked',
        label: 'Success then Blocked',
        pattern: 'GRACEFUL+ -> (RST_HANDSHAKE | ABORTIVE | INCOMPLETE)+',
        description: 'Successful sessions followed by failures — spambot, credential stuffing, or blocklist trigger',
        killChainPhase: 'exploitation',
        withinMinutes: 15,
    },
    {
        id: 'exploit_smtp_spambot',
        label: 'SMTP Spambot',
        pattern: '(GRACEFUL[port=25] | ABORTIVE[port=25]) -> RST_HANDSHAKE[port=113]',
        description: 'SMTP connection (abortive or graceful) with failed IDENT lookup — spambot signature',
        killChainPhase: 'exploitation',
    },

    // ── Impact / DDoS ──
    {
        id: 'impact_syn_flood',
        label: 'SYN Flood',
        pattern: 'INCOMPLETE[volume=high]+',
        description: 'High-volume incomplete connections — SYN flood',
        killChainPhase: 'impact',
    },
    {
        id: 'impact_rst_flood',
        label: 'RST Flood',
        pattern: 'RST_HANDSHAKE[volume=high]+',
        description: 'High-volume RST during handshake — RST flood',
        killChainPhase: 'impact',
    },
    {
        id: 'impact_escalation',
        label: 'Escalating Attack',
        pattern: 'RST_HANDSHAKE+ -> INCOMPLETE+',
        description: 'RST probing escalates to volumetric SYN flood',
        killChainPhase: 'impact',
    },
    {
        id: 'impact_unknown_flood',
        label: 'Unknown Flood',
        pattern: 'UNKNOWN{2,}',
        description: 'Sustained unknown/invalid flow type — anomalous traffic',
        killChainPhase: 'impact',
    },

    // ── Recovery ──
    {
        id: 'recovery_attack_to_normal',
        label: 'Attack → Recovery',
        pattern: '(RST_HANDSHAKE | INCOMPLETE)+ -> GRACEFUL+',
        description: 'Attack traffic subsiding into normal connections',
        killChainPhase: 'recovery',
    },
    {
        id: 'recovery_abort_to_normal',
        label: 'Abort → Recovery',
        pattern: 'ABORTIVE+ -> GRACEFUL{2,}',
        description: 'Connection failures transitioning to successful closes',
        killChainPhase: 'recovery',
    },
    {
        id: 'recovery_no_clean_shutdown',
        label: 'No Clean Shutdown',
        pattern: '^ ABORTIVE+ $',
        description: 'Pair with only abortive connections — possible C2 or exfiltration',
        killChainPhase: 'recovery',
    },

    // ── Fan patterns (bypass DSL) ──
    {
        id: 'fan_in_ddos',
        label: 'Fan-In: DDoS Target',
        fanType: 'fan_in',
        closeType: 'incomplete_no_synack',
        threshold: 5,
        description: 'Many sources sending incomplete connections to one target',
        killChainPhase: 'impact',
    },
    {
        id: 'fan_out_scan',
        label: 'Fan-Out: Port Scan',
        fanType: 'fan_out',
        closeType: 'incomplete_no_synack',
        threshold: 5,
        description: 'One source sending incomplete connections to many targets',
        killChainPhase: 'recon',
    },
    {
        id: 'fan_in_rst',
        label: 'Fan-In: RST Target',
        fanType: 'fan_in',
        closeType: 'rst_during_handshake',
        threshold: 3,
        description: 'Many sources sending RST to one target — distributed probe',
        killChainPhase: 'recon',
    },
];

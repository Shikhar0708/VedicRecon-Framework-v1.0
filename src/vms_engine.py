def calculate_vms(analysis: dict) -> tuple:
    score = 100
    findings = []

    ports = str(analysis.get("ports", ""))
    services_raw = str(analysis.get("services", "")).lower()
    banners = str(analysis.get("banners", "")).lower()
    edge = bool(analysis.get("is_edge_protected", False))

    # Normalize services list
    services = {s.strip() for s in services_raw.split("|") if s.strip()}

    # --- LOW-CONFIDENCE SERVICE CLASSIFICATION ---
    LOW_CONFIDENCE_SERVICES = {"ppp", "unknown", "rpcbind", "tcpwrapped"}
    has_low_confidence_service = bool(services & LOW_CONFIDENCE_SERVICES)

    # --- Edge Opacity Heuristic ---
    tcpwrapped = "tcpwrapped" in services
    common_edge_ports = {"53", "80", "443", "8080"}
    open_common_ports = sum(p in ports for p in common_edge_ports)

    high_opacity_edge = (
        tcpwrapped
        and open_common_ports >= 3
        and not banners.strip()
    )

    # --- BASELINE: EDGE FIRST ---
    if high_opacity_edge:
        findings.append(
            "High Edge Opacity Detected: Services intentionally suppress fingerprinting"
        )
        edge_opacity = "high"

    elif edge:
        findings.append("Edge / Reverse-Proxy Abstraction Detected")
        edge_opacity = "medium"

    else:
        score -= 25
        findings.append("Direct Exposure: No Edge Protection (-25)")
        edge_opacity = "low"

    # --- Defensive Density (ONLY if origin-visible) ---
    if edge_opacity == "low":
        density_raw = analysis.get("defensive_density") or "0%"
        try:
            density_val = float(str(density_raw).replace("%", "").split()[0])
        except Exception:
            density_val = 0.0

        if density_val == 0:
            score -= 15
            findings.append("Zero Internal Defensive Density (-15)")
        elif density_val < 50:
            score -= 8
            findings.append("Low Internal Defensive Density (-8)")

    # --- Critical Exposure Flags (STRICT, CONFIDENCE-GATED) ---
    critical_flags = {
        "exposed_database": False,
        "probable_rce_surface": False,
    }

    if edge_opacity == "low":
        # Database exposure is explicit and allowed
        if "mongodb" in services or "27017" in ports:
            critical_flags["exposed_database"] = True
            findings.append("CRITICAL: Database Service Directly Exposed")

        # RCE surface MUST NOT be inferred from low-confidence services
        if (
            any(p in ports for p in ["3000", "8080", "8081"])
            and not has_low_confidence_service
        ):
            critical_flags["probable_rce_surface"] = True
            findings.append("HIGH: Unprotected Development / Application Surface")

        elif has_low_confidence_service:
            findings.append(
                "Unverified Service Attribution: Service identity inferred from port heuristics only"
            )

    # --- Score caps (origin only) ---
    score_cap = 100
    if critical_flags["exposed_database"]:
        score_cap = min(score_cap, 45)
    if critical_flags["probable_rce_surface"]:
        score_cap = min(score_cap, 35)

    # --- Opacity safety floor ---
    if edge_opacity == "high":
        score = max(score, 70)
    elif edge_opacity == "medium":
        score = max(score, 60)

    final_score = min(score, score_cap)

    return int(final_score), findings, edge_opacity

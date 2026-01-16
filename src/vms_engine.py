def calculate_vms(analysis: dict) -> int:
    """
    Deterministic Infrastructure Maturity Score (VMS v1.1).
    Engine-owned. No AI inference.
    """

    score = 100
    edge = analysis.get("is_edge_protected", False)

    # --- Base Maturity Deductions ---

    if not edge:
        score -= 25

    density = analysis.get("defensive_density", "0%").replace("%", "")
    try:
        density_val = float(density)
    except ValueError:
        density_val = 0.0

    if density_val == 0:
        score -= 20
    elif density_val < 50:
        score -= 10

    if analysis.get("os", "") == "DETECTION_FAILED" and not edge:
        score -= 15

    if not analysis.get("detected_vendors") and not edge:
        score -= 10

    services = analysis.get("services", "")
    if "tcpwrapped" in services and not edge:
        score -= 10

    # --- Critical Risk Flags ---

    critical_flags = {
        "unauth_database": False,
        "rce_surface": False
    }

    ports = analysis.get("ports", "")
    services_lower = services.lower()

    if "mongodb" in services_lower or "27017" in ports:
        critical_flags["unauth_database"] = True

    if any(p in ports for p in ["3000", "8080", "8081"]) and "http" in services_lower:
        critical_flags["rce_surface"] = True

    # --- Risk-Based Score Caps ---

    score_cap = 100

    if critical_flags["unauth_database"]:
        score_cap = min(score_cap, 40)

    if critical_flags["rce_surface"]:
        score_cap = min(score_cap, 35)

    if all(critical_flags.values()):
        score_cap = min(score_cap, 25)

    score = min(score, score_cap)

    return max(0, min(100, score))

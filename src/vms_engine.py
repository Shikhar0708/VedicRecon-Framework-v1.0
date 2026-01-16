def calculate_vms(analysis: dict) -> int:
    """
    Deterministic Infrastructure Maturity Score (VMS v1).
    Engine-owned. No AI inference.
    """

    score = 100

    # Edge protection
    if not analysis.get("is_edge_protected", False):
        score -= 25

    # Defensive density
    density = analysis.get("defensive_density", "0%").replace("%", "")
    try:
        density_val = float(density)
    except ValueError:
        density_val = 0.0

    if density_val == 0:
        score -= 20
    elif density_val < 50:
        score -= 10

    # OS visibility
    if analysis.get("os", "") == "DETECTION_FAILED":
        score -= 15

    # Vendor signals
    if not analysis.get("detected_vendors"):
        score -= 10

    # Ambiguous service exposure
    services = analysis.get("services", "")
    if "tcpwrapped" in services and not analysis.get("is_edge_protected"):
        score -= 10

    return max(0, min(100, score))

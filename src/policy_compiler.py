class PolicyCompiler:
    """
    Compiles ai_profile.json + engine signals into a deterministic system prompt.
    """

    def __init__(self, config: dict):
        self.config = config

    def _compile_tone(self, vms_score: int) -> str:
        metrics = self.config.get("strategic_metrics", {})
        if not metrics.get("tone_binding", True):
            return "Neutral advisory tone."

        if vms_score >= 80:
            return "Defensive Excellence — focus on micro-optimizations."
        elif vms_score >= 50:
            return "Developing Posture — highlight missing hardening."
        return "Critical Exposure — demand foundational remediation."

    def _compile_recommendation_limit(self, vms_score: int) -> int:
        policy = self.config.get("recommendation_policy", {})
        if vms_score >= 80:
            return policy.get("max_if_high_maturity", 1)
        elif vms_score >= 50:
            return policy.get("max_if_medium_maturity", 3)
        return policy.get("max_if_low_maturity", 5)

    def _compile_constraints(self) -> str:
        constraints = self.config.get("ai_constraints", {})
        return "\n".join(
            f"- {k.replace('_', ' ').upper()}: {v}"
            for k, v in constraints.items()
        )

    def _compile_evidence_policy(self) -> str:
        evidence = self.config.get("evidence_policy", {})
        levels = ", ".join(evidence.get("allowed_levels", []))
        manual = evidence.get("require_manual_validation_notice", False)
        return (
            f"- Allowed Evidence Levels: {levels}\n"
            f"- Manual Validation Required: {manual}"
        )

    def compile_prompt(self, profile_data: dict, vms_score: int) -> str:
        tone = self._compile_tone(vms_score)
        max_recs = self._compile_recommendation_limit(vms_score)

        return (
            f"ROLE: {profile_data['role']}\n"
            f"FOCUS: {profile_data['focus']}\n"
            f"FORMAT: {profile_data['format']}\n\n"

            "GOVERNANCE CONSTRAINTS:\n"
            f"{self._compile_constraints()}\n\n"

            "EVIDENCE POLICY:\n"
            f"{self._compile_evidence_policy()}\n\n"

            f"STRATEGIC CONTEXT: {tone}\n"
            f"INFRASTRUCTURE MATURITY SCORE: {vms_score}/100\n\n"

            "RECOMMENDATION LIMIT:\n"
            f"- Maximum recommendations per finding: {max_recs}\n\n"

            "TABLE FORMATTING RULES:\n"
            "1. Every Markdown table row MUST end with '|'.\n"
            "2. Table rationales max 2 sentences.\n"
            "3. No spacing-based column alignment.\n\n"

            "CONTEXTUAL SEMANTICS:\n"
            "If is_edge_protected is True, interpret missing service data as "
            "'SUCCESSFUL ABSTRACTION' and 'HIGH DEFENSIVE MATURITY'. "
            "Do NOT speculate on internal services.\n\n"

            "STRICT PRIVACY:\n"
            "Node IDs (e.g., [IP_1]) are tokens and MUST NOT be resolved.\n"
        )

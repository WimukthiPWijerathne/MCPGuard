# security/approval.py
import os

class ApprovalManager:
    @staticmethod
    def prompt_approval(
        user_id: str,
        tool: str,
        arguments: dict,
        risk_score: int,
        auto_approve: bool = False
    ) -> bool:
        """
        Handles human-in-the-loop approvals.
        If auto_approve is True or MCPGUARD_AUTO_APPROVE=1 in env, approves automatically.
        """
        if auto_approve or os.getenv("MCPGUARD_AUTO_APPROVE") == "1":
            return True

        print(f"\n[APPROVAL REQUIRED] User '{user_id}' requested '{tool}' (Risk: {risk_score})")
        print(f"Arguments: {arguments}")
        
        try:
            response = input("Approve tool execution? (y/N): ").strip().lower()
            return response == "y"
        except (EOFError, KeyboardInterrupt):
            return False
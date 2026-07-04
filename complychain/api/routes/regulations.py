"""Regulation assessment endpoints."""

try:
    from fastapi import APIRouter, HTTPException
    from ..schemas import AssessRequest

    router = APIRouter(prefix="/regulations", tags=["regulations"])

    @router.get("")
    def list_regulations():
        from ...regulations import default_registry
        return [r.regulation_id for r in default_registry.list_all()]

    @router.post("/assess")
    def assess(req: AssessRequest):
        from ...regulations import default_registry, InstitutionProfile
        profile = InstitutionProfile(
            name=req.name,
            jurisdiction=req.jurisdiction,
            entity_type=req.entity_type,
            processes_card_payments=req.processes_card_payments,
            eu_nexus=req.eu_nexus,
            employee_count=req.employee_count,
            hipaa_covered_entity=req.hipaa_covered_entity,
        )
        reports = default_registry.assess_all(profile)
        return {
            reg_id: (report.to_dict() if hasattr(report, "to_dict") else {})
            for reg_id, report in reports.items()
        }

    @router.get("/{regulation_id}/history")
    def history(regulation_id: str, days: int = 30):
        from ...persistence import AssessmentStore
        store = AssessmentStore()
        return store.query(regulation_id=regulation_id, days=days)

    @router.get("/{regulation_id}/diff")
    def diff(regulation_id: str):
        from ...persistence import AssessmentStore
        store = AssessmentStore()
        d = store.diff(regulation_id)
        if d is None:
            raise HTTPException(status_code=404, detail="No previous assessments found for diff.")
        return {
            "risk_delta": d.risk_delta,
            "status_changed": d.status_changed,
            "control_diffs": [
                {
                    "control_id": c.control_id,
                    "changed": c.changed,
                    "old_status": c.old_status,
                    "new_status": c.new_status,
                }
                for c in d.control_diffs
            ],
        }

except ImportError:
    pass

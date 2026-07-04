"""
SARGenerator — produces ready-to-file Suspicious Activity Report artifacts.

Outputs:
  - Human-readable narrative (str)
  - PDF report (bytes) via ReportLab
  - FinCEN BSA E-Filing 2.0 XML (str)

Usage:
    from complychain.reporting import SARGenerator
    sar = SARGenerator().generate(scan_result, tx_data)
    Path("sar.pdf").write_bytes(sar.to_pdf())
    Path("sar.xml").write_text(sar.to_xml())
"""

import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .explainability import ExplanationEngine

_FLAG_NARRATIVES: Dict[str, str] = {
    "HIGH_VALUE_TRANSACTION": (
        "A {transaction_type} of ${amount:,.2f} was processed, exceeding the $10,000 "
        "Currency Transaction Report (CTR) threshold established under 31 U.S.C. § 5313."
    ),
    "STRUCTURING_SUSPECTED": (
        "{transaction_count} transaction(s) totalling ${amount:,.2f} were identified within "
        "a 24-hour window, with individual amounts kept below the $10,000 reporting threshold. "
        "This pattern is consistent with structuring as defined under 31 U.S.C. § 5324."
    ),
    "SANCTIONS_MATCH": (
        "The {party} '{entity}' was identified as a potential match against the OFAC "
        "Specially Designated Nationals (SDN) list or FinCEN watchlist, in potential "
        "violation of the International Emergency Economic Powers Act (IEEPA)."
    ),
    "CROSS_BORDER_TRANSFER": (
        "An international transfer of ${amount:,.2f} was initiated to {destination_country}. "
        "Enhanced due diligence was applied per GLBA §314.4(b) and FATF Recommendation 16."
    ),
    "ML_ANOMALY_DETECTED": (
        "Automated machine learning analysis identified this transaction as statistically "
        "anomalous relative to established baseline patterns, warranting further review."
    ),
    "WIRE_TRANSFER_MONITORING": (
        "A wire transfer of ${amount:,.2f} was processed, triggering FinCEN monitoring "
        "requirements under 31 C.F.R. § 1010.410 (Recordkeeping for wire transfers)."
    ),
    "CURRENCY_TRANSACTION_REPORTING": (
        "A cash transaction of ${amount:,.2f} was conducted, requiring mandatory CTR "
        "filing under 31 C.F.R. § 1010.311."
    ),
    "MISSING_DEVICE_ID": (
        "The transaction lacked a device fingerprint, impairing device-based access "
        "controls required under GLBA §314.4(c)(1)."
    ),
    "PEP_EXPOSURE": (
        "A politically exposed person (PEP) was identified as a party to this transaction, "
        "triggering Enhanced Due Diligence (EDD) obligations."
    ),
}


@dataclass
class SARReport:
    sar_id: str
    filing_type: str
    generated_at: datetime
    narrative: str
    subject_info: Dict[str, Any]
    transaction_summary: Dict[str, Any]
    risk_score: int
    threat_flags: List[str]
    fincen_compliance: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sar_id": self.sar_id,
            "filing_type": self.filing_type,
            "generated_at": self.generated_at.isoformat(),
            "narrative": self.narrative,
            "subject_info": self.subject_info,
            "transaction_summary": self.transaction_summary,
            "risk_score": self.risk_score,
            "threat_flags": self.threat_flags,
            "fincen_compliance": self.fincen_compliance,
        }

    def to_xml(self) -> str:
        """FinCEN BSA E-Filing 2.0 XML structure (public schema)."""
        root = ET.Element("EFilingBatchXML", {
            "xmlns": "FinCEN/BSAEFILING",
            "SeqNum": "1",
            "TotalAmount": str(self.transaction_summary.get("amount", 0)),
        })
        filing = ET.SubElement(root, "FormData")

        hdr = ET.SubElement(filing, "ReportHeader")
        ET.SubElement(hdr, "BSAID").text = self.sar_id
        ET.SubElement(hdr, "FilingType").text = self.filing_type
        ET.SubElement(hdr, "FilingDate").text = self.generated_at.strftime("%Y%m%d")
        ET.SubElement(hdr, "ReportType").text = "SAR"

        subj = ET.SubElement(filing, "SubjectInformation")
        for key, val in self.subject_info.items():
            ET.SubElement(subj, key.replace(" ", "_")).text = str(val)

        tx = ET.SubElement(filing, "TransactionInformation")
        for key, val in self.transaction_summary.items():
            ET.SubElement(tx, key.replace(" ", "_")).text = str(val)

        narr = ET.SubElement(filing, "NarrativeSection")
        ET.SubElement(narr, "Narrative").text = self.narrative

        susp = ET.SubElement(filing, "SuspiciousActivities")
        for flag in self.threat_flags:
            ET.SubElement(susp, "Activity").text = flag

        ET.indent(root, space="  ")
        return ET.tostring(root, encoding="unicode", xml_declaration=False)

    def to_pdf(self) -> bytes:
        """Generates a PDF SAR document using ReportLab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )
        from reportlab.lib import colors
        from io import BytesIO

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter,
                                leftMargin=inch, rightMargin=inch,
                                topMargin=inch, bottomMargin=inch)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Heading1"],
                                     fontSize=14, spaceAfter=6)
        section_style = ParagraphStyle("Section", parent=styles["Heading2"],
                                       fontSize=11, spaceBefore=12, spaceAfter=4)
        body_style = styles["BodyText"]

        story = []

        story.append(Paragraph("SUSPICIOUS ACTIVITY REPORT", title_style))
        story.append(Paragraph("FinCEN Form 111 — BSA E-Filing", styles["Heading2"]))
        story.append(Spacer(1, 0.15 * inch))

        meta = [
            ["SAR ID", self.sar_id],
            ["Filing Type", self.filing_type],
            ["Generated At", self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Risk Score", f"{self.risk_score}/100"],
        ]
        meta_table = Table(meta, colWidths=[2 * inch, 4 * inch])
        meta_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Subject Information", section_style))
        subj_data = [[k, str(v)] for k, v in self.subject_info.items()]
        if subj_data:
            subj_table = Table(subj_data, colWidths=[2 * inch, 4 * inch])
            subj_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))
            story.append(subj_table)

        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Transaction Summary", section_style))
        tx_data_rows = [[k, str(v)] for k, v in self.transaction_summary.items()]
        if tx_data_rows:
            tx_table = Table(tx_data_rows, colWidths=[2 * inch, 4 * inch])
            tx_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))
            story.append(tx_table)

        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Suspicious Activity Flags", section_style))
        for flag in self.threat_flags:
            story.append(Paragraph(f"• {flag}", body_style))

        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Narrative", section_style))
        story.append(Paragraph(self.narrative, body_style))

        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            "This report was generated automatically by ComplyChain v3.0.0. "
            "It should be reviewed by a qualified BSA Officer before filing with FinCEN.",
            ParagraphStyle("Disclaimer", parent=styles["Italic"], fontSize=8,
                           textColor=colors.grey)
        ))

        doc.build(story)
        return buf.getvalue()


class SARGenerator:
    """Generates Suspicious Activity Reports from GLBAScanner scan results."""

    def generate(
        self,
        scan_result: dict,
        tx_data: dict,
        filing_type: str = "INITIAL",
    ) -> SARReport:
        flags: List[str] = scan_result.get("threat_flags", [])
        fincen: dict = scan_result.get("fincen_compliance", {})
        risk_score: int = scan_result.get("risk_score", 0)

        if fincen.get("sanctions_match") and "SANCTIONS_MATCH" not in flags:
            flags = list(flags) + ["SANCTIONS_MATCH"]

        narrative = self._build_narrative(flags, tx_data, fincen)
        subject_info = self._extract_subject(tx_data)
        tx_summary = self._extract_tx_summary(tx_data, scan_result)

        report = SARReport(
            sar_id=str(uuid.uuid4()),
            filing_type=filing_type,
            generated_at=datetime.utcnow(),
            narrative=narrative,
            subject_info=subject_info,
            transaction_summary=tx_summary,
            risk_score=risk_score,
            threat_flags=flags,
            fincen_compliance=fincen,
        )

        try:
            from ..events import default_bus, Event, EventType
            default_bus.emit(Event(EventType.SAR_GENERATED, {
                "sar_id": report.sar_id,
                "risk_score": risk_score,
                "filing_type": filing_type,
                "flags": flags,
            }))
        except Exception:
            pass

        return report

    def _build_narrative(
        self, flags: List[str], tx_data: dict, fincen: dict
    ) -> str:
        amount = tx_data.get("amount", 0)
        tx_type = tx_data.get("transaction_type", "transaction")
        beneficiary = tx_data.get("beneficiary", "unknown party")
        originator = tx_data.get("originator", "unknown party")
        destination = tx_data.get("destination_country", "an unknown destination")
        tx_count = tx_data.get("transaction_count", 1)

        sentences: List[str] = [
            f"The following suspicious activity was identified involving a {tx_type} "
            f"of ${amount:,.2f}."
        ]

        for flag in flags:
            template = _FLAG_NARRATIVES.get(flag)
            if not template:
                continue
            try:
                sentence = template.format(
                    amount=amount,
                    transaction_type=tx_type,
                    transaction_count=tx_count,
                    entity=beneficiary,
                    party="beneficiary",
                    destination_country=destination,
                    originator=originator,
                    beneficiary=beneficiary,
                )
                sentences.append(sentence)
            except (KeyError, ValueError):
                sentences.append(f"Flag raised: {flag}.")

        if fincen.get("ctr_required"):
            sentences.append(
                "A Currency Transaction Report (CTR) is required to be filed "
                "with FinCEN within 15 calendar days."
            )
        if fincen.get("sar_required"):
            sentences.append(
                "A Suspicious Activity Report (SAR) is required. The institution "
                "must not inform the subject of this filing (tipping-off prohibition, "
                "31 U.S.C. § 5318(g)(2))."
            )

        sentences.append(
            "This report was generated by the ComplyChain automated compliance "
            "system and requires review by a qualified BSA Officer prior to filing."
        )

        return " ".join(sentences)

    def _extract_subject(self, tx_data: dict) -> Dict[str, Any]:
        return {
            "BeneficiaryName": tx_data.get("beneficiary", "Unknown"),
            "OriginatorName": tx_data.get("originator", "Unknown"),
            "AccountNumber": tx_data.get("account_number", "Unknown"),
            "TaxIDNumber": tx_data.get("tax_id", "Unknown"),
            "Address": tx_data.get("address", "Unknown"),
        }

    def _extract_tx_summary(self, tx_data: dict, scan_result: dict) -> Dict[str, Any]:
        return {
            "Amount": tx_data.get("amount", 0),
            "Currency": scan_result.get("currency", "USD"),
            "TransactionType": tx_data.get("transaction_type", "Unknown"),
            "TransactionDate": tx_data.get("date", datetime.utcnow().strftime("%Y-%m-%d")),
            "DestinationCountry": tx_data.get("destination_country", "US"),
            "RiskScore": scan_result.get("risk_score", 0),
        }

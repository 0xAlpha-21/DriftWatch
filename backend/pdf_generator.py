import io
import json
from datetime import datetime, timezone, timedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# Context-Aware Threat & Recommendation Mapping
EVENT_MAPPING = {
    "FULL_ADMIN_PRIVILEGES": {
        "auditor_rec": "Replace wildcard '*' IAM actions with specific API bounds (e.g., 's3:GetObject', 'ec2:DescribeInstances') restricted to designated resource ARNs.",
        "exec_impact": "Over-permissive identities allow attackers to execute complete account takeovers, delete production infrastructure, or exfiltrate databases. This leads to massive business interruption and loss of customer trust.",
        "exec_rec": "Revoke wildcard access and enforce strict Role-Based Access Control (RBAC)."
    },
    "PUBLIC_BUCKET_EXPOSED": {
        "auditor_rec": "Enable 'Block Public Access' (BPA) at the bucket level and restrict the bucket policy to specific VPC endpoints or CloudFront OACs.",
        "exec_impact": "Publicly accessible storage exposes sensitive company/customer data to the internet, triggering immediate data breaches, severe regulatory fines (GDPR/DPDPA), and devastating brand reputation damage.",
        "exec_rec": "Enforce private access limits and mandate encryption at rest."
    },
    "EXPOSED_RDP": {
        "auditor_rec": "Restrict inbound RDP (Port 3389) rules to approved corporate VPN CIDRs (e.g., 10.10.1.0/24) instead of 0.0.0.0/0.",
        "exec_impact": "Open remote desktop ports invite automated brute-force attacks, serving as the primary entry point for ransomware deployment and critical system lockouts.",
        "exec_rec": "Close internet-facing ports and mandate VPN or AWS Systems Manager for access."
    },
    "RULES_MODIFIED": {
        "auditor_rec": "Revert unauthorized network rule modifications. Ensure security group ingress is limited strictly to known IPs (e.g., 10.10.1.2/32) and expected traffic.",
        "exec_impact": "Unauthorized network changes bypass security perimeters, exposing internal workloads to external threat actors and business logic abuse.",
        "exec_rec": "Restore approved network perimeter configurations via Terraform."
    },
    "HARDCODED_SECRETS": {
        "auditor_rec": "Remove plaintext AWS keys from environment variables. Migrate secrets to AWS Secrets Manager and utilize IAM Roles for Service Accounts (IRSA).",
        "exec_impact": "Leaked application credentials allow attackers to hijack cloud resources, incurring massive unauthorized compute charges (crypto-mining) and intellectual property theft.",
        "exec_rec": "Eradicate hardcoded keys and deploy centralized automated secret management."
    },
    "GENERIC_DRIFT": {
        "auditor_rec": "Review and revert the configuration drift to the approved Terraform baseline.",
        "exec_impact": "Unmanaged configuration changes introduce unknown security blindspots and violate compliance mandates, increasing liability.",
        "exec_rec": "Audit the modified resource and restore the secure baseline."
    }
}

def build_pdf_report(report_type: str, metrics: dict, incidents: list) -> io.BytesIO:
    buffer = io.BytesIO()
    
    doc_title = "DriftWatch Auditor Report" if report_type == "auditor" else "DriftWatch Executive Summary"
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=doc_title,
        author="DriftWatch CSPM Engine"
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor("#0f172a"), spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#64748b"), spaceAfter=14
    )
    heading_style = ParagraphStyle(
        'SectionHeading', parent=styles['Heading2'], fontSize=13, leading=16, textColor=colors.HexColor("#1e293b"), spaceBefore=12, spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyDark', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor("#334155")
    )
    table_header_style = ParagraphStyle(
        'TableHeader', parent=styles['Normal'], fontSize=9, leading=11, fontName='Helvetica-Bold', textColor=colors.white
    )
    table_text = ParagraphStyle(
        'TableText', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor("#1e293b")
    )
    code_style = ParagraphStyle(
        'CodeDiff', parent=styles['Normal'], fontSize=7, leading=9, fontName='Courier', textColor=colors.HexColor("#0f172a")
    )

    story = []

    # NEW: IST Timezone Definition
    ist_tz = timezone(timedelta(hours=5, minutes=30))

    # Title & Header
    story.append(Paragraph(doc_title, title_style))
    generated_time = datetime.now(ist_tz).strftime('%Y-%m-%d %H:%M:%S IST')
    story.append(Paragraph(f"Generated on: {generated_time} | Scope: AWS Infrastructure (us-east-1)", subtitle_style))
    story.append(Spacer(1, 10))

    # Metric KPI Summary Grid
    posture_score = max(0, 100 - (metrics.get('active_drifts', 0) * 20))
    kpi_data = [
        ["Monitored Assets", "Active Drifts", "Critical Risks", "Posture Score"],
        [
            str(metrics.get("monitored_assets", 0)),
            str(metrics.get("active_drifts", 0)),
            str(metrics.get("critical_risks", 0)),
            f"{posture_score}%"
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[130, 130, 130, 130])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#475569")),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, 1), 14),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 15))

    # -------------------------------------------------------------
    # 1. EXECUTIVE SUMMARY VIEW
    # -------------------------------------------------------------
    if report_type == "executive":
        story.append(Paragraph("Executive Posture & Business Impact Analysis", heading_style))
        
        if metrics.get('active_drifts', 0) == 0:
            status_text = "<b>Environment Status: SECURE</b><br/>No active configuration drifts detected. The infrastructure aligns with baseline security requirements, minimizing risk and regulatory exposure."
            story.append(Paragraph(status_text, body_style))
        else:
            status_text = (
                f"<b>Environment Status: ELEVATED RISK (Posture Score: {posture_score}%)</b><br/>"
                f"DriftWatch has identified <b>{metrics.get('active_drifts', 0)} security drifts</b> across the monitored AWS environment. "
                "These unauthorized infrastructure mutations actively expose the business to financial loss, operational downtime, and strict regulatory penalties."
            )
            story.append(Paragraph(status_text, body_style))
            story.append(Spacer(1, 12))

        exec_rows = [[
            Paragraph("Impacted Asset & Threat", table_header_style), 
            Paragraph("Business & Security Impact", table_header_style), 
            Paragraph("Strategic Remediation", table_header_style)
        ]]
        
        for inc in incidents:
            event = inc.get("event_type", "GENERIC_DRIFT")
            mapping = EVENT_MAPPING.get(event, EVENT_MAPPING["GENERIC_DRIFT"])
            
            asset_info = f"<b>{inc.get('resource_id', 'Unknown')}</b><br/><font color='#b91c1c'>Threat:</font> {event}"
            
            exec_rows.append([
                Paragraph(asset_info, table_text),
                Paragraph(mapping["exec_impact"], table_text),
                Paragraph(mapping["exec_rec"], table_text)
            ])

        if len(exec_rows) > 1:
            exec_table = Table(exec_rows, colWidths=[160, 220, 140])
            exec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")), 
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(exec_table)

    # -------------------------------------------------------------
    # 2. AUDITOR REPORT VIEW
    # -------------------------------------------------------------
    else:
        story.append(Paragraph("Technical Drift Logs & Control Deviations", heading_style))

        if not incidents:
            story.append(Paragraph("No active security drift records found in the current audit log.", body_style))
        else:
            for idx, inc in enumerate(incidents, 1):
                event = inc.get("event_type", "GENERIC_DRIFT")
                mapping = EVENT_MAPPING.get(event, EVENT_MAPPING["GENERIC_DRIFT"])

                # NEW: Convert Incident Timestamp to IST
                raw_ts = inc.get("timestamp", "")
                try:
                    dt = datetime.fromisoformat(raw_ts.replace('Z', '+00:00'))
                    display_ts = dt.astimezone(ist_tz).strftime('%Y-%m-%d %H:%M:%S IST')
                except Exception:
                    display_ts = raw_ts

                story.append(Paragraph(f"<b>Finding No.{idx}: {inc.get('resource_id', 'Unknown')}</b>", heading_style))
                
                framework_info = (
                    f"<b>Event:</b> {event} | <b>Timestamp:</b> {display_ts}<br/>"
                    f"<b>CIS:</b> {inc.get('cis_control', 'N/A')}<br/>"
                    f"<b>ISO 27001:</b> {inc.get('iso_control', 'N/A')}<br/>"
                    f"<b>GDPR:</b> {inc.get('gdpr_control', 'N/A')}<br/>"
                    f"<b>DPDPA 2023:</b> {inc.get('dpdpa_control', 'N/A')}"
                )
                story.append(Paragraph(framework_info, body_style))
                story.append(Spacer(1, 6))

                recommendation_text = f"<b>Actionable Recommendation:</b> {mapping['auditor_rec']}"
                story.append(Paragraph(recommendation_text, body_style))
                story.append(Spacer(1, 6))

                raw_diff = inc.get("details", "{}")
                try:
                    formatted_diff = json.dumps(json.loads(raw_diff) if isinstance(raw_diff, str) else raw_diff, indent=2)
                except Exception:
                    formatted_diff = str(raw_diff)

                diff_table = Table([[Paragraph(formatted_diff.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style)]], colWidths=[520])
                diff_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(diff_table)
                story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)
    return buffer
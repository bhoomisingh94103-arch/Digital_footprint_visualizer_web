import os
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf_report(assessment_data, output_folder, report_type='email'):
    """
    Generate an executive cybersecurity assessment PDF report using ReportLab.
    assessment_data: dict containing:
      - assessment_id
      - scan_date
      - email / target
      - risk_score (0-100)
      - risk_level ('Low', 'Moderate', 'High', 'Critical')
      - breach_count
      - breaches (list of dicts)
      - ip_info (dict, optional)
      - reputation_info (dict, optional)
      - category_scores (dict, optional for questionnaire)
      - recommendations (list of dicts with title, priority, steps)
    """
    os.makedirs(output_folder, exist_ok=True)
    
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_id = assessment_data.get('assessment_id', timestamp_str)
    filename = f"DFI_Security_Report_{report_type.upper()}_{report_id}.pdf"
    file_path = os.path.join(output_folder, filename)
    
    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom cyber-themed typography
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    
    bold_body = ParagraphStyle(
        'BoldBody',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#0f172a')
    )
    
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Italic'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748b')
    )

    story = []
    
    # 1. Header Banner
    story.append(Paragraph("DIGITAL FOOTPRINT INTELLIGENCE", title_style))
    story.append(Paragraph("Discover Your Digital Presence. Understand Your Risks. Take Control.", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#10b981'), spaceAfter=10))
    
    # 2. Executive Metadata Block
    risk_score = assessment_data.get('risk_score', 0)
    risk_level = assessment_data.get('risk_level', 'Low')
    
    # Color coding based on risk
    if risk_score > 75:
        score_color = colors.HexColor('#ef4444') # Red
    elif risk_score > 50:
        score_color = colors.HexColor('#f97316') # Orange
    elif risk_score > 25:
        score_color = colors.HexColor('#eab308') # Yellow
    else:
        score_color = colors.HexColor('#10b981') # Green

    target_info = assessment_data.get('email') or assessment_data.get('target', 'General Privacy Profile')
    scan_date = assessment_data.get('scan_date', datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    
    meta_table_data = [
        [
            Paragraph("<b>Assessment ID:</b>", body_style),
            Paragraph(f"DFI-SEC-{report_id}", body_style),
            Paragraph("<b>Risk Rating:</b>", body_style),
            Paragraph(f"<font color='{score_color.hexval()}'><b>{risk_level.upper()} ({risk_score}/100)</b></font>", bold_body)
        ],
        [
            Paragraph("<b>Target Evaluated:</b>", body_style),
            Paragraph(target_info, body_style),
            Paragraph("<b>Scan Timestamp:</b>", body_style),
            Paragraph(str(scan_date), body_style)
        ],
        [
            Paragraph("<b>Assessment Mode:</b>", body_style),
            Paragraph("Mode A: Email Footprint" if report_type == 'email' else "Mode B: Digital Privacy Questionnaire", body_style),
            Paragraph("<b>Breach Matches:</b>", body_style),
            Paragraph(str(assessment_data.get('breach_count', 0)), bold_body)
        ]
    ]
    
    meta_table = Table(meta_table_data, colWidths=[1.3*inch, 2.3*inch, 1.3*inch, 2.1*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))
    
    # 3. Breach Findings (If Mode A or breaches present)
    breaches = assessment_data.get('breaches', [])
    if report_type == 'email' or breaches:
        story.append(Paragraph("Verified Data Breach Intelligence (XposedOrNot Verified Index)", section_heading))
        if breaches:
            breach_table_data = [
                [
                    Paragraph("<b>Breach Entity</b>", bold_body),
                    Paragraph("<b>Year</b>", bold_body),
                    Paragraph("<b>Exposed Data Classes</b>", bold_body),
                    Paragraph("<b>Password Risk</b>", bold_body)
                ]
            ]
            
            for b in breaches[:12]: # Cap at 12 to maintain clean layout
                breach_table_data.append([
                    Paragraph(f"<b>{b.get('breach_name', 'Unknown')}</b><br/><font color='#64748b'>{b.get('domain', '')}</font>", body_style),
                    Paragraph(str(b.get('breach_date', 'N/A')), body_style),
                    Paragraph(str(b.get('data_classes', 'Credentials; Profile Data')), body_style),
                    Paragraph(str(b.get('password_risk', 'unknown')).capitalize(), body_style)
                ])
                
            breach_table = Table(breach_table_data, colWidths=[2.0*inch, 0.8*inch, 3.2*inch, 1.0*inch])
            breach_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(breach_table)
        else:
            story.append(Paragraph("<b>No public breach records found</b>: Your email address was not identified in any known data dumps indexed by XposedOrNot.", body_style))
        story.append(Spacer(1, 10))

    # 4. Questionnaire Category Scores (If Mode B)
    cat_scores = assessment_data.get('category_scores', {})
    if cat_scores:
        story.append(Paragraph("Security Category Breakdown (Mode B Assessment)", section_heading))
        cat_table_data = [
            [Paragraph("<b>Category</b>", bold_body), Paragraph("<b>Risk Score (0-100)</b>", bold_body), Paragraph("<b>Posture</b>", bold_body)]
        ]
        for cat, score in cat_scores.items():
            posture = "Hardened" if score <= 25 else "Moderate Risk" if score <= 50 else "High Risk" if score <= 75 else "Critical Vulnerability"
            cat_table_data.append([
                Paragraph(cat, body_style),
                Paragraph(f"{score}/100", bold_body),
                Paragraph(posture, body_style)
            ])
        cat_table = Table(cat_table_data, colWidths=[3.2*inch, 1.8*inch, 2.0*inch])
        cat_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(cat_table)
        story.append(Spacer(1, 10))

    # 5. Network Privacy Overview (If HackMyIP present)
    ip_info = assessment_data.get('ip_info')
    if ip_info and ip_info.get('ip') != 'Unavailable':
        story.append(Paragraph("Network Privacy & Visitor IP Intelligence (HackMyIP)", section_heading))
        ip_table_data = [
            [
                Paragraph("<b>Visitor IP:</b>", body_style), Paragraph(str(ip_info.get('ip')), body_style),
                Paragraph("<b>Location:</b>", body_style), Paragraph(f"{ip_info.get('city', '')}, {ip_info.get('country', '')}", body_style)
            ],
            [
                Paragraph("<b>Network Org:</b>", body_style), Paragraph(f"{ip_info.get('isp_org', '')} ({ip_info.get('asn', '')})", body_style),
                Paragraph("<b>Proxy / VPN Status:</b>", body_style), Paragraph("Detected" if ip_info.get('is_vpn') or ip_info.get('is_proxy') else "Clean Residential Connection", body_style)
            ]
        ]
        ip_table = Table(ip_table_data, colWidths=[1.4*inch, 2.2*inch, 1.4*inch, 2.0*inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 10))

    # 6. Actionable Security Recommendations
    recommendations = assessment_data.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Prioritized Security Recommendations", section_heading))
        rec_table_data = [
            [
                Paragraph("<b>Priority</b>", bold_body),
                Paragraph("<b>Security Objective & Action Steps</b>", bold_body)
            ]
        ]
        
        for r in recommendations[:6]:
            p_color = '#ef4444' if r.get('priority') == 'Critical' else '#f97316' if r.get('priority') == 'High' else '#10b981'
            steps_fmt = "<br/>".join([f"• {s}" for s in r.get('action_steps', '').split('\n') if s.strip()])
            
            rec_cell = (
                f"<b>{r.get('title')}</b> ({r.get('category')})<br/>"
                f"<font color='#475569'>{r.get('reason')}</font><br/><br/>"
                f"<b>Implementation Steps:</b><br/>{steps_fmt}"
            )
            
            rec_table_data.append([
                Paragraph(f"<font color='{p_color}'><b>{r.get('priority', 'Medium').upper()}</b></font>", bold_body),
                Paragraph(rec_cell, body_style)
            ])
            
        rec_table = Table(rec_table_data, colWidths=[1.1*inch, 5.9*inch])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 12))

    # 7. Compliance, Limitations and Privacy Disclaimer
    disclaimer_block = [
        HRFlowable(width="100%", thickness=0.8, color=colors.HexColor('#cbd5e1'), spaceAfter=6),
        Paragraph("<b>Data Sources & Disclaimers:</b>", bold_body),
        Paragraph(
            "This report is generated by Digital Footprint Intelligence using publicly verifiable indexing data from "
            "XposedOrNot, HackMyIP, and user-provided privacy responses. This system <b>does not</b> access, read, or request "
            "passwords or private emails from Google, Microsoft, or third-party email providers. Breach indicators reflect "
            "publicly disclosed historical security incidents.",
            disclaimer_style
        )
    ]
    story.append(KeepTogether(disclaimer_block))

    # Build the document
    doc.build(story)
    return file_path, filename


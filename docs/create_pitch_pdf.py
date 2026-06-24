#!/usr/bin/env python3
"""
CTPPO Elevator Pitch PDF Generator
Creates a professional 2-page pitch deck
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import io

# Colors
PRIMARY_COLOR = HexColor('#1a365d')  # Dark blue
SECONDARY_COLOR = HexColor('#2c5282')  # Medium blue
ACCENT_COLOR = HexColor('#38a169')  # Green
LIGHT_BG = HexColor('#f7fafc')  # Light gray
WHITE = colors.white
BLACK = colors.black


def create_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()
    
    # Title style
    styles.add(ParagraphStyle(
        name='CustomTitle',
        parent=styles['Title'],
        fontSize=32,
        textColor=PRIMARY_COLOR,
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))
    
    # Subtitle
    styles.add(ParagraphStyle(
        name='Subtitle',
        parent=styles['Normal'],
        fontSize=16,
        textColor=SECONDARY_COLOR,
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica'
    ))
    
    # Section header
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=PRIMARY_COLOR,
        spaceBefore=20,
        spaceAfter=10,
        fontName='Helvetica-Bold'
    ))
    
    # Body text
    styles.add(ParagraphStyle(
        name='CustomBody',
        parent=styles['Normal'],
        fontSize=11,
        textColor=BLACK,
        spaceAfter=8,
        alignment=TA_JUSTIFY,
        leading=14
    ))
    
    # Bullet point
    styles.add(ParagraphStyle(
        name='CustomBullet',
        parent=styles['Normal'],
        fontSize=11,
        textColor=BLACK,
        leftIndent=20,
        spaceAfter=6,
        bulletIndent=10,
        leading=14
    ))
    
    # Stat number
    styles.add(ParagraphStyle(
        name='StatNumber',
        parent=styles['Normal'],
        fontSize=28,
        textColor=ACCENT_COLOR,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))
    
    # Stat label
    styles.add(ParagraphStyle(
        name='StatLabel',
        parent=styles['Normal'],
        fontSize=10,
        textColor=SECONDARY_COLOR,
        alignment=TA_CENTER
    ))
    
    # Footer
    styles.add(ParagraphStyle(
        name='Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=SECONDARY_COLOR,
        alignment=TA_CENTER
    ))
    
    return styles


def create_pitch_pdf(output_path):
    """Create the elevator pitch PDF."""
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    styles = create_styles()
    story = []
    
    # ==================== PAGE 1 ====================
    
    # Title
    story.append(Spacer(1, 30))
    story.append(Paragraph("🛡️ CTPPO", styles['CustomTitle']))
    story.append(Paragraph(
        "Cyber Threat Prioritization & Path Optimization",
        styles['Subtitle']
    ))
    
    # Tagline
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "<b>AI-Powered CVE Severity Classification & Attack Path Analysis</b>",
        ParagraphStyle(
            'Tagline',
            parent=styles['Normal'],
            fontSize=14,
            textColor=SECONDARY_COLOR,
            alignment=TA_CENTER,
            spaceAfter=30
        )
    ))
    
    # Problem Section
    story.append(Paragraph("THE PROBLEM", styles['SectionHeader']))
    story.append(Paragraph(
        "Security teams are drowning in vulnerability data. With <b>25,000+ new CVEs published annually</b> "
        "and growing, manual prioritization is impossible. Critical vulnerabilities slip through while teams "
        "waste time on low-priority issues.",
        styles['CustomBody']
    ))
    
    # Problem stats table
    problem_data = [
        ['25,000+', '73%', '$4.45M'],
        ['New CVEs per year', 'Security teams understaffed', 'Avg. cost of data breach']
    ]
    
    problem_table = Table(problem_data, colWidths=[2.2*inch, 2.2*inch, 2.2*inch])
    problem_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 24),
        ('TEXTCOLOR', (0, 0), (-1, 0), ACCENT_COLOR),
        ('FONTSIZE', (0, 1), (-1, 1), 9),
        ('TEXTCOLOR', (0, 1), (-1, 1), SECONDARY_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(Spacer(1, 15))
    story.append(problem_table)
    story.append(Spacer(1, 20))
    
    # Solution Section
    story.append(Paragraph("OUR SOLUTION", styles['SectionHeader']))
    story.append(Paragraph(
        "CTPPO uses <b>multi-modal deep learning</b> to automatically classify CVE severity and identify "
        "optimal attack paths. Our system combines natural language understanding with structured vulnerability "
        "data to deliver accurate, explainable predictions.",
        styles['CustomBody']
    ))
    
    # Features
    story.append(Spacer(1, 10))
    features = [
        "<b>🎯 Multi-Modal Classification:</b> Combines text descriptions with CVSS components, CWE types, and exploit indicators",
        "<b>🔍 Explainable AI:</b> Attention visualization shows WHY each prediction was made",
        "<b>🗺️ Attack Path Analysis:</b> NAMOA* algorithm finds ALL Pareto-optimal attack paths",
        "<b>📊 Real-Time Processing:</b> Analyze new CVEs as they're published"
    ]
    
    for feature in features:
        story.append(Paragraph(f"• {feature}", styles['CustomBullet']))
    
    # Key Metrics
    story.append(Spacer(1, 20))
    story.append(Paragraph("KEY METRICS", styles['SectionHeader']))
    
    metrics_data = [
        ['70.5%', '189K', '8', '93%'],
        ['F1 Score', 'CVEs Processed', 'CVSS Features', 'Coverage']
    ]
    
    metrics_table = Table(metrics_data, colWidths=[1.65*inch, 1.65*inch, 1.65*inch, 1.65*inch])
    metrics_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 22),
        ('TEXTCOLOR', (0, 0), (-1, 0), ACCENT_COLOR),
        ('FONTSIZE', (0, 1), (-1, 1), 9),
        ('TEXTCOLOR', (0, 1), (-1, 1), SECONDARY_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, SECONDARY_COLOR),
    ]))
    story.append(metrics_table)
    
    # Page break
    story.append(PageBreak())
    
    # ==================== PAGE 2 ====================
    
    # Technology Section
    story.append(Paragraph("TECHNOLOGY STACK", styles['SectionHeader']))
    
    tech_data = [
        ['Component', 'Technology', 'Purpose'],
        ['Text Analysis', 'DistilBERT', 'NLP understanding of CVE descriptions'],
        ['Multi-Modal Fusion', 'PyTorch', 'Combines text + structured features'],
        ['CVSS Processing', 'Custom Encoders', '8 vulnerability component features'],
        ['Attack Paths', 'NAMOA*', 'Multi-objective path optimization'],
        ['Explainability', 'Attention Viz', 'Transparent decision-making'],
    ]
    
    tech_table = Table(tech_data, colWidths=[1.8*inch, 1.8*inch, 3*inch])
    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, SECONDARY_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
    ]))
    story.append(tech_table)
    story.append(Spacer(1, 20))
    
    # Competitive Advantage
    story.append(Paragraph("COMPETITIVE ADVANTAGE", styles['SectionHeader']))
    
    comparison_data = [
        ['Feature', 'Traditional Tools', 'CTPPO'],
        ['Input Data', 'Text only', 'Multi-modal (text + 8 CVSS + CWE)'],
        ['Explainability', 'Black box', 'Full attention visualization'],
        ['Attack Paths', 'Single path or none', 'ALL Pareto-optimal paths'],
        ['Label Quality', 'Inconsistent NVD', 'CVSS-score derived'],
        ['Customization', 'Fixed rules', 'Trainable on your data'],
    ]
    
    comparison_table = Table(comparison_data, colWidths=[1.8*inch, 2.4*inch, 2.4*inch])
    comparison_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, SECONDARY_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ('TEXTCOLOR', (2, 1), (2, -1), ACCENT_COLOR),
        ('FONTNAME', (2, 1), (2, -1), 'Helvetica-Bold'),
    ]))
    story.append(comparison_table)
    story.append(Spacer(1, 20))
    
    # Use Cases
    story.append(Paragraph("USE CASES", styles['SectionHeader']))
    
    use_cases = [
        "<b>Security Operations Centers (SOC):</b> Automate CVE triage and prioritization",
        "<b>Vulnerability Management:</b> Focus remediation on highest-risk vulnerabilities",
        "<b>Penetration Testing:</b> Identify optimal attack paths for red team exercises",
        "<b>Compliance:</b> Document risk-based prioritization decisions"
    ]
    
    for uc in use_cases:
        story.append(Paragraph(f"• {uc}", styles['CustomBullet']))
    
    story.append(Spacer(1, 20))
    
    # Roadmap
    story.append(Paragraph("ROADMAP", styles['SectionHeader']))
    
    roadmap_data = [
        ['Phase', 'Timeline', 'Deliverables'],
        ['Current', 'Jan 2026', '70.5% F1 model, NAMOA* integration'],
        ['Next', 'Feb 2026', '78-82% F1 with CVSS components'],
        ['Beta', 'Q2 2026', 'REST API, web dashboard'],
        ['Production', 'Q3 2026', 'Enterprise deployment, integrations'],
    ]
    
    roadmap_table = Table(roadmap_data, colWidths=[1.5*inch, 1.5*inch, 3.6*inch])
    roadmap_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_COLOR),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, SECONDARY_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
    ]))
    story.append(roadmap_table)
    story.append(Spacer(1, 25))
    
    # Contact Section
    story.append(Paragraph("CONTACT", styles['SectionHeader']))
    
    contact_info = """
    <b>Ruthvik Bandari</b><br/>
    MS Applied Artificial Intelligence<br/>
    Northeastern University<br/>
    <br/>
    📧 bandari.ru@northeastern.edu<br/>
    🔗 github.com/ruthvik/ctppo
    """
    
    story.append(Paragraph(contact_info, ParagraphStyle(
        'Contact',
        parent=styles['Normal'],
        fontSize=11,
        textColor=SECONDARY_COLOR,
        alignment=TA_CENTER,
        leading=16
    )))
    
    story.append(Spacer(1, 20))
    
    # Footer tagline
    story.append(Paragraph(
        "<i>\"Transforming vulnerability management with AI-powered intelligence\"</i>",
        ParagraphStyle(
            'FooterTagline',
            parent=styles['Normal'],
            fontSize=12,
            textColor=PRIMARY_COLOR,
            alignment=TA_CENTER,
            fontName='Helvetica-Oblique'
        )
    ))
    
    # Build PDF
    doc.build(story)
    print(f"✅ Elevator pitch PDF created: {output_path}")


if __name__ == "__main__":
    import os
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CTPPO_Elevator_Pitch.pdf")
    create_pitch_pdf(output_path)

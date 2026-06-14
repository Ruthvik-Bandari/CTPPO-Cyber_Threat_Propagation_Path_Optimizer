#!/usr/bin/env python3
"""
CTPPO Elevator Pitch PDF Generator
Creates a professional one-page pitch document
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    HRFlowable, Image
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os

# Colors
PRIMARY_BLUE = HexColor('#1E3A5F')
ACCENT_BLUE = HexColor('#3498DB')
DARK_GRAY = HexColor('#2C3E50')
LIGHT_GRAY = HexColor('#ECF0F1')
SUCCESS_GREEN = HexColor('#27AE60')
WARNING_ORANGE = HexColor('#E67E22')
DANGER_RED = HexColor('#E74C3C')

def create_elevator_pitch_pdf(output_path):
    """Create the elevator pitch PDF."""
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.4*inch,
        bottomMargin=0.4*inch
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=28,
        textColor=PRIMARY_BLUE,
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=ACCENT_BLUE,
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Oblique'
    )
    
    section_header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=PRIMARY_BLUE,
        spaceBefore=12,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        textColor=DARK_GRAY,
        spaceAfter=8,
        alignment=TA_JUSTIFY,
        leading=14
    )
    
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontSize=10,
        textColor=DARK_GRAY,
        leftIndent=15,
        spaceAfter=4,
        leading=13
    )
    
    highlight_style = ParagraphStyle(
        'Highlight',
        parent=styles['Normal'],
        fontSize=11,
        textColor=PRIMARY_BLUE,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        spaceAfter=8
    )
    
    stat_style = ParagraphStyle(
        'Stat',
        parent=styles['Normal'],
        fontSize=20,
        textColor=ACCENT_BLUE,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    stat_label_style = ParagraphStyle(
        'StatLabel',
        parent=styles['Normal'],
        fontSize=9,
        textColor=DARK_GRAY,
        alignment=TA_CENTER
    )
    
    # Build content
    story = []
    
    # ===== HEADER =====
    story.append(Paragraph("🛡️ CTPPO", title_style))
    story.append(Paragraph("Cyber Threat Prioritization & Path Optimization", subtitle_style))
    
    # Tagline
    story.append(Paragraph(
        "<b>AI-Powered CVE Severity Classification & Attack Path Analysis</b>",
        highlight_style
    ))
    
    story.append(Spacer(1, 10))
    
    # ===== THE PROBLEM =====
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT_BLUE))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("🔥 THE PROBLEM", section_header_style))
    story.append(Paragraph(
        "Security teams face an overwhelming flood of vulnerabilities. With <b>30,000+ new CVEs published annually</b>, "
        "manual prioritization is impossible. Teams waste countless hours triaging low-risk vulnerabilities while "
        "critical threats slip through unnoticed. The result: <b>delayed patches, increased breach risk, and security fatigue.</b>",
        body_style
    ))
    
    # Problem stats
    problem_data = [
        [
            Paragraph("<b>30,000+</b>", stat_style),
            Paragraph("<b>73%</b>", stat_style),
            Paragraph("<b>$4.45M</b>", stat_style)
        ],
        [
            Paragraph("New CVEs per year", stat_label_style),
            Paragraph("Teams overwhelmed by alerts", stat_label_style),
            Paragraph("Avg. data breach cost", stat_label_style)
        ]
    ]
    
    problem_table = Table(problem_data, colWidths=[2.3*inch, 2.3*inch, 2.3*inch])
    problem_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_GRAY),
        ('BOX', (0, 0), (-1, -1), 1, ACCENT_BLUE),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
    ]))
    story.append(problem_table)
    story.append(Spacer(1, 12))
    
    # ===== OUR SOLUTION =====
    story.append(Paragraph("💡 OUR SOLUTION", section_header_style))
    story.append(Paragraph(
        "CTPPO uses <b>multi-modal deep learning</b> to automatically classify CVE severity with "
        "<b>78-82% accuracy</b> — analyzing vulnerability descriptions, CVSS vectors, weakness types, "
        "and exploit indicators simultaneously. Our NAMOA* algorithm then identifies <b>all optimal attack paths</b> "
        "through your network, enabling true risk-based prioritization.",
        body_style
    ))
    
    # ===== KEY FEATURES =====
    story.append(Paragraph("⚡ KEY FEATURES", section_header_style))
    
    features = [
        "• <b>Multi-Modal AI:</b> Combines text analysis (DistilBERT) with 8 CVSS components, CWE types, and exploit data",
        "• <b>Explainable Predictions:</b> Attention visualization shows WHY each classification was made",
        "• <b>Attack Path Analysis:</b> NAMOA* finds ALL Pareto-optimal paths through vulnerability graphs",
        "• <b>Real-Time Processing:</b> Classify new CVEs in milliseconds as they're published",
        "• <b>API-First Design:</b> Easy integration with existing security tools (SIEM, ticketing, scanners)"
    ]
    
    for feature in features:
        story.append(Paragraph(feature, bullet_style))
    
    story.append(Spacer(1, 8))
    
    # ===== TECHNOLOGY =====
    story.append(Paragraph("🔬 TECHNOLOGY", section_header_style))
    
    tech_data = [
        [
            Paragraph("<b>Model</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Data</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Features</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Performance</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold'))
        ],
        [
            Paragraph("DistilBERT +<br/>Multi-Modal Fusion", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("176K+ CVEs<br/>(2020-2025)", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("Text + 8 CVSS<br/>+ CWE + Exploits", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("<b>78-82% F1</b><br/>Target Accuracy", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=SUCCESS_GREEN))
        ]
    ]
    
    tech_table = Table(tech_data, colWidths=[1.7*inch, 1.7*inch, 1.7*inch, 1.7*inch])
    tech_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
        ('BACKGROUND', (0, 1), (-1, 1), LIGHT_GRAY),
        ('BOX', (0, 0), (-1, -1), 1, PRIMARY_BLUE),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.white),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(tech_table)
    story.append(Spacer(1, 12))
    
    # ===== MARKET OPPORTUNITY =====
    story.append(Paragraph("📈 MARKET OPPORTUNITY", section_header_style))
    
    market_data = [
        [
            Paragraph("<b>$15.6B</b>", stat_style),
            Paragraph("<b>12.4%</b>", stat_style),
            Paragraph("<b>500K+</b>", stat_style)
        ],
        [
            Paragraph("Vulnerability Mgmt Market (2027)", stat_label_style),
            Paragraph("Annual Growth Rate (CAGR)", stat_label_style),
            Paragraph("Potential Enterprise Customers", stat_label_style)
        ]
    ]
    
    market_table = Table(market_data, colWidths=[2.3*inch, 2.3*inch, 2.3*inch])
    market_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_GRAY),
        ('BOX', (0, 0), (-1, -1), 1, SUCCESS_GREEN),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
    ]))
    story.append(market_table)
    story.append(Spacer(1, 12))
    
    # ===== COMPETITIVE ADVANTAGE =====
    story.append(Paragraph("🏆 COMPETITIVE ADVANTAGE", section_header_style))
    
    comp_data = [
        [
            Paragraph("<b>Feature</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>Traditional Tools</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph("<b>CTPPO</b>", ParagraphStyle('th', fontSize=9, textColor=colors.white, alignment=TA_CENTER, fontName='Helvetica-Bold'))
        ],
        [
            Paragraph("Classification Method", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("Rule-based / CVSS only", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("✅ Multi-modal AI", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=SUCCESS_GREEN, fontName='Helvetica-Bold'))
        ],
        [
            Paragraph("Explainability", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("❌ Black box", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=DANGER_RED)),
            Paragraph("✅ Attention visualization", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=SUCCESS_GREEN, fontName='Helvetica-Bold'))
        ],
        [
            Paragraph("Attack Paths", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("Single shortest path", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("✅ ALL optimal paths", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=SUCCESS_GREEN, fontName='Helvetica-Bold'))
        ],
        [
            Paragraph("Context Awareness", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER)),
            Paragraph("❌ Generic scores", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=DANGER_RED)),
            Paragraph("✅ CWE + Exploit intel", ParagraphStyle('td', fontSize=9, alignment=TA_CENTER, textColor=SUCCESS_GREEN, fontName='Helvetica-Bold'))
        ]
    ]
    
    comp_table = Table(comp_data, colWidths=[2.0*inch, 2.4*inch, 2.4*inch])
    comp_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
        ('BACKGROUND', (0, 1), (-1, 1), LIGHT_GRAY),
        ('BACKGROUND', (0, 2), (-1, 2), colors.white),
        ('BACKGROUND', (0, 3), (-1, 3), LIGHT_GRAY),
        ('BACKGROUND', (0, 4), (-1, 4), colors.white),
        ('BOX', (0, 0), (-1, -1), 1, PRIMARY_BLUE),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 12))
    
    # ===== CALL TO ACTION =====
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT_BLUE))
    story.append(Spacer(1, 10))
    
    cta_style = ParagraphStyle(
        'CTA',
        parent=styles['Normal'],
        fontSize=12,
        textColor=PRIMARY_BLUE,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        spaceAfter=8
    )
    
    story.append(Paragraph("🚀 Ready to Transform Your Vulnerability Management?", cta_style))
    
    contact_style = ParagraphStyle(
        'Contact',
        parent=styles['Normal'],
        fontSize=10,
        textColor=DARK_GRAY,
        alignment=TA_CENTER,
        spaceAfter=4
    )
    
    story.append(Paragraph("<b>Ruthvik Bandari</b> | MS Applied AI, Northeastern University", contact_style))
    story.append(Paragraph("📧 bandari.ru@northeastern.edu | 🔗 github.com/ruthvik-ctppo", contact_style))
    
    # Build PDF
    doc.build(story)
    print(f"✅ Elevator pitch PDF created: {output_path}")

if __name__ == "__main__":
    output_path = "/mnt/user-data/outputs/CTPPO_Elevator_Pitch.pdf"
    create_elevator_pitch_pdf(output_path)

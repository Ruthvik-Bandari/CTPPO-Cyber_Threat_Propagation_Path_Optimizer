#!/usr/bin/env python3
"""
CTPPO PDF Report Generator
===========================

Generates professional security assessment PDF reports.

Author: Ruthvik Bandari
Date: January 2026
"""

import io
from datetime import datetime
from typing import Dict, List, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class SecurityReportGenerator:
    """Generate PDF security reports."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1e3a5f')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#2563eb')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#374151')
        ))
        
        self.styles.add(ParagraphStyle(
            name='BodyTextCustom',
            parent=self.styles['BodyText'],
            fontSize=10,
            spaceBefore=6,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='High',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.HexColor('#ea580c'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Medium',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.HexColor('#ca8a04'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='Low',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.HexColor('#16a34a'),
            fontName='Helvetica-Bold'
        ))
    
    def generate_scan_report(self, scan_data: Dict[str, Any]) -> bytes:
        """
        Generate a PDF report from scan results.
        
        Args:
            scan_data: Dictionary containing scan results
            
        Returns:
            PDF file as bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("🛡️ CTPPO Security Assessment Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 12))
        
        # Report metadata
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563eb')))
        story.append(Spacer(1, 12))
        
        meta_data = [
            ['Target:', scan_data.get('target', 'N/A')],
            ['Scan Type:', scan_data.get('scan_type', 'N/A')],
            ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ]
        
        meta_table = Table(meta_data, colWidths=[1.5*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#374151')),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
        
        risk_summary = scan_data.get('risk_summary', {})
        risk_level = risk_summary.get('risk_level', 'UNKNOWN')
        
        # Risk level box
        risk_colors = {
            'CRITICAL': colors.HexColor('#dc2626'),
            'HIGH': colors.HexColor('#ea580c'),
            'MEDIUM': colors.HexColor('#ca8a04'),
            'LOW': colors.HexColor('#16a34a'),
        }
        risk_color = risk_colors.get(risk_level, colors.gray)
        
        risk_data = [[f"Overall Risk Level: {risk_level}"]]
        risk_table = Table(risk_data, colWidths=[6*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 16),
            ('PADDING', (0, 0), (-1, -1), 15),
            ('ROUNDEDCORNERS', [5, 5, 5, 5]),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 15))
        
        # Summary statistics - calculate from actual vulnerabilities if not provided
        vulns = scan_data.get('web_vulnerabilities', []) or scan_data.get('vulnerabilities', [])
        
        # Calculate severity breakdown if not provided
        severity_breakdown = risk_summary.get('severity_breakdown', {})
        if not severity_breakdown and vulns:
            severity_breakdown = {
                'CRITICAL': sum(1 for v in vulns if v.get('severity', '').upper() == 'CRITICAL'),
                'HIGH': sum(1 for v in vulns if v.get('severity', '').upper() == 'HIGH'),
                'MEDIUM': sum(1 for v in vulns if v.get('severity', '').upper() == 'MEDIUM'),
                'LOW': sum(1 for v in vulns if v.get('severity', '').upper() == 'LOW'),
                'INFO': sum(1 for v in vulns if v.get('severity', '').upper() == 'INFO'),
            }
        
        # Calculate total vulnerabilities
        total_vulns = risk_summary.get('total_vulnerabilities', 0)
        if not total_vulns and vulns:
            total_vulns = len(vulns)
        
        summary_text = f"""
        This security assessment identified <b>{total_vulns}</b> vulnerabilities 
        across <b>{risk_summary.get('total_hosts', 1)}</b> host(s) with <b>{risk_summary.get('total_open_ports', 0)}</b> open ports.
        """
        story.append(Paragraph(summary_text, self.styles['BodyTextCustom']))
        
        # Add cloud provider notice if detected
        cloud_info = scan_data.get('cloud_provider', {})
        if cloud_info and cloud_info.get('detected'):
            cloud_notice = f"""
            <b>☁️ Cloud Platform Detected: {cloud_info.get('name', 'Unknown').title()}</b><br/>
            {cloud_info.get('note', '')}
            """
            story.append(Spacer(1, 10))
            
            cloud_data = [[Paragraph(cloud_notice, self.styles['BodyTextCustom'])]]
            cloud_table = Table(cloud_data, colWidths=[6*inch])
            cloud_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#dbeafe')),
                ('PADDING', (0, 0), (-1, -1), 10),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#3b82f6')),
            ]))
            story.append(cloud_table)
            story.append(Spacer(1, 10))
        
        # Severity breakdown table
        severity_data = [
            ['Severity', 'Count'],
            ['Critical', str(severity_breakdown.get('CRITICAL', 0))],
            ['High', str(severity_breakdown.get('HIGH', 0))],
            ['Medium', str(severity_breakdown.get('MEDIUM', 0))],
            ['Low', str(severity_breakdown.get('LOW', 0))],
            ['Info', str(severity_breakdown.get('INFO', 0))],
        ]
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fee2e2')),  # Critical
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ffedd5')),  # High
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fef9c3')),  # Medium
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#dcfce7')),  # Low
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#dbeafe')),  # Info
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        # Discovered Services
        hosts = scan_data.get('hosts', [])
        if hosts:
            story.append(Paragraph("Discovered Services", self.styles['SectionHeader']))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
            
            for host in hosts:
                host_name = host.get('host', 'Unknown')
                story.append(Paragraph(f"Host: {host_name}", self.styles['SubSection']))
                
                ports = host.get('ports', [])
                if ports:
                    port_data = [['Port', 'State', 'Service', 'Version']]
                    for port in ports:
                        port_data.append([
                            str(port.get('port', '')),
                            port.get('state', ''),
                            port.get('service', ''),
                            port.get('version', '')[:30]
                        ])
                    
                    port_table = Table(port_data, colWidths=[1*inch, 1*inch, 1.5*inch, 2.5*inch])
                    port_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ]))
                    story.append(port_table)
                    story.append(Spacer(1, 10))
        
        # Vulnerabilities
        vulns = scan_data.get('web_vulnerabilities', []) or scan_data.get('vulnerabilities', [])
        if vulns:
            story.append(PageBreak())
            story.append(Paragraph("Vulnerability Details", self.styles['SectionHeader']))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
            
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(v.get('severity', 'INFO').upper(), 5))
            
            for i, vuln in enumerate(vulns_sorted, 1):
                severity = vuln.get('severity', 'INFO').upper()
                style_name = severity if severity in ['Critical', 'High', 'Medium', 'Low'] else 'BodyTextCustom'
                
                # Vulnerability header
                vuln_header = f"{i}. [{severity}] {vuln.get('name', 'Unknown Vulnerability')}"
                story.append(Paragraph(vuln_header, self.styles.get(severity, self.styles['SubSection'])))
                
                # Details table
                details = []
                if vuln.get('id'):
                    details.append(['ID:', vuln.get('id')])
                if vuln.get('url'):
                    details.append(['URL:', vuln.get('url')[:60]])
                if vuln.get('description'):
                    details.append(['Description:', vuln.get('description')[:200]])
                if vuln.get('solution'):
                    details.append(['Solution:', vuln.get('solution')[:200]])
                
                if details:
                    detail_table = Table(details, colWidths=[1.2*inch, 4.8*inch])
                    detail_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                    ]))
                    story.append(detail_table)
                
                story.append(Spacer(1, 10))
        
        # Recommendations
        recommendations = risk_summary.get('recommendations', [])
        if recommendations:
            story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
            
            for rec in recommendations:
                story.append(Paragraph(f"• {rec}", self.styles['BodyTextCustom']))
            
            story.append(Spacer(1, 20))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563eb')))
        story.append(Spacer(1, 10))
        
        footer_text = """
        <i>This report was generated by CTPPO (Cyber Threat Prioritization and Path Optimization).
        For questions or support, contact your security team.</i>
        """
        story.append(Paragraph(footer_text, self.styles['BodyTextCustom']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def generate_attack_path_report(self, path_data: Dict[str, Any]) -> bytes:
        """Generate PDF report for attack path analysis."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title
        story.append(Paragraph("🎯 Attack Path Analysis Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#dc2626')))
        story.append(Spacer(1, 20))
        
        # Risk Summary
        risk_summary = path_data.get('risk_summary', {})
        
        summary_data = [
            ['Metric', 'Value'],
            ['Overall Risk', risk_summary.get('overall_risk', 'N/A')],
            ['Total Paths', str(risk_summary.get('total_paths', 0))],
            ['Critical Paths', str(risk_summary.get('critical_paths', 0))],
            ['Total Vulnerabilities', str(risk_summary.get('total_vulnerabilities', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Attack Paths
        paths = path_data.get('paths', {})
        if paths:
            story.append(Paragraph("Discovered Attack Paths", self.styles['SectionHeader']))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
            
            for path_id, path_list in paths.items():
                story.append(Paragraph(f"Path: {path_id}", self.styles['SubSection']))
                
                for path in path_list[:3]:  # Show top 3 variants
                    vulns = path.get('vulnerabilities', [])
                    risk = path.get('risk_score', 0)
                    
                    story.append(Paragraph(f"Risk Score: {risk:.2f}", self.styles['BodyTextCustom']))
                    
                    if vulns:
                        path_steps = " → ".join([f"{v.get('source', '?')} ({v.get('cve_id', 'N/A')})" for v in vulns[:5]])
                        story.append(Paragraph(f"Path: {path_steps} → Target", self.styles['BodyTextCustom']))
                    
                    story.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()


# FastAPI endpoint integration
def create_pdf_endpoints(app):
    """Add PDF generation endpoints to FastAPI app."""
    from fastapi import HTTPException
    from fastapi.responses import Response
    
    generator = SecurityReportGenerator()
    
    @app.post("/api/reports/scan-pdf")
    async def generate_scan_pdf(scan_data: dict):
        """Generate PDF report from scan results."""
        try:
            pdf_bytes = generator.generate_scan_report(scan_data)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename=ctppo-scan-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
                }
            )
        except Exception as e:
            raise HTTPException(500, f"Failed to generate PDF: {str(e)}")
    
    @app.post("/api/reports/attack-path-pdf")
    async def generate_attack_path_pdf(path_data: dict):
        """Generate PDF report from attack path analysis."""
        try:
            pdf_bytes = generator.generate_attack_path_report(path_data)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename=ctppo-attack-path-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
                }
            )
        except Exception as e:
            raise HTTPException(500, f"Failed to generate PDF: {str(e)}")

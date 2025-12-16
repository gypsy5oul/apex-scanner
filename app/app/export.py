"""
Export functionality for PDF and CSV reports
Includes executive summary PDF generation
"""
import io
import csv
import json
import redis
from datetime import datetime
from typing import Dict, Any, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Redis connection
redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=10,
    decode_responses=True
)


def get_redis_client() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


class ReportExporter:
    """Export scan reports in various formats"""

    def __init__(self):
        self.redis = get_redis_client()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1a237e')
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#303f9f')
        ))

        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#424242')
        ))

        self.styles.add(ParagraphStyle(
            name='BodyTextCustom',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceBefore=5,
            spaceAfter=5
        ))

        self.styles.add(ParagraphStyle(
            name='CriticalText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#d32f2f')
        ))

        self.styles.add(ParagraphStyle(
            name='HighText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#f57c00')
        ))

    def export_to_csv(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> bytes:
        """Export vulnerabilities to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        headers = [
            'CVE ID', 'Severity', 'CVSS Score', 'Package', 'Installed Version',
            'Fixed Version', 'Fix Available', 'Attack Vector', 'Attack Complexity',
            'Privileges Required', 'Description', 'Scanner Source', 'Priority'
        ]
        writer.writerow(headers)

        # Data rows
        for vuln in vulnerabilities:
            cvss = vuln.get('cvss', {})
            metrics = cvss.get('metrics', {})
            priority = vuln.get('priority_score', {})

            row = [
                vuln.get('id', ''),
                vuln.get('severity', ''),
                cvss.get('base_score', ''),
                vuln.get('package', ''),
                vuln.get('installed_version', ''),
                vuln.get('fixed_version', ''),
                'Yes' if vuln.get('fix_available') else 'No',
                metrics.get('attack_vector', ''),
                metrics.get('attack_complexity', ''),
                metrics.get('privileges_required', ''),
                vuln.get('description', '')[:200],  # Truncate description
                vuln.get('source', ''),
                priority.get('level', '')
            ]
            writer.writerow(row)

        output.seek(0)
        return output.getvalue().encode('utf-8')

    def export_sbom_to_csv(
        self,
        scan_id: str,
        packages: List[Dict[str, Any]]
    ) -> bytes:
        """Export SBOM packages to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        headers = [
            'Package Name', 'Version', 'Type', 'Language', 'Licenses',
            'CPE', 'PURL'
        ]
        writer.writerow(headers)

        # Data rows
        for pkg in packages:
            licenses = pkg.get('licenses', [])
            if isinstance(licenses, list):
                licenses = ', '.join(str(l) for l in licenses)

            row = [
                pkg.get('name', ''),
                pkg.get('version', ''),
                pkg.get('type', ''),
                pkg.get('language', ''),
                licenses,
                pkg.get('cpe', ''),
                pkg.get('purl', '')
            ]
            writer.writerow(row)

        output.seek(0)
        return output.getvalue().encode('utf-8')

    def generate_executive_summary_pdf(
        self,
        scan_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        include_details: bool = False
    ) -> bytes:
        """Generate executive summary PDF report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        story = []

        # Title
        story.append(Paragraph(
            "Security Scan Executive Summary",
            self.styles['CustomTitle']
        ))

        # Scan Information
        story.append(Paragraph("Scan Overview", self.styles['SectionHeader']))

        scan_info = [
            ['Image Name:', scan_data.get('image_name', 'Unknown')],
            ['Scan ID:', scan_data.get('scan_id', 'Unknown')],
            ['Scan Date:', scan_data.get('scan_timestamp', datetime.now().isoformat())],
            ['Base OS:', scan_data.get('base_image_os', 'Unknown')],
            ['Total Packages:', str(scan_data.get('total_packages', 0))],
            ['Scanners Used:', scan_data.get('scanners_used', 'grype, trivy, syft')]
        ]

        info_table = Table(scan_info, colWidths=[2*inch, 4.5*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 20))

        # Risk Assessment
        story.append(Paragraph("Risk Assessment", self.styles['SectionHeader']))

        # Convert Redis string values to integers
        def to_int(val, default=0):
            try:
                return int(val) if val else default
            except (ValueError, TypeError):
                return default

        critical = to_int(scan_data.get('critical', 0))
        high = to_int(scan_data.get('high', 0))
        medium = to_int(scan_data.get('medium', 0))
        low = to_int(scan_data.get('low', 0))
        total = critical + high + medium + low

        # Determine overall risk
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = colors.HexColor('#d32f2f')
            risk_description = "Immediate action required. Critical vulnerabilities detected."
        elif high > 0:
            risk_level = "HIGH"
            risk_color = colors.HexColor('#f57c00')
            risk_description = "High priority remediation needed."
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_color = colors.HexColor('#ffc107')
            risk_description = "Scheduled remediation recommended."
        else:
            risk_level = "LOW"
            risk_color = colors.HexColor('#4caf50')
            risk_description = "No critical issues detected."

        risk_table = Table([
            ['Overall Risk Level:', risk_level],
            ['Assessment:', risk_description]
        ], colWidths=[2*inch, 4.5*inch])
        risk_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (1, 0), (1, 0), risk_color),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 20))

        # Vulnerability Summary
        story.append(Paragraph("Vulnerability Summary", self.styles['SectionHeader']))

        vuln_data = [
            ['Severity', 'Count', 'Fixable', '% of Total'],
            ['Critical', str(critical), str(scan_data.get('fixable_critical', 0)),
             f"{(critical/total*100):.1f}%" if total > 0 else "0%"],
            ['High', str(high), str(scan_data.get('fixable_high', 0)),
             f"{(high/total*100):.1f}%" if total > 0 else "0%"],
            ['Medium', str(medium), str(scan_data.get('fixable_medium', 0)),
             f"{(medium/total*100):.1f}%" if total > 0 else "0%"],
            ['Low', str(low), str(scan_data.get('fixable_low', 0)),
             f"{(low/total*100):.1f}%" if total > 0 else "0%"],
            ['Total', str(total), '-', '100%']
        ]

        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1.2*inch, 1.2*inch, 1.5*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#ffebee')),  # Critical row
            ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#fff3e0')),  # High row
            ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#fffde7')),  # Medium row
            ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#e8f5e9')),  # Low row
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#e3f2fd')),  # Total row
            ('FONTNAME', (0, 5), (-1, 5), 'Helvetica-Bold'),
            ('ROWHEIGHT', (0, 0), (-1, -1), 25),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 20))

        # Key Findings
        story.append(Paragraph("Key Findings", self.styles['SectionHeader']))

        findings = []
        if critical > 0:
            findings.append(f"• {critical} CRITICAL vulnerabilities require immediate attention")
        if high > 0:
            findings.append(f"• {high} HIGH severity vulnerabilities should be prioritized")

        fixable_critical = to_int(scan_data.get('fixable_critical', 0))
        fixable_high = to_int(scan_data.get('fixable_high', 0))
        if fixable_critical > 0 or fixable_high > 0:
            findings.append(f"• {fixable_critical + fixable_high} critical/high vulnerabilities have available fixes")

        # Multi-scanner insights
        grype_unique = to_int(scan_data.get('grype_unique_count', 0))
        trivy_unique = to_int(scan_data.get('trivy_unique_count', 0))
        if grype_unique > 0 or trivy_unique > 0:
            findings.append(f"• Multi-scanner analysis found {grype_unique + trivy_unique} additional vulnerabilities")

        if not findings:
            findings.append("• No critical or high severity vulnerabilities detected")
            findings.append("• Image appears to be in good security posture")

        for finding in findings:
            story.append(Paragraph(finding, self.styles['BodyTextCustom']))

        story.append(Spacer(1, 20))

        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))

        recommendations = []
        if critical > 0:
            recommendations.append("1. Immediately patch or update packages with critical vulnerabilities")
        if high > 0:
            recommendations.append("2. Schedule high priority patching for high severity issues")
        if fixable_critical + fixable_high > 0:
            recommendations.append("3. Apply available security patches for fixable vulnerabilities")
        recommendations.append("4. Implement regular scanning schedule for continuous monitoring")
        recommendations.append("5. Consider base image updates to reduce inherited vulnerabilities")

        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['BodyTextCustom']))

        # Top Critical/High Vulnerabilities (if details requested)
        if include_details and vulnerabilities:
            story.append(PageBreak())
            story.append(Paragraph("Top Priority Vulnerabilities", self.styles['SectionHeader']))

            # Filter and sort
            priority_vulns = [v for v in vulnerabilities
                           if v.get('severity', '').upper() in ['CRITICAL', 'HIGH']]
            priority_vulns = priority_vulns[:20]  # Top 20

            if priority_vulns:
                vuln_details = [['CVE ID', 'Severity', 'Package', 'Fix Available']]

                for v in priority_vulns:
                    vuln_details.append([
                        v.get('id', 'N/A'),
                        v.get('severity', 'N/A'),
                        f"{v.get('package', 'N/A')} ({v.get('installed_version', 'N/A')})",
                        'Yes' if v.get('fix_available') else 'No'
                    ])

                detail_table = Table(vuln_details, colWidths=[1.8*inch, 1*inch, 2.5*inch, 1*inch])
                detail_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('ROWHEIGHT', (0, 0), (-1, -1), 20),
                ]))
                story.append(detail_table)

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"Generated by Security Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
            ParagraphStyle(
                'Footer',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER
            )
        ))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    def generate_detailed_pdf(
        self,
        scan_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        packages: List[Dict[str, Any]] = None
    ) -> bytes:
        """Generate detailed vulnerability report PDF"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        story = []

        # Title
        story.append(Paragraph(
            "Detailed Vulnerability Report",
            self.styles['CustomTitle']
        ))

        # Image info
        story.append(Paragraph(
            f"Image: {scan_data.get('image_name', 'Unknown')}",
            self.styles['SubHeader']
        ))
        story.append(Paragraph(
            f"Scan Date: {scan_data.get('scan_timestamp', datetime.now().isoformat())}",
            self.styles['BodyTextCustom']
        ))
        story.append(Spacer(1, 20))

        # Group vulnerabilities by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        for severity in severity_order:
            severity_vulns = [v for v in vulnerabilities
                           if v.get('severity', '').upper() == severity]

            if severity_vulns:
                story.append(Paragraph(
                    f"{severity} Severity Vulnerabilities ({len(severity_vulns)})",
                    self.styles['SectionHeader']
                ))

                for vuln in severity_vulns[:50]:  # Limit per severity
                    cvss = vuln.get('cvss', {})
                    metrics = cvss.get('metrics', {})

                    vuln_info = f"""
                    <b>{vuln.get('id', 'N/A')}</b><br/>
                    Package: {vuln.get('package', 'N/A')} v{vuln.get('installed_version', 'N/A')}<br/>
                    CVSS Score: {cvss.get('base_score', 'N/A')} |
                    Attack Vector: {metrics.get('attack_vector', 'N/A')}<br/>
                    Fix Available: {'Yes - ' + vuln.get('fixed_version', '') if vuln.get('fix_available') else 'No'}
                    """
                    story.append(Paragraph(vuln_info, self.styles['BodyTextCustom']))
                    story.append(Spacer(1, 10))

                if len(severity_vulns) > 50:
                    story.append(Paragraph(
                        f"... and {len(severity_vulns) - 50} more {severity} vulnerabilities",
                        self.styles['BodyTextCustom']
                    ))

                story.append(Spacer(1, 15))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

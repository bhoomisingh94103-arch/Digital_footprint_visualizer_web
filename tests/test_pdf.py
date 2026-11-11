import os
import tempfile
from services.pdf_service import generate_pdf_report

def test_generate_pdf_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_data = {
            'assessment_id': 999,
            'scan_date': '2026-11-11 12:00:00 UTC',
            'email': 'security_audit@example.com',
            'risk_score': 65,
            'risk_level': 'High',
            'breach_count': 2,
            'breaches': [
                {
                    'breach_name': 'TestPortal Breach',
                    'domain': 'testportal.com',
                    'breach_date': '2025',
                    'data_classes': 'Passwords;Email addresses;Names',
                    'password_risk': 'plaintext'
                }
            ],
            'ip_info': {
                'ip': '203.0.113.1',
                'city': 'San Francisco',
                'country': 'US',
                'isp_org': 'Cloud Test Network',
                'asn': 'AS12345',
                'is_vpn': False,
                'is_proxy': False
            },
            'recommendations': [
                {
                    'title': 'Reset Exposed Passwords',
                    'category': 'Authentication',
                    'priority': 'Critical',
                    'reason': 'Credentials exposed in plaintext.',
                    'action_steps': '1. Change password\n2. Enable 2FA'
                }
            ]
        }
        
        file_path, filename = generate_pdf_report(sample_data, tmpdir, 'email')
        assert os.path.exists(file_path)
        assert filename.endswith('.pdf')
        assert os.path.getsize(file_path) > 1000


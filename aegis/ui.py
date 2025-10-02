"""
Simplified Streamlit UI for Aegis-Lite
======================================
Reduced complexity while maintaining functionality
"""

import streamlit as st
import json
import pandas as pd
import time
from aegis.database import get_all_assets, get_db_stats, init_db, clear_db
from aegis.cli import run_scan_logic
from aegis.utils import get_risk_level, safe_json_parse

# Page configuration
st.set_page_config(
    page_title="Aegis-Lite Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def show_system_info():
    """Display basic system information in sidebar"""
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        st.sidebar.subheader("💻 System Status")
        st.sidebar.metric("CPU Usage", f"{cpu:.1f}%")
        st.sidebar.metric("RAM Usage", f"{memory.percent:.1f}%")

        if cpu > 80 or memory.percent > 80:
            st.sidebar.warning("⚠️ High system usage!")

    except ImportError:
        st.sidebar.info("System monitoring not available")

def format_scan_results(assets):
    """Format scan results for display"""
    if not assets:
        return pd.DataFrame()

    df_data = []
    for asset in assets:
        try:
            # Parse JSON fields safely
            https_data = safe_json_parse(asset.get('ssl_vulnerabilities', '{}'))
            web_data = safe_json_parse(asset.get('web_vulnerabilities', '{}'))

            # Check for certificate expiry warning
            cert_warning = ""
            if https_data.get('cert_expires_soon'):
                days = https_data.get('days_until_expiry', 0)
                cert_warning = f"⚠️ Expires in {days} days"

            # Format row data
            risk_score = asset.get('score', 0)
            row = {
                'Domain': asset.get('domain', ''),
                'IP Address': asset.get('ip', 'Unknown'),
                'Open Ports': asset.get('ports', ''),
                'Risk Score': risk_score,
                'Risk Level': get_risk_level(risk_score),
                'HTTPS': '✅' if https_data.get('has_https') else '❌',
                'Certificate': cert_warning or ('✅ Valid' if https_data.get('valid_cert') else '❌ Invalid'),
                'Vulnerabilities': len(web_data.get('vulnerabilities', [])),
                'Last Scanned': asset.get('last_scanned', '')
            }
            df_data.append(row)

        except Exception as e:
            st.error(f"Error processing asset: {e}")
            continue

    return pd.DataFrame(df_data)

def main():
    """Main application function"""

    # Initialize database
    try:
        init_db()
    except Exception as e:
        st.error(f"Database initialization failed: {e}")
        return

    # Header
    st.title("🛡️ Aegis-Lite Security Scanner")
    st.markdown("**Ethical Attack Surface Scanner for Small-Medium Enterprises**")
    st.markdown("---")

    # Sidebar
    show_system_info()

    st.sidebar.markdown("---")
    st.sidebar.subheader("📋 Risk Level Guide")
    st.sidebar.markdown("""
    **Risk Scoring:**
    - 🔴 **Critical (70-100)**: Immediate attention required
    - 🟠 **High (50-69)**: Address promptly
    - 🟡 **Medium (30-49)**: Monitor and plan fixes
    - 🟢 **Low (1-29)**: Good security posture
    - ⚪ **None (0)**: No services detected
    """)

    st.sidebar.markdown("---")
    if st.sidebar.button("🗑️ Clear All Data"):
        try:
            clear_db()
            st.sidebar.success("Database cleared!")
            st.experimental_rerun()
        except Exception as e:
            st.sidebar.error(f"Failed to clear database: {e}")

    # Main tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Scan", "📊 Results", "📋 Report"])

    # Tab 1: Scanning
    with tab1:
        st.header("Domain Scanning")

        # Input section
        col1, col2 = st.columns([2, 1])

        with col1:
            domain = st.text_input(
                "🌐 Target Domain",
                placeholder="example.com",
                help="Enter the domain you want to scan"
            )

        with col2:
            st.markdown("**Options:**")
            ethical = st.checkbox("🤝 Ethical Mode", value=True)
            monitor = st.checkbox("📊 Monitor Resources")
            max_subdomains = st.number_input(
                "Max Subdomains", min_value=1, max_value=500, value=50
            )

        # Scan button
        if st.button("🚀 Start Scan", type="primary", disabled=not domain):
            if not domain:
                st.error("Please enter a domain name")
            else:
                # Create progress indicators
                progress_bar = st.progress(0)
                status_text = st.empty()

                try:
                    status_text.text("Initializing scan...")
                    progress_bar.progress(10)

                    status_text.text(f"Scanning {domain}...")
                    progress_bar.progress(30)

                    with st.spinner("Running security scan..."):
                        result = run_scan_logic(domain, ethical, monitor, max_subdomains)

                    progress_bar.progress(100)

                    # Show results
                    if result.get("success"):
                        st.success("✅ Scan completed successfully!")
                        st.balloons()

                        # Show summary
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Subdomains Found", result.get("subdomains_found", 0))
                        with col2:
                            st.metric("Successful Scans", result.get("successful_scans", 0))
                        with col3:
                            st.metric("Duration", f"{result.get('duration', 0):.1f}s")

                    else:
                        st.error("❌ Scan failed. Check the console for details.")

                except Exception as e:
                    st.error(f"Scan error: {e}")
                finally:
                    status_text.empty()

        # Information
        st.info("""
        **ℹ️ About Ethical Scanning:**
        - Respects rate limits and scanning best practices
        - Uses 2-second delays between requests
        - Focuses on common ports only in ethical mode
        """)

    # Tab 2: Results
    with tab2:
        st.header("📊 Scan Results")

        try:
            assets = get_all_assets()

            if assets:
                # Summary metrics
                st.subheader("📈 Summary")
                df = format_scan_results(assets)

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("Total Assets", len(assets))
                with col2:
                    avg_score = df['Risk Score'].mean() if not df.empty else 0
                    st.metric("Average Risk Score", f"{avg_score:.1f}")
                with col3:
                    high_risk = len(df[df['Risk Score'] >= 50]) if not df.empty else 0
                    st.metric("High+ Risk Assets", high_risk)
                with col4:
                    https_count = len(df[df['HTTPS'] == '✅']) if not df.empty else 0
                    st.metric("HTTPS Enabled", https_count)

                st.markdown("---")

                # Assets table
                st.subheader("🎯 Discovered Assets")
                if not df.empty:
                    # Color code risk scores
                    def color_risk_score(val):
                        if val >= 70:
                            return 'color: red; font-weight: bold'
                        elif val >= 50:
                            return 'color: orange; font-weight: bold'
                        elif val >= 30:
                            return 'color: goldenrod'
                        elif val > 0:
                            return 'color: green'
                        else:
                            return 'color: gray'

                    styled_df = df.style.map(color_risk_score, subset=['Risk Score'])
                    st.dataframe(styled_df, width='stretch')

                    # Vulnerability details
                    vuln_assets = []
                    for asset in assets:
                        web_data = safe_json_parse(asset.get('web_vulnerabilities', '{}'))
                        vulns = web_data.get('vulnerabilities', [])
                        if vulns:
                            for vuln in vulns:
                                vuln_assets.append({
                                    'Domain': asset['domain'],
                                    'Vulnerability': vuln.get('name', 'Unknown'),
                                    'Severity': vuln.get('severity', 'info').title(),
                                    'Template': vuln.get('template', 'unknown')
                                })

                    if vuln_assets:
                        st.subheader("🚨 Vulnerabilities Found")
                        vuln_df = pd.DataFrame(vuln_assets)
                        st.dataframe(vuln_df, use_container_width=True)

                        critical_count = len([v for v in vuln_assets if v['Severity'] in ['Critical', 'High']])
                        if critical_count > 0:
                            st.error(f"⚠️ Found {critical_count} critical/high severity vulnerabilities!")

            else:
                st.info("🔭 No scan results found. Run a scan first!")

        except Exception as e:
            st.error(f"Error loading results: {e}")

    # Tab 3: Report
    with tab3:
        st.header("📋 Security Report")

        try:
            assets = get_all_assets()
            stats = get_db_stats()

            if assets:
                # Executive Summary
                st.subheader("📊 Executive Summary")

                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Total Assets:** {stats['total_assets']}")
                    st.write(f"**Average Risk Score:** {stats['avg_score']:.1f}/100")
                    st.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}")

                with col2:
                    st.write(f"**Critical Risk:** {stats['critical_risk_assets']} assets")
                    st.write(f"**High Risk:** {stats['high_risk_assets']} assets")
                    st.write(f"**Medium Risk:** {stats['medium_risk_assets']} assets")
                    st.write(f"**Low Risk:** {stats['low_risk_assets']} assets")

                # Risk Distribution Chart
                st.subheader("📈 Risk Distribution")
                risk_data = {
                    'Risk Level': ['Critical (70+)', 'High (50-69)', 'Medium (30-49)', 'Low (1-29)'],
                    'Count': [
                        stats['critical_risk_assets'],
                        stats['high_risk_assets'],
                        stats['medium_risk_assets'],
                        stats['low_risk_assets']
                    ]
                }
                risk_df = pd.DataFrame(risk_data)
                st.bar_chart(risk_df.set_index('Risk Level'))

                # Key Findings
                st.subheader("🔍 Key Findings")

                https_count = 0
                total_vulns = 0
                expiring_certs = 0

                for asset in assets:
                    https_data = safe_json_parse(asset.get('ssl_vulnerabilities', '{}'))
                    web_data = safe_json_parse(asset.get('web_vulnerabilities', '{}'))

                    if https_data.get('has_https'):
                        https_count += 1

                    if https_data.get('cert_expires_soon'):
                        expiring_certs += 1

                    total_vulns += len(web_data.get('vulnerabilities', []))

                findings = []
                if stats['critical_risk_assets'] > 0:
                    findings.append(f"🔴 {stats['critical_risk_assets']} critical-risk assets require immediate attention")
                if stats['high_risk_assets'] > 0:
                    findings.append(f"🟠 {stats['high_risk_assets']} high-risk assets need prompt remediation")
                if https_count < len(assets):
                    findings.append(f"🟡 {len(assets) - https_count} assets lack HTTPS encryption")
                if expiring_certs > 0:
                    findings.append(f"⚠️ {expiring_certs} SSL certificates expire within 30 days")
                if total_vulns > 0:
                    findings.append(f"🟠 {total_vulns} total vulnerabilities discovered")
                if not findings:
                    findings.append("🟢 No critical security issues found")

                for finding in findings:
                    st.write(finding)

                # Export Section
                st.subheader("💾 Export Report")

                col1, col2 = st.columns(2)

                with col1:
                    # JSON Export
                    report_data = {
                        'summary': {
                            'total_assets': len(assets),
                            'critical_risk': stats['critical_risk_assets'],
                            'high_risk': stats['high_risk_assets'],
                            'medium_risk': stats['medium_risk_assets'],
                            'low_risk': stats['low_risk_assets'],
                            'avg_score': stats['avg_score']
                        },
                        'assets': [dict(asset) for asset in assets],
                        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S')
                    }

                    st.download_button(
                        label="📄 Download JSON Report",
                        data=json.dumps(report_data, indent=2),
                        file_name=f"aegis_report_{time.strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )

                with col2:
                    # CSV Export
                    csv_data = format_scan_results(assets).to_csv(index=False)

                    st.download_button(
                        label="📊 Download CSV Report",
                        data=csv_data,
                        file_name=f"aegis_assets_{time.strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )

                # Recommendations
                st.subheader("💡 Recommendations")

                recommendations = []
                if stats['critical_risk_assets'] > 0:
                    recommendations.append("🔴 **URGENT**: Address critical-risk assets immediately")
                if stats['high_risk_assets'] > 0:
                    recommendations.append("🟠 **HIGH PRIORITY**: Remediate high-risk vulnerabilities")
                if https_count < len(assets):
                    recommendations.append("🔒 Enable HTTPS for all web services")
                if expiring_certs > 0:
                    recommendations.append("🔄 Renew SSL certificates before expiry")

                # Standard recommendations
                recommendations.extend([
                    "📅 Conduct regular security assessments",
                    "🛡️ Implement security monitoring",
                    "📖 Keep software updated and patched",
                    "🔐 Use strong authentication mechanisms"
                ])

                for rec in recommendations:
                    st.write(rec)

            else:
                st.info("🔭 No data available for report generation. Run a scan first!")

        except Exception as e:
            st.error(f"Error generating report: {e}")

    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "🛡️ Aegis-Lite - Ethical Security Scanner for SMEs<br>"
        "Built for educational purposes - Use responsibly"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()

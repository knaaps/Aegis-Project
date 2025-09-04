import streamlit as st
import sqlite3
import subprocess
import psutil
import json
import pandas as pd
from aegis.database import get_all_assets, get_db_stats
from aegis.cli import run_scan_logic

st.set_page_config(
    page_title="Aegis-Lite Scanner",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Aegis-Lite: Ethical Attack Surface Scanner")
st.caption("Designed for Small-Medium Enterprises")

# Sidebar with system metrics
with st.sidebar:
    st.subheader("System Status")
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    st.metric("CPU Usage", f"{cpu:.1f}%")
    st.metric("RAM Usage", f"{ram:.1f}%")

    if cpu > 80 or ram > 80:
        st.warning("High resource usage detected!")

# Main tabs
tab1, tab2, tab3 = st.tabs(["🔍 Scan", "📊 Results", "📋 Report"])

with tab1:
    st.subheader("Domain Scanning")

    col1, col2 = st.columns([2, 1])

    with col1:
        domain = st.text_input(
            "Target Domain",
            placeholder="example.com",
            help="Enter the domain you want to scan (without http://)"
        )

    with col2:
        ethical = st.checkbox("Ethical Mode", value=True, help="Respect robots.txt and rate limits")
        monitor = st.checkbox("Resource Monitor", help="Track system resources during scan")

    if st.button("Start Scan", type="primary", disabled=not domain):
        with st.spinner(f"Scanning {domain}..."):
            try:
                result = run_scan_logic(domain, ethical, monitor)

                if result.get("success"):
                    st.success(f"✅ Scan completed! Found {result.get('successful_scans', 0)} assets")
                    st.balloons()
                else:
                    st.error("❌ Scan failed. Check the logs for details.")

            except Exception as e:
                st.error(f"Scan error: {e}")

with tab2:
    st.subheader("Scan Results")

    try:
        assets = get_all_assets()

        if assets:
            # Convert to DataFrame for better display
            df = pd.DataFrame(assets)

            # Display summary metrics
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Total Assets", len(assets))
            with col2:
                avg_score = df['score'].mean() if 'score' in df.columns else 0
                st.metric("Avg Risk Score", f"{avg_score:.1f}")
            with col3:
                high_risk = len(df[df['score'] > 50]) if 'score' in df.columns else 0
                st.metric("High Risk Assets", high_risk)
            with col4:
                with_ports = len(df[df['ports'].notna() & (df['ports'] != '')]) if 'ports' in df.columns else 0
                st.metric("Assets with Ports", with_ports)

            # Display assets table
            st.subheader("Assets")
            st.dataframe(
                df[['domain', 'ip', 'ports', 'score', 'last_scanned']],
                use_container_width=True
            )

            # Display vulnerabilities if any
            if any('vulnerabilities' in str(asset.get('web_vulnerabilities', '')) for asset in assets):
                st.subheader("Vulnerabilities")
                vuln_data = []
                for asset in assets:
                    try:
                        web_vulns = json.loads(asset.get('web_vulnerabilities', '{}'))
                        for vuln in web_vulns.get('vulnerabilities', []):
                            vuln_data.append({
                                'Domain': asset['domain'],
                                'Vulnerability': vuln.get('name', 'Unknown'),
                                'Severity': vuln.get('severity', 'info'),
                                'Template': vuln.get('template_id', '')
                            })
                    except:
                        continue

                if vuln_data:
                    st.dataframe(pd.DataFrame(vuln_data), use_container_width=True)
        else:
            st.info("No assets found. Run a scan first!")

    except Exception as e:
        st.error(f"Error loading results: {e}")

with tab3:
    st.subheader("Security Report")

    try:
        stats = get_db_stats()
        assets = get_all_assets()

        if assets:
            # Report summary
            st.write("### Executive Summary")
            st.write(f"""
            - **Total Assets Scanned**: {stats['total_assets']}
            - **Average Risk Score**: {stats['avg_score']:.1f}/100
            - **High Risk Assets**: {stats['high_risk_assets']} (>{50})
            - **Medium Risk Assets**: {stats['medium_risk_assets']} (20-50)
            - **Low Risk Assets**: {stats['low_risk_assets']} (≤20)
            """)

            # Export options
            col1, col2 = st.columns(2)

            with col1:
                if st.button("Download JSON Report"):
                    report_data = {
                        'summary': stats,
                        'assets': [dict(asset) for asset in assets],
                        'generated_at': pd.Timestamp.now().isoformat()
                    }

                    st.download_button(
                        label="📄 Download JSON",
                        data=json.dumps(report_data, indent=2),
                        file_name=f"aegis_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )

            with col2:
                if st.button("Download CSV Report"):
                    csv_data = pd.DataFrame([dict(asset) for asset in assets]).to_csv(index=False)

                    st.download_button(
                        label="📊 Download CSV",
                        data=csv_data,
                        file_name=f"aegis_assets_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
        else:
            st.info("No data available for report generation.")

    except Exception as e:
        st.error(f"Error generating report: {e}")

# Footer
st.markdown("---")
st.caption("🛡️ Aegis-Lite v1.5 - Ethical Security Scanner for SMEs")

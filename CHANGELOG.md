# Changelog

All notable changes to the Aegis project will be documented in this file.

## [1.1.0] - 2026-05-19

### Added
- **Interactive Cyber Range**: Introduced the "Threat Lab" terminal for real-time attack simulation (SQLi, RCE, Path Traversal).
- **Simulated WAF (Defense Shields)**: Implemented middleware-level Web Application Firewall logic with a toggleable dashboard control.
- **Interactive Scanning**: Added the ability to trigger a full DevSecOps scan directly from the web UI with automated redirection.
- **Enhanced Security Dashboard**: Completely redesigned the scan report with metric cards for severity, consolidated tool results, and modern dashboard aesthetics.
- **Team Implementation Guide**: Added a dedicated section to `README.md` explaining how to adopt Aegis patterns in professional environments.

### Changed
- **UI/UX Overhaul**: Redesigned the landing page into a professional "Security Control Center."
- **Flask Integration**: Added `/report`, `/run-scan`, and `/toggle-waf` routes to support new interactive features.
- **Report Template**: Optimized `report_template.html` for better readability and visual impact.

### Fixed
- Updated local run instructions to use the correct port (5001) and virtual environment activation steps.

---
## [1.0.0] - 2026-05-18

### Added
- Initial release of Aegis DevSecOps demo.
- Integration with Bandit (SAST), Safety (SCA), and Trivy (Container).
- Automated GitHub Actions pipeline.
- Policy Engine for unified security gatekeeping.
- Vulnerable Flask application with intentional security flaws.

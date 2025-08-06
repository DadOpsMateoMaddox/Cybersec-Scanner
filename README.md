# MultiThreatScanner 
*by Kevin Landry*

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Threat Level](https://img.shields.io/badge/threat%20level-MAXIMUM-red.svg)](README.md)

> *"Scanning threats so you don't have to lose sleep"*

## What is this thing?

MultiThreatScanner is Kevin Landry's answer to the age-old question: "How many different ways can my infrastructure be compromised today?" 

It's a comprehensive cybersecurity scanning tool that combines the reconnaissance capabilities of Nmap, the intelligence gathering power of Shodan, visual phishing detection using OpenCV, and automated alerting that actually works. Think of it as your paranoid security friend who never stops checking the locks.

## Why MultiThreatScanner?

Because running individual security tools is like trying to catch rain with a teacup while blindfolded. You need something that brings all the pain points together in one delightfully efficient package. This isn't just another port scanner that tells you "yep, port 80 is open" and calls it a day - it's a full-spectrum threat assessment platform that gives you the kind of insights that make you either sleep better at night or invest in stronger coffee.

Think of it as that one friend who's perpetually paranoid about security but is actually right 90% of the time. Annoying? Maybe. Useful? Absolutely.

### What it actually does:

- **Network Reconnaissance**: Uses Nmap to discover open ports, services, and vulnerabilities (because knowing is half the battle, and the other half is existential dread)
- **Threat Intelligence**: Leverages Shodan's massive database to see what the rest of the internet knows about your target (spoiler: it's probably more than you think)
- **SSL/TLS Analysis**: Checks certificate health because expired certs are about as useful as a chocolate teapot in a heatwave
- **Visual Phishing Detection**: Uses computer vision to spot phishing attempts (because humans are terrible at spotting fake websites, but great at clicking suspicious links)
- **Risk Assessment**: Calculates an overall risk score that tells you exactly how worried you should be (on a scale from "meh" to "update your resume")
- **Automated Alerting**: Sends email alerts when things go sideways (because manual monitoring is for people who enjoy pain)
- **Comprehensive Reporting**: Generates detailed reports that you can actually understand (revolutionary concept, I know)

## Installation

First, make sure you have Python 3.8+ installed. If you're still running Python 2.7, we need to have a serious conversation about your life choices.

*Also, this is 2025 - if you're not using virtual environments, you're living dangerously. Create one with `python -m venv venv` and activate it. Your future self will thank you.*

### Dependencies

```bash
pip install python-nmap shodan opencv-python requests urllib3
```

*(Don't know what pip is? Here's a [quick guide](https://pip.pypa.io/en/stable/installation/) - but if you're reading this and don't know pip, maybe start with "Hello World" before diving into cybersecurity tools)*

**Note**: Some dependencies might require additional system packages, and of course always run:
```bash
sudo apt/dnf update && sudo apt/dnf upgrade
```
*Because running outdated packages while building security tools is like locking your front door but leaving the windows wide open.*

- **Nmap**: You'll need the actual Nmap binary installed on your system
  - Ubuntu/Debian: `sudo apt-get install nmap`
  - macOS: `brew install nmap`
  - Windows: Download from [nmap.org](https://nmap.org/download.html)

- **OpenCV**: May require additional system libraries
  - Ubuntu/Debian: `sudo apt-get install python3-opencv`

### Clone and Setup

```bash
git clone https://github.com/yourusername/multithreatscanner.git
cd multithreatscanner
pip install -r requirements.txt  # (create this file with the dependencies above)
```

## Configuration

Create a `config.json` file to customize your scanning parameters:

```json
{
    "shodan_api_key": "your_actual_shodan_api_key_here",
    "email_settings": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "your_email@gmail.com",
        "password": "your_app_password",
        "alert_recipients": ["security@yourcompany.com", "sleepless@admin.com"]
    },
    "scan_settings": {
        "nmap_args": "-sS -sV -O -A --script vuln",
        "timeout": 300,
        "phishing_threshold": 0.8
    }
}
```

**Pro Tips**:

- Get a Shodan API key from [shodan.io](https://shodan.io) (the free tier is fine for testing, unless you're scanning the entire internet, in which case you have bigger problems)
- Use Gmail App Passwords for email authentication (regular passwords won't work because Google doesn't trust you, and honestly, they're probably right)
- The `nmap_args` can be customized based on your scanning needs and time constraints (and how much you enjoy watching progress bars)

## Usage

### Basic Scan
```bash
python MultiThreatScanner.py example.com
```

### Advanced Usage
```bash
# Scan with custom config
python MultiThreatScanner.py example.com --config config.json

# Include phishing detection with screenshot
python MultiThreatScanner.py example.com --screenshot suspicious_site.png

# Verbose output (for when you want to see all the gory details and pretend you understand what's happening)
python MultiThreatScanner.py example.com --verbose
```

### Sample Output

```
    ╔══════════════════════════════════════════════════════════════╗
    ║                    MultiThreatScanner v1.0                  ║
    ║                      by Kevin Landry                        ║
    ║                                                              ║
    ║    "Scanning threats so you don't have to lose sleep"       ║
    ╚══════════════════════════════════════════════════════════════╝

2024-08-05 15:30:15 - MultiThreatScanner - INFO - Starting comprehensive scan of example.com
2024-08-05 15:30:16 - MultiThreatScanner - INFO - Starting Nmap scan on example.com
2024-08-05 15:30:45 - MultiThreatScanner - INFO - Nmap scan completed. Found 3 potential issues.
2024-08-05 15:30:46 - MultiThreatScanner - INFO - Querying Shodan for intelligence on example.com
2024-08-05 15:30:47 - MultiThreatScanner - INFO - Shodan lookup completed successfully
2024-08-05 15:30:48 - MultiThreatScanner - INFO - Risk assessment complete. Score: 35/100 - MEDIUM - Some issues need attention

MultiThreatScanner Report
========================
Created by: Kevin Landry's MultiThreatScanner
Scan Date: 2024-08-05T15:30:15
Target: example.com

EXECUTIVE SUMMARY
=================
Risk Score: 35/100
Threat Level: MEDIUM - Some issues need attention
Total Vulnerabilities: 3

DETAILED FINDINGS
=================

1. OPEN_PORT
   Risk Level: HIGH
   Description: N/A
   Port: 22
   Service: ssh

2. OPEN_PORT
   Risk Level: MEDIUM
   Description: N/A
   Port: 80
   Service: http

3. SSL_EXPIRY
   Risk Level: MEDIUM
   Description: SSL certificate expires in 15 days

Scan completed by MultiThreatScanner - Because security never sleeps.
```

## Features Breakdown

### Network Scanning
Uses Nmap with sensible defaults but fully customizable. Detects:
- Open ports and running services
- Service versions and potential vulnerabilities
- Operating system fingerprinting
- Common vulnerability scripts

### Threat Intelligence
Integrates with Shodan to provide:
- Known vulnerabilities (CVEs) for the target
- Historical scanning data
- Geolocation and ISP information
- Additional context that manual scanning might miss

### Phishing Detection
Computer vision-based detection that:
- Compares website screenshots against known phishing templates
- Configurable confidence thresholds
- Can be extended with custom phishing databases

### Risk Assessment
Calculates a numerical risk score based on:
- **CRITICAL** vulnerabilities: 25 points each
- **HIGH** risk issues: 15 points each  
- **MEDIUM** risk issues: 10 points each
- **LOW** risk issues: 5 points each

### Automated Alerting
Sends email alerts when:
- Risk score exceeds configurable thresholds
- Critical vulnerabilities are detected
- Phishing attempts are identified

## Exit Codes

MultiThreatScanner uses exit codes for automation-friendly operation:

- `0`: Success (Low risk, score < 25)
- `1`: Warning (Medium risk, score 25-74)  
- `2`: Critical (High risk, score >= 75)

Perfect for integrating into CI/CD pipelines or monitoring systems.

## File Outputs

- **Scan logs**: `multithreat_scan.log`
- **Detailed reports**: `multithreat_report_[target]_[timestamp].txt`
- **JSON results**: Available programmatically via the scanner object

## Limitations and Disclaimers

### Legal Stuff
- **Only scan systems you own or have explicit permission to test**
- This tool is for defensive security purposes
- The author (Kevin Landry) is not responsible for misuse
- Always comply with local laws and regulations

### Technical Limitations

- Nmap scans require appropriate permissions (may need sudo for some scan types, because security tools love making you feel powerless)
- Shodan integration requires a valid API key (free tier available, premium tier for those with deeper pockets and commitment issues)
- Phishing detection is only as good as your template database (garbage in, garbage out - a universal law of computing)
- SSL analysis only works on HTTPS-enabled targets (shocking, I know)
- Some scans may trigger security alerts on the target system (because irony is a beautiful thing)

### Performance Notes

- Full scans can take several minutes depending on target size (perfect time to grab coffee, contemplate life choices, or both)
- Network timeouts are configurable but may need adjustment (because the internet doesn't care about your schedule)
- Large targets may require scan segmentation (divide and conquer, just like your will to live)

## Troubleshooting

### Common Issues

**"Import X could not be resolved"**
- Make sure all dependencies are installed: `pip install -r requirements.txt`
- For system-level dependencies, check the installation section

**"Nmap scan failed"**
- Ensure Nmap binary is installed and accessible
- Check if you need elevated privileges for the scan type
- Verify the target is reachable

**"Shodan API error"**
- Verify your API key is correct and active
- Check your Shodan account query limits
- Ensure the target IP is in Shodan's database

**"SSL analysis failed"**
- Target may not support HTTPS
- Certificate issues on the target side
- Network connectivity problems

**"Email alerts not working"**
- Check SMTP settings and credentials
- Use app passwords for Gmail (not your regular password)
- Verify firewall/network allows SMTP connections

### Debug Mode
Run with `--verbose` flag to see detailed execution information:
```bash
python MultiThreatScanner.py example.com --verbose
```

## Contributing

Found a bug? Want to add a feature? Kevin Landry welcomes contributions, but please:

1. Fork the repository
2. Create a feature branch
3. Add tests if applicable
4. Submit a pull request with a clear description

### Development Setup
```bash
git clone https://github.com/yourusername/multithreatscanner.git
cd multithreatscanner
pip install -r requirements-dev.txt  # includes testing dependencies
```

## Future Enhancements

- Web interface for easier management
- Database storage for historical scan data
- Integration with additional threat intelligence sources
- Custom vulnerability scoring algorithms
- Mobile app for alert notifications
- Docker containerization
- Multi-threading for faster scans

## Credits

- **Author**: Kevin Landry
- **Nmap**: The Network Mapper team
- **Shodan**: John Matherly and the Shodan team
- **OpenCV**: The OpenCV development team
- **Coffee**: For making this possible

## License

MIT License - because sharing is caring, but attribution is appreciated.

---

## Final Words

MultiThreatScanner was built out of frustration with having to run multiple tools to get a complete picture of security posture. It's not perfect, but it's a hell of a lot better than manually running each tool separately and trying to correlate the results while your coffee gets cold and your sanity slowly evaporates.

If this tool helps you sleep better at night (or at least know why you shouldn't), then Kevin Landry's job here is done. If it doesn't help, well, at least you learned something about Python and disappointment.

Remember: Security is not a destination, it's a journey. And sometimes that journey involves automated tools that do the boring stuff so you can focus on the interesting problems (like explaining to management why the budget for "more security tools" isn't actually a request for new office coffee machines).

Stay paranoid, stay secure, and remember that the only thing scarier than finding vulnerabilities is *not* finding them.

**- Kevin Landry**

---

**"The best time to fix a security vulnerability was yesterday. The second best time is now."**

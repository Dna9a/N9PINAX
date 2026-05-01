# *Network-Scanning_tool*
## Network Device Scanner with Visual Dashboard
Build your own lightweight network scanner (not just using Nmap directly), including device fingerprinting with MAC vendor lookup and a visual dashboard.

### Core Features
- Discover hosts on local network.
- Scan common ports and basic service info.
- Identify manufacturer via MAC OUI lookup.
- Show results in a dashboard.

### Suggested Stack

- Flask (web interface)
- Optional Raspberry Pi deployment
- login page with bcrypt
- or GitHub OAuth

### Cybersecurity Focus
- Secure the dashboard (authentication, input validation, rate limiting).
- Secure scanner execution and stored scan data.

## Important Note
Github will be the middle point for the project, so all the code and documentation will be there, and we will use it to track our progress and share our work. We will also use it to collaborate and communicate with each other.

## ``Dna9a's`` Part :
- The whole Python program using `Scapy`
- Python + Scapy (packet crafting and discovery)

### Python script content
- Scan the network list Ip and mac address
- List MAC manufacturer
- Makefile (for dependencies, installation, and runtime)
- Server security input validation, rate limiting.
- Report generation (PDF/HTML) using python libraries like `reportlab` or `weasyprint`.

## ``Dbvonie's`` Part :
- Server-side logic and Flask app
- Flask (web interface)
- login page with bcrypt
- or GitHub OAuth
- Flask and Ui interface (Style frontend and backend)

### Interface Part :
- Animations
- Dashboard (Visualization of scan results)
- + Plus (parsing of scan results and display them in a user-friendly way)
- Authentication page login.... 
- README.md (Documentation)
- Notification system (alerts for new devices or suspicious activity using a websocket or polling mechanism)
- Security measures (input validation, rate limiting, secure storage of scan data)




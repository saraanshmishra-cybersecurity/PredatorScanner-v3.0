import aiohttp
import asyncio

class Scanner:
    def __init__(self, url):
        self.url = url
        # 10 High-impact payloads
        self.payloads = [
            {"type": "SQLi", "payload": "'", "risk": "Low", "desc": "SQLi: Basic syntax disruption"},
            {"type": "SQLi", "payload": "''", "risk": "Medium", "desc": "SQLi: Tautology bypass attempt"},
            {"type": "SQLi", "payload": "' OR '1'='1", "risk": "Critical", "desc": "SQLi: Auth Bypass pattern"},
            {"type": "SQLi", "payload": "'; WAITFOR DELAY '0:0:5'--", "risk": "High", "desc": "SQLi: Blind inference delay"},
            {"type": "SQLi", "payload": "UNION SELECT NULL,@@version--", "risk": "Critical", "desc": "SQLi: Data Extraction"},
            {"type": "XSS", "payload": "<script>alert(1)</script>", "risk": "Medium", "desc": "Basic XSS Injection"},
            {"type": "XSS", "payload": "<img src=x onerror=alert(1)>", "risk": "High", "desc": "XSS: Event Handler bypass"},
            {"type": "XSS", "payload": "javascript:alert(1)//", "risk": "Medium", "desc": "XSS: Protocol-based Injection"},
            {"type": "XSS", "payload": "<details open ontoggle=alert(1)>", "risk": "High", "desc": "XSS: HTML5 Element Injection"},
            {"type": "XSS", "payload": "><svg/onload=alert(1)>", "risk": "Critical", "desc": "XSS: SVG Filter Bypass"}
        ]

    def _infer_location(self, vuln_type):
        if vuln_type == "SQLi":
            return "Server-Side Database Query Layer"
        return "Client-Side DOM / Application Response Body"

    async def _test_payload(self, session, item):
        target = f"{self.url}{item['payload']}"
        results = []
        try:
            async with session.get(target, timeout=5) as response:
                text = await response.text()
                detected = False
                if item['type'] == "SQLi":
                    if any(err in text.lower() for err in ["sql syntax", "mysql", "sqlite", "postgresql"]):
                        detected = True
                elif item['type'] == "XSS":
                    if item['payload'] in text:
                        detected = True

                if detected:
                    results.append({
                        "type": "Cross-Site Scripting (XSS)" if item['type'] == "XSS" else "SQL Injection",
                        "payload": item['payload'],
                        "risk": item['risk'],
                        "impact": item['desc'],
                        "location": self._infer_location(item['type'])
                    })
        except: pass
        return results

    async def scan_all(self):
        vulnerabilities = []
        async with aiohttp.ClientSession() as session:
            tasks = [self._test_payload(session, p) for p in self.payloads]
            finished_tasks = await asyncio.gather(*tasks)
            for sublist in finished_tasks: vulnerabilities.extend(sublist)
        return vulnerabilities
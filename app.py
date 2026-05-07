from flask import Flask, render_template, request, session, redirect, url_for
import asyncio
from scanner import Scanner
import datetime
import json
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
HISTORY_FILE = 'scan_history.json'

def manage_history(new_entry=None):
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            try:
                history = json.load(f)
            except:
                history = []
    if new_entry:
        history.insert(0, new_entry)
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history[:10], f)
    return history

@app.route('/', methods=['GET', 'POST'])
def index():
    report_data = None
    url_input = ""
    
    # Handle Re-scans from Sidebar
    rescan_url = request.args.get('rescan')
    if rescan_url:
        url_input = rescan_url

    if request.method == 'POST':
        target_url = request.form.get('url')
        if target_url:
            if not target_url.startswith('http'): 
                target_url = 'http://' + target_url
            
            engine = Scanner(target_url)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                vulnerabilities = loop.run_until_complete(engine.scan_all())
            finally:
                loop.close()
            
            status = "vulnerable" if vulnerabilities else "secure"
            report_data = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                "url": target_url,
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities),
                "status": status
            }
            
            manage_history(report_data)
            
            # Use session to pass data across the redirect
            session['temp_report'] = report_data
            session['temp_url'] = target_url
            return redirect(url_for('index', show_results='true'))

    if request.args.get('show_results') == 'true':
        report_data = session.get('temp_report')
        url_input = session.get('temp_url')
        # Pop results so refresh clears them
        session.pop('temp_report', None)
        session.pop('temp_url', None)

    # TECHNICAL FIX: Ensure url_input is an empty string, not None
    if url_input is None:
        url_input = ""

    return render_template('index.html', 
                           history=manage_history(), 
                           report=report_data, 
                           url_val=url_input,
                           datetime=datetime)

if __name__ == '__main__':
    app.run(debug=True, threaded=False)
import os
import time
import json
import csv
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import html
import sys

# ================= 設定值 =================
BURP_API_URL = "http://localhost:1337/v0.1"
API_KEY = ""  # 若有設定請填入
MAX_RETRIES = 5
# =========================================

# 全域變數
scan_states = {}
all_session_results = []
issue_definitions_map = {}
completed_tasks = 0
total_tasks = 0
lock = threading.Lock()
stop_dashboard_flag = False
CURRENT_SCAN_CONFIG = "Crawl and Audit - Fast"
API_ONLINE = False

# [NEW] 日誌與時間記錄
scan_logs = []  # 所有日誌記錄
scan_time_records = {}  # 各站點時間記錄 {url: {start, end, duration}}
session_start_time = None
session_end_time = None

class ANSI:
    CYAN, GREEN, YELLOW, RED, RESET, BOLD = '\033[96m', '\033[92m', '\033[93m', '\033[91m', '\033[0m', '\033[1m'
    GREY = '\033[90m'
    CLEAR = 'cls' if os.name == 'nt' else 'clear'

def clear_screen():
    os.system(ANSI.CLEAR)

# [NEW] 日誌記錄函數
def log_event(level, message, url=None):
    """記錄事件到日誌系統"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "level": level,  # INFO, WARNING, ERROR, SUCCESS
        "message": message,
        "url": url
    }
    with lock:
        scan_logs.append(log_entry)
    
    # 同時輸出到控制台(可選)
    if level == "ERROR":
        print(f"{ANSI.RED}[{level}] {message}{ANSI.RESET}")

# --- 0. API 檢查與 KB 載入 ---
def check_api_and_load_kb():
    global API_ONLINE, issue_definitions_map
    headers = {}
    if API_KEY: headers["X-Burp-API-Key"] = API_KEY
    
    try:
        requests.get(f"{BURP_API_URL.replace('/v0.1','')}/api-definition", headers=headers, timeout=2)
        API_ONLINE = True
        log_event("INFO", "Burp API 連線成功")
        
        if not issue_definitions_map:
            print(f"\n{ANSI.CYAN}[*] 偵測到 Burp 上線,正在載入知識庫...{ANSI.RESET}")
            try:
                resp = requests.get(f"{BURP_API_URL}/knowledge_base/issue_definitions", headers=headers, timeout=10)
                if resp.status_code == 200:
                    defs = resp.json()
                    for d in defs:
                        try:
                            if d.get("issue_type_id"):
                                issue_definitions_map[int(d.get("issue_type_id"), 16)] = d
                        except: pass
                    print(f"{ANSI.GREEN}[+] 知識庫載入完成 (共 {len(issue_definitions_map)} 筆){ANSI.RESET}")
                    log_event("SUCCESS", f"知識庫載入完成: {len(issue_definitions_map)} 筆定義")
                    time.sleep(1.5)
                else:
                    log_event("ERROR", f"知識庫載入失敗: HTTP {resp.status_code}")
            except Exception as e:
                log_event("ERROR", f"知識庫載入錯誤: {e}")
        return True
    except:
        API_ONLINE = False
        log_event("WARNING", "Burp API 離線")
        return False

# --- 1. 合併資料邏輯 ---
def merge_issue_data(issue):
    type_idx = issue.get("type_index")
    definition = issue_definitions_map.get(type_idx, {})
    if not issue.get("issue_background"): issue["issue_background"] = definition.get("description", "")
    if not issue.get("remediation_background"): issue["remediation_background"] = definition.get("remediation", "")
    if not issue.get("references") and definition.get("references"): issue["references"] = definition.get("references")
    if not issue.get("description"): issue["description"] = issue.get("issue_background", "")
    return issue

# --- 2. 掃描策略選擇 ---
def select_scan_config():
    global CURRENT_SCAN_CONFIG
    configs = [
        "Crawl and Audit - Fast", "Crawl and Audit - Balanced", 
        "Crawl and Audit - Deep", "Crawl and Audit - Lightweight", "Audit checks - All issues"
    ]
    print(f"\n{ANSI.BOLD}請選擇掃描策略 (Scan Configuration):{ANSI.RESET}")
    for idx, cfg in enumerate(configs): print(f"{idx + 1}. {cfg}")
    choice = input(f"請輸入選項 (預設 1 - Fast): ").strip()
    try: idx = int(choice) - 1; CURRENT_SCAN_CONFIG = configs[idx] if 0 <= idx < len(configs) else configs[0]
    except: CURRENT_SCAN_CONFIG = configs[0]
    print(f"{ANSI.GREEN}已設定策略為: {CURRENT_SCAN_CONFIG}{ANSI.RESET}\n")
    log_event("INFO", f"掃描策略設定: {CURRENT_SCAN_CONFIG}")
    time.sleep(1)

# --- 3. 報告生成器 (增強版) ---
def generate_reports(url, issues, output_dir, scan_config, task_id="-", start_time=None, end_time=None):
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = url.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "_")
    enriched_issues = [merge_issue_data(i) for i in issues]
    
    # 計算掃描時長
    duration_seconds = None
    if start_time and end_time:
        duration_seconds = (end_time - start_time).total_seconds()
    
    # JSON
    json_filename = os.path.join(output_dir, f"{timestamp_str}_Data_{safe_name}.json")
    try:
        json_data = {
            "target_url": url,
            "scan_configuration": scan_config,
            "task_id": task_id,
            "scan_start_time": start_time.isoformat() if start_time else None,
            "scan_end_time": end_time.isoformat() if end_time else None,
            "scan_duration_seconds": duration_seconds,
            "generated_at": datetime.now().isoformat(),
            "issue_count": len(enriched_issues),
            "issues": enriched_issues
        }
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=4)
    except Exception as e:
        log_event("ERROR", f"JSON 生成錯誤: {e}", url)

    # HTML (增強版 - 加入時間資訊)
    def normalize_severity(raw_sev):
        s = str(raw_sev).lower() if raw_sev else ""
        if "high" in s: return "High"
        if "medium" in s: return "Medium"
        if "low" in s: return "Low"
        return "Information"

    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Information": 3}
    processed_issues = []
    for issue in enriched_issues:
        norm_sev = normalize_severity(issue.get('severity', 'Information'))
        issue['_normalized_severity'] = norm_sev
        if norm_sev in severity_counts: severity_counts[norm_sev] += 1
        processed_issues.append(issue)
    processed_issues.sort(key=lambda x: severity_order.get(x['_normalized_severity'], 4))

    html_filename = os.path.join(output_dir, f"{timestamp_str}_Report_{safe_name}.html")
    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f9f9f9; color: #333; margin: 0; padding: 20px; }
    .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    h1 { border-bottom: 2px solid #e04006; padding-bottom: 10px; color: #e04006; }
    .meta { background: #eee; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
    .time-info { background: #d4edda; padding: 10px; margin-bottom: 20px; border-radius: 4px; border-left: 4px solid #28a745; }
    .summary-box { display: flex; gap: 10px; margin-bottom: 30px; }
    .stat-card { flex: 1; padding: 15px; text-align: center; color: #fff; border-radius: 4px; font-weight: bold; }
    .High { background: #ff3333; } .Medium { background: #ff9933; } .Low { background: #3399ff; } .Information { background: #808080; }
    details { margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; overflow: hidden; }
    summary { padding: 12px; cursor: pointer; background: #f1f1f1; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
    .issue-content { padding: 20px; background: #fff; border-top: 1px solid #ddd; }
    .tag { padding: 3px 8px; border-radius: 10px; font-size: 0.8em; color: white; margin-right: 10px; }
    .path { font-family: monospace; color: #555; background: #eee; padding: 2px 5px; border-radius: 3px; word-break: break-all; }
    .section-title { font-size: 1.1em; font-weight: bold; margin-top: 20px; margin-bottom: 10px; color: #e04006; border-left: 4px solid #e04006; padding-left: 8px; }
    .bg-section { color: #555; font-size: 0.95em; }
    """
    
    # 時間資訊區塊
    time_info_html = ""
    if start_time and end_time:
        time_info_html = f"""
        <div class="time-info">
            <strong>🕒 掃描時間資訊:</strong><br>
            開始時間: {start_time.strftime('%Y-%m-%d %H:%M:%S')}<br>
            結束時間: {end_time.strftime('%Y-%m-%d %H:%M:%S')}<br>
            掃描時長: {int(duration_seconds // 60)} 分 {int(duration_seconds % 60)} 秒
        </div>
        """
    
    html_content = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Report: {url}</title><style>{css}</style></head><body>
    <div class="container"><h1>Burp Scan Report</h1>
    <div class="meta"><strong>Target:</strong> {url}<br><strong>Config:</strong> {scan_config}<br><strong>ID:</strong> {task_id}<br><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    {time_info_html}
    <div class="summary-box"><div class="stat-card High">High: {severity_counts['High']}</div><div class="stat-card Medium">Medium: {severity_counts['Medium']}</div><div class="stat-card Low">Low: {severity_counts['Low']}</div><div class="stat-card Information">Info: {severity_counts['Information']}</div></div>
    <h2>Issue Details</h2>"""

    if not processed_issues: html_content += "<p>No issues found.</p>"
    else:
        for issue in processed_issues:
            name, sev, path = html.escape(issue.get('name', 'Unknown')), issue['_normalized_severity'], html.escape(issue.get('path', '/'))
            content_html = ""
            if issue.get('description'): content_html += f'<div class="section-title">Detail</div><div>{issue["description"]}</div>'
            if issue.get('issue_background'): content_html += f'<div class="section-title">Background</div><div class="bg-section">{issue["issue_background"]}</div>'
            if issue.get('evidence'): content_html += f'<div class="section-title">Evidence</div><div><ul>' + "".join([f"<li>{html.escape(str(e))}</li>" for e in issue['evidence']]) + '</ul></div>'
            if issue.get('remediation'): content_html += f'<div class="section-title">Remediation</div><div>{issue["remediation"]}</div>'
            if issue.get('remediation_background'): content_html += f'<div class="section-title">Gen. Remediation</div><div class="bg-section">{issue["remediation_background"]}</div>'
            if issue.get('references'): content_html += f'<div class="section-title">References</div><div>{issue["references"]}</div>'
            
            html_content += f"""<details><summary><span><span class="tag {sev}">{sev}</span> {name}</span></summary><div class="issue-content"><p><strong>Path:</strong> <span class="path">{path}</span></p>{content_html}</div></details>"""
    
    html_content += "</div></body></html>"
    with open(html_filename, "w", encoding="utf-8") as f: f.write(html_content)
    
    return {"url": url, "issues": len(enriched_issues), "severity_counts": severity_counts}, html_filename

# --- 4. 匯出 UI ---
def export_existing_tasks_ui(report_dir):
    clear_screen()
    print(f"{ANSI.BOLD}=== 匯出 Burp 現有任務報告 ==={ANSI.RESET}")
    headers = {} if not API_KEY else {"X-Burp-API-Key": API_KEY}
    id_input = input(f"{ANSI.YELLOW}請輸入 Task ID (逗號分隔): {ANSI.RESET}").strip()
    if not id_input: return
    print("-" * 75)
    print(f"{'ID':<5} | {'Status':<15} | {'Result':<50}")
    print("-" * 75)
    for t_id in [x.strip() for x in id_input.split(',')]:
        try:
            r = requests.get(f"{BURP_API_URL}/scan/{t_id}", headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                events = data.get("issue_events", [])
                issues = [e.get("issue") for e in events if e.get("type") == "issue_found" and e.get("issue")]
                origin = issues[0].get("origin", "Unknown") if issues else "Unknown"
                if issues:
                    _, html_path = generate_reports(origin, issues, report_dir, "Existing", t_id)
                    print(f"{t_id:<5} | {ANSI.GREEN}{data.get('scan_status','?')[:15]:<15}{ANSI.RESET} | {os.path.basename(html_path)}")
                    log_event("SUCCESS", f"匯出任務 {t_id} 成功", origin)
                else: print(f"{t_id:<5} | {data.get('scan_status','?'):<15} | {ANSI.YELLOW}無漏洞/未完成{ANSI.RESET}")
            else: print(f"{t_id:<5} | {ANSI.RED}Not Found{ANSI.RESET}     | HTTP {r.status_code}")
        except Exception as e:
            print(f"{t_id:<5} | {ANSI.RED}Error{ANSI.RESET}         | {e}")
            log_event("ERROR", f"匯出任務 {t_id} 失敗: {e}")
    print("-" * 75); input("\n按 Enter 回選單...")

# --- 5. 掃描核心 (增強版 - 記錄時間) ---
def run_scan_task(url, report_dir):
    global completed_tasks, scan_time_records
    url = url.strip()
    
    # 記錄開始時間
    start_time = datetime.now()
    with lock:
        scan_states[url].update({"status": "Starting", "task_id": "Init"})
        scan_time_records[url] = {"start": start_time, "end": None, "duration": None}
    
    log_event("INFO", f"開始掃描", url)
    
    headers = {} if not API_KEY else {"X-Burp-API-Key": API_KEY}
    
    try:
        payload = {"urls": [url], "scan_configurations": [{"name": CURRENT_SCAN_CONFIG, "type": "NamedConfiguration"}]}
        resp = requests.post(f"{BURP_API_URL}/scan", json=payload, headers=headers, timeout=5)
        if resp.status_code == 201:
            task_id = resp.headers.get("Location").split("/")[-1]
            with lock: scan_states[url].update({"task_id": task_id, "status": "Wait 3s..."})
            log_event("SUCCESS", f"任務 {task_id} 建立成功", url)
            time.sleep(3)
        else:
            with lock: scan_states[url]["status"] = f"Err {resp.status_code}"; completed_tasks += 1
            log_event("ERROR", f"任務建立失敗: HTTP {resp.status_code}", url)
            return
    except Exception as e:
        with lock: scan_states[url]["status"] = "Conn Fail"; completed_tasks += 1
        log_event("ERROR", f"連線失敗: {e}", url)
        return

    task_id = scan_states[url]["task_id"]
    final_data = {}
    
    while True:
        try:
            r = requests.get(f"{BURP_API_URL}/scan/{task_id}", headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                final_data = data
                status = data.get("scan_status")
                metrics = data.get("scan_metrics", {})
                reqs = metrics.get("crawl_requests_made", metrics.get("audit_queue_items_completed", 0))
                issue_count = len([e for e in data.get("issue_events", []) if e.get("type") == "issue_found"])
                with lock: scan_states[url].update({"status": status, "reqs": reqs, "issues": issue_count})
                if status in ["succeeded", "failed"]: break
            time.sleep(2)
        except Exception as e:
            with lock: scan_states[url]["status"] = "Burp Lost"
            log_event("ERROR", f"掃描過程中斷: {e}", url)
            break

    # 記錄結束時間
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    with lock:
        scan_time_records[url]["end"] = end_time
        scan_time_records[url]["duration"] = duration

    if scan_states[url]["status"] != "Burp Lost" and final_data:
        with lock: scan_states[url]["status"] = "Reporting"
        issues = [e.get("issue") for e in final_data.get("issue_events", []) if e.get("type") == "issue_found"]
        report_data, _ = generate_reports(url, issues, report_dir, CURRENT_SCAN_CONFIG, task_id, start_time, end_time)
        
        # 將完整的漏洞資料也加入 report_data
        report_data['full_issues'] = [merge_issue_data(i) for i in issues]
        
        with lock:
            all_session_results.append(report_data)
            scan_states[url]["status"] = "Completed"
        log_event("SUCCESS", f"掃描完成 - 發現 {len(issues)} 個問題,耗時 {int(duration)}秒", url)
    else:
        if scan_states[url]["status"] != "Burp Lost":
            with lock: scan_states[url]["status"] = "Failed"
        log_event("ERROR", "掃描失敗", url)
    
    with lock: completed_tasks += 1

# --- 6. Dashboard ---
def dashboard_loop():
    while not stop_dashboard_flag:
        clear_screen()
        print(f"{ANSI.BOLD}Burp Suite Pro 自動化掃描 v11.0 (Enhanced Logging){ANSI.RESET}")
        print(f"進度: {completed_tasks}/{total_tasks} | 策略: {CURRENT_SCAN_CONFIG}")
        print("-" * 90)
        print(f"{'URL':<35} | {'ID':<5} | {'Status':<15} | {'Reqs':<6} | {'Issues':<6}")
        print("-" * 90)
        with lock:
            for url, s in scan_states.items():
                st, c = s['status'], ANSI.YELLOW
                if "scann" in st.lower() or "crawl" in st.lower(): c = ANSI.GREEN
                elif st == "Waiting": c = ANSI.GREY
                elif st == "Completed": c = ANSI.CYAN
                elif "fail" in st.lower() or "lost" in st.lower() or "err" in st.lower(): c = ANSI.RED
                print(f"{(url[:32] + '..') if len(url) > 32 else url:<35} | {s.get('task_id','-'):<5} | {c}{st:<15}{ANSI.RESET} | {s['reqs']:<6} | {ANSI.RED}{s['issues']:<6}{ANSI.RESET}")
        print("-" * 90)
        time.sleep(1)

# --- 7. [NEW] 匯出日誌與統計報告 ---
def export_logs_and_statistics(report_dir):
    """匯出完整日誌和統計資料"""
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 1. 匯出 JSON 日誌
    log_json_path = os.path.join(report_dir, f"{timestamp_str}_Scan_Logs.json")
    try:
        with open(log_json_path, "w", encoding="utf-8") as f:
            json.dump({
                "session_start": session_start_time.isoformat() if session_start_time else None,
                "session_end": session_end_time.isoformat() if session_end_time else None,
                "total_events": len(scan_logs),
                "logs": scan_logs
            }, f, ensure_ascii=False, indent=4)
        print(f"{ANSI.GREEN}[+] 日誌已匯出: {log_json_path}{ANSI.RESET}")
    except Exception as e:
        print(f"{ANSI.RED}[!] 日誌匯出失敗: {e}{ANSI.RESET}")
    
    # 2. 匯出 CSV 統計報告
    csv_path = os.path.join(report_dir, f"{timestamp_str}_Scan_Statistics.csv")
    try:
        with open(csv_path, "w", newline='', encoding="utf-8-sig") as csvfile:
            fieldnames = ['URL', 'Task_ID', 'Status', 'Start_Time', 'End_Time', 'Duration_Sec', 
                         'High', 'Medium', 'Low', 'Information', 'Total_Issues']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            with lock:
                for url, state in scan_states.items():
                    time_record = scan_time_records.get(url, {})
                    
                    # 從 all_session_results 找到對應的統計
                    severity_data = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
                    total_issues = 0
                    for result in all_session_results:
                        if result.get("url") == url:
                            severity_data = result.get("severity_counts", severity_data)
                            total_issues = result.get("issues", 0)
                            break
                    
                    writer.writerow({
                        'URL': url,
                        'Task_ID': state.get('task_id', '-'),
                        'Status': state.get('status', 'Unknown'),
                        'Start_Time': time_record.get('start').strftime('%Y-%m-%d %H:%M:%S') if time_record.get('start') else '',
                        'End_Time': time_record.get('end').strftime('%Y-%m-%d %H:%M:%S') if time_record.get('end') else '',
                        'Duration_Sec': int(time_record.get('duration', 0)) if time_record.get('duration') else 0,
                        'High': severity_data.get('High', 0),
                        'Medium': severity_data.get('Medium', 0),
                        'Low': severity_data.get('Low', 0),
                        'Information': severity_data.get('Information', 0),
                        'Total_Issues': total_issues
                    })
        print(f"{ANSI.GREEN}[+] 統計報告已匯出: {csv_path}{ANSI.RESET}")
    except Exception as e:
        print(f"{ANSI.RED}[!] CSV 匯出失敗: {e}{ANSI.RESET}")
    
    # 3. 匯出增強版總覽 JSON (包含完整漏洞細節)
    summary_path = os.path.join(report_dir, f"{timestamp_str}_Session_Summary.json")
    try:
        total_duration = (session_end_time - session_start_time).total_seconds() if session_start_time and session_end_time else 0
        
        # 收集所有站點的詳細資料
        detailed_scans = []
        
        with lock:
            for url, state in scan_states.items():
                time_record = scan_time_records.get(url, {})
                
                # 從 all_session_results 找到對應的完整資料
                severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
                full_issues = []
                
                for result in all_session_results:
                    if result.get("url") == url:
                        severity_counts = result.get("severity_counts", severity_counts)
                        full_issues = result.get("full_issues", [])  # 完整漏洞資料
                        break
                
                scan_detail = {
                    "url": url,
                    "task_id": state.get('task_id', '-'),
                    "status": state.get('status', 'Unknown'),
                    "start_time": time_record.get('start').isoformat() if time_record.get('start') else None,
                    "end_time": time_record.get('end').isoformat() if time_record.get('end') else None,
                    "duration_seconds": time_record.get('duration', 0),
                    "severity_counts": severity_counts,
                    "total_issues": len(full_issues),
                    "issues": full_issues  # 完整漏洞細節
                }
                
                detailed_scans.append(scan_detail)
        
        summary_data = {
            "session_info": {
                "start_time": session_start_time.isoformat() if session_start_time else None,
                "end_time": session_end_time.isoformat() if session_end_time else None,
                "total_duration_seconds": total_duration,
                "scan_configuration": CURRENT_SCAN_CONFIG,
                "total_targets": total_tasks,
                "completed_targets": completed_tasks
            },
            "aggregate_statistics": {
                "total_high": sum(s.get("severity_counts", {}).get("High", 0) for s in detailed_scans),
                "total_medium": sum(s.get("severity_counts", {}).get("Medium", 0) for s in detailed_scans),
                "total_low": sum(s.get("severity_counts", {}).get("Low", 0) for s in detailed_scans),
                "total_information": sum(s.get("severity_counts", {}).get("Information", 0) for s in detailed_scans),
                "total_issues": sum(s.get("total_issues", 0) for s in detailed_scans)
            },
            "scan_details": detailed_scans  # 包含每個站點的完整漏洞資料
        }
        
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, ensure_ascii=False, indent=4)
        print(f"{ANSI.GREEN}[+] 會話總覽已匯出 (含完整漏洞細節): {summary_path}{ANSI.RESET}")
    except Exception as e:
        print(f"{ANSI.RED}[!] 總覽匯出失敗: {e}{ANSI.RESET}")

# --- 8. 主程式 ---
def main():
    global total_tasks, completed_tasks, scan_states, stop_dashboard_flag, all_session_results
    global session_start_time, session_end_time, scan_logs, scan_time_records
    
    while True:
        check_api_and_load_kb()
        
        clear_screen()
        print(f"{ANSI.BOLD}=== Burp Suite 自動化檢測工具 v11.0 (Enhanced) ==={ANSI.RESET}")
        
        if API_ONLINE:
            print(f"API 狀態: {ANSI.GREEN}Online{ANSI.RESET}")
            kb_status = f"{ANSI.GREEN}已載入 ({len(issue_definitions_map)}){ANSI.RESET}" if issue_definitions_map else f"{ANSI.YELLOW}載入中...{ANSI.RESET}"
            print(f"知識庫: {kb_status}")
            print("-" * 40)
            print("1. 執行批量掃描 (New Scan)")
            print("2. 匯出既有任務 (Export Existing)")
            print("q. 離開程式 (Quit)")
            print("-" * 40)
            prompt = "請輸入選項: "
        else:
            print(f"API 狀態: {ANSI.RED}Offline (等待 Burp 連線中...){ANSI.RESET}")
            print(f"知識庫: {ANSI.GREY}等待連線{ANSI.RESET}")
            print("-" * 40)
            print(f"{ANSI.YELLOW}[!] Burp 未啟動。程式將每 5 秒自動重試連線...{ANSI.RESET}")
            print("q. 離開程式 (Quit)")
            print("-" * 40)
            prompt = "請輸入選項 (或按 Enter 重新檢查): "

        try:
            if not API_ONLINE:
                print(f"{ANSI.CYAN}正在嘗試連線至 {BURP_API_URL}... (按 Ctrl+C 強制離開){ANSI.RESET}")
                time.sleep(3)
                continue
                
            choice = input(prompt).strip().lower()
        except KeyboardInterrupt:
            print("\nBye!"); break

        if choice in ['q', 'quit']:
            print("Bye!"); break

        if not API_ONLINE:
            continue

        report_dir = "reports"
        if not os.path.exists(report_dir): os.makedirs(report_dir)

        if choice == '2':
            export_existing_tasks_ui(report_dir)
        elif choice == '1':
            # 重置所有狀態
            with lock:
                scan_states = {}
                all_session_results = []
                completed_tasks = 0
                total_tasks = 0
                stop_dashboard_flag = False
                scan_logs = []
                scan_time_records = {}
                session_start_time = None
                session_end_time = None
            
            url_file = input("網址清單 (預設 urls.txt): ").strip() or "urls.txt"
            if not os.path.exists(url_file):
                print(f"{ANSI.RED}找不到檔案!{ANSI.RESET}")
                time.sleep(1)
                continue
            
            select_scan_config()
            try: workers = int(input("並行數 (預設 2): ").strip() or "2")
            except: workers = 2
            
            with open(url_file, "r") as f:
                raw_urls = [line.strip() for line in f if line.strip()]
                urls = list(dict.fromkeys(raw_urls))
            
            total_tasks = len(urls)
            if total_tasks == 0:
                print("清單是空的。")
                time.sleep(1)
                continue
            
            # 記錄會話開始時間
            session_start_time = datetime.now()
            log_event("INFO", f"掃描會話開始 - 共 {total_tasks} 個目標")
            
            with lock:
                for u in urls: scan_states[u] = {"status": "Waiting", "reqs": 0, "issues": 0, "task_id": "-"}
            
            ui_thread = threading.Thread(target=dashboard_loop, daemon=True)
            ui_thread.start()
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for url in urls:
                    time.sleep(0.5)
                    executor.submit(run_scan_task, url, report_dir)
            
            while completed_tasks < total_tasks: time.sleep(1)
            stop_dashboard_flag = True
            ui_thread.join()
            
            # 記錄會話結束時間
            session_end_time = datetime.now()
            log_event("INFO", f"掃描會話結束 - 完成 {completed_tasks}/{total_tasks} 個目標")
            
            # 最後顯示完整 Dashboard
            clear_screen()
            print(f"{ANSI.BOLD}Burp Suite Pro 自動化掃描 v11.0 (Completed){ANSI.RESET}")
            print(f"進度: {completed_tasks}/{total_tasks} | 策略: {CURRENT_SCAN_CONFIG}")
            
            if session_start_time and session_end_time:
                total_duration = (session_end_time - session_start_time).total_seconds()
                print(f"會話時間: {session_start_time.strftime('%H:%M:%S')} - {session_end_time.strftime('%H:%M:%S')} (共 {int(total_duration//60)}分{int(total_duration%60)}秒)")
            
            print("-" * 90)
            print(f"{'URL':<35} | {'ID':<5} | {'Status':<15} | {'Reqs':<6} | {'Issues':<6}")
            print("-" * 90)
            with lock:
                for url, s in scan_states.items():
                    color = ANSI.CYAN if s['status'] == "Completed" else ANSI.RED
                    print(f"{(url[:32] + '..') if len(url) > 32 else url:<35} | {s.get('task_id','-'):<5} | {color}{s['status']:<15}{ANSI.RESET} | {s['reqs']:<6} | {ANSI.RED}{s['issues']:<6}{ANSI.RESET}")
            print("-" * 90)

            # 匯出日誌與統計
            print(f"\n{ANSI.CYAN}正在匯出日誌與統計報告...{ANSI.RESET}")
            export_logs_and_statistics(report_dir)
            
            input(f"\n{ANSI.CYAN}按 Enter 回主選單...{ANSI.RESET}")
        else:
            print("無效選項。")
            time.sleep(0.5)

if __name__ == "__main__":
    main()
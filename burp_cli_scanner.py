import os
import time
import json
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import html
import sys

# ================= 設定區 =================
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
API_ONLINE = False  # [v10] 新增 API 狀態旗標

class ANSI:
    CYAN, GREEN, YELLOW, RED, RESET, BOLD = '\033[96m', '\033[92m', '\033[93m', '\033[91m', '\033[0m', '\033[1m'
    GREY = '\033[90m'
    CLEAR = 'cls' if os.name == 'nt' else 'clear'

def clear_screen():
    os.system(ANSI.CLEAR)

# --- 0. [v10] API 檢查與 KB 載入 ---
def check_api_and_load_kb():
    """
    檢查 API 是否存活。若存活且 KB 尚未載入，則執行載入。
    回傳: True (Online), False (Offline)
    """
    global API_ONLINE, issue_definitions_map
    headers = {}
    if API_KEY: headers["X-Burp-API-Key"] = API_KEY
    
    try:
        # 嘗試輕量級請求確認存活
        requests.get(f"{BURP_API_URL.replace('/v0.1','')}/api-definition", headers=headers, timeout=2)
        API_ONLINE = True
        
        # 如果 API 在線，但知識庫還是空的，就嘗試載入
        if not issue_definitions_map:
            print(f"\n{ANSI.CYAN}[*] 偵測到 Burp 上線，正在載入知識庫...{ANSI.RESET}")
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
                    time.sleep(1.5) # 讓使用者看到成功訊息
                else:
                    print(f"{ANSI.RED}[!] 載入失敗: HTTP {resp.status_code}{ANSI.RESET}")
            except Exception as e:
                print(f"{ANSI.RED}[!] 載入錯誤: {e}{ANSI.RESET}")
        return True
    except:
        API_ONLINE = False
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
    print(f"{ANSI.GREEN}已設定策略為: {CURRENT_SCAN_CONFIG}{ANSI.RESET}\n"); time.sleep(1)

# --- 3. 報告生成器 ---
def generate_reports(url, issues, output_dir, scan_config, task_id="-"):
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = url.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "_")
    enriched_issues = [merge_issue_data(i) for i in issues]
    
    # JSON
    json_filename = os.path.join(output_dir, f"{timestamp_str}_Data_{safe_name}.json")
    try:
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump({
                "target_url": url, "scan_configuration": scan_config, "task_id": task_id,
                "generated_at": datetime.now().isoformat(), "issue_count": len(enriched_issues), "issues": enriched_issues
            }, f, ensure_ascii=False, indent=4)
    except Exception as e: print(f"JSON Error: {e}")

    # HTML
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
    html_content = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Report: {url}</title><style>{css}</style></head><body>
    <div class="container"><h1>Burp Scan Report</h1>
    <div class="meta"><strong>Target:</strong> {url}<br><strong>Config:</strong> {scan_config}<br><strong>ID:</strong> {task_id}<br><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
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
    return {}, html_filename

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
                else: print(f"{t_id:<5} | {data.get('scan_status','?'):<15} | {ANSI.YELLOW}無漏洞/未完成{ANSI.RESET}")
            else: print(f"{t_id:<5} | {ANSI.RED}Not Found{ANSI.RESET}     | HTTP {r.status_code}")
        except Exception as e: print(f"{t_id:<5} | {ANSI.RED}Error{ANSI.RESET}         | {e}")
    print("-" * 75); input("\n按 Enter 回選單...")

# --- 5. 掃描核心 ---
def run_scan_task(url, report_dir):
    global completed_tasks
    url = url.strip()
    with lock: scan_states[url].update({"status": "Starting", "task_id": "Init"})
    headers = {} if not API_KEY else {"X-Burp-API-Key": API_KEY}
    
    try:
        payload = {"urls": [url], "scan_configurations": [{"name": CURRENT_SCAN_CONFIG, "type": "NamedConfiguration"}]}
        resp = requests.post(f"{BURP_API_URL}/scan", json=payload, headers=headers, timeout=5)
        if resp.status_code == 201:
            task_id = resp.headers.get("Location").split("/")[-1]
            with lock: scan_states[url].update({"task_id": task_id, "status": "Wait 3s..."})
            time.sleep(3)
        else:
            with lock: scan_states[url]["status"] = f"Err {resp.status_code}"; completed_tasks += 1; return
    except:
        with lock: scan_states[url]["status"] = "Conn Fail"; completed_tasks += 1; return

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
        except:
            with lock: scan_states[url]["status"] = "Burp Lost"; break

    if scan_states[url]["status"] != "Burp Lost" and final_data:
        with lock: scan_states[url]["status"] = "Reporting"
        issues = [e.get("issue") for e in final_data.get("issue_events", []) if e.get("type") == "issue_found"]
        report_data, _ = generate_reports(url, issues, report_dir, CURRENT_SCAN_CONFIG, task_id)
        with lock: all_session_results.append(report_data); scan_states[url]["status"] = "Completed"
    else:
        if scan_states[url]["status"] != "Burp Lost":
            with lock: scan_states[url]["status"] = "Failed"
    with lock: completed_tasks += 1

# --- 6. Dashboard ---
def dashboard_loop():
    while not stop_dashboard_flag:
        clear_screen()
        print(f"{ANSI.BOLD}Burp Suite Pro 自動化掃描 v10.0 (Auto-Detect){ANSI.RESET}")
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

# --- 7. 主程式 (v10 改良版) ---
def main():
    global total_tasks, completed_tasks, scan_states, stop_dashboard_flag, all_session_results
    
    # 迴圈監控 API 狀態，直到使用者按 q 離開
    while True:
        check_api_and_load_kb() # 每次回到選單前都檢查一次狀態
        
        clear_screen()
        print(f"{ANSI.BOLD}=== Burp Suite 自動化檢測工具 v10.0 ==={ANSI.RESET}")
        
        # 狀態顯示與選單動態生成
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
            # 只有在 Offline 時才顯示這個動態提示
            print(f"{ANSI.YELLOW}[!] Burp 未啟動。程式將每 5 秒自動重試連線...{ANSI.RESET}")
            print("q. 離開程式 (Quit)")
            print("-" * 40)
            prompt = "請輸入選項 (或按 Enter 重新檢查): "

        # 使用 input 配合 timeout 機制 (但在 Python input 是 blocking 的)
        # 所以我們用一個簡單的 trick: 如果 offline，我們允許使用者輸入 q，
        # 否則我們就 sleep 一下然後 continue 來模擬「定期檢查」
        
        # 這裡為了良好的 UX，我們不使用複雜的非同步 input，
        # 而是讓使用者手動按 Enter 刷新，或者如果 Online 就正常操作。
        
        try:
            # 這裡我們做一個改良：如果 Offline，我們自動倒數刷新
            if not API_ONLINE:
                print(f"{ANSI.CYAN}正在嘗試連線至 {BURP_API_URL}... (按 Ctrl+C 強制離開){ANSI.RESET}")
                time.sleep(3) # 等待 3 秒再刷新
                continue      # 跳回 while 開頭重新 check_api
                
            choice = input(prompt).strip().lower()
        except KeyboardInterrupt:
            print("\nBye!"); break

        if choice in ['q', 'quit']:
            print("Bye!"); break

        # 如果還沒 Online 但使用者亂按 (除了 q)
        if not API_ONLINE:
            continue 

        # --- 以下是 Online 才會執行的邏輯 ---
        report_dir = "reports"
        if not os.path.exists(report_dir): os.makedirs(report_dir)

        if choice == '2':
            export_existing_tasks_ui(report_dir)
        elif choice == '1':
            with lock:
                scan_states = {}; all_session_results = []
                completed_tasks = 0; total_tasks = 0; stop_dashboard_flag = False
            
            url_file = input("網址清單 (預設 urls.txt): ").strip() or "urls.txt"
            if not os.path.exists(url_file): print(f"{ANSI.RED}找不到檔案!{ANSI.RESET}"); time.sleep(1); continue
            
            select_scan_config()
            try: workers = int(input("並行數 (預設 2): ").strip() or "2")
            except: workers = 2
            
            with open(url_file, "r") as f:
                raw_urls = [line.strip() for line in f if line.strip()]
                urls = list(dict.fromkeys(raw_urls)) # 去重且保持順序
            
            total_tasks = len(urls)
            if total_tasks == 0: print("清單是空的。"); time.sleep(1); continue
            
            with lock:
                for u in urls: scan_states[u] = {"status": "Waiting", "reqs": 0, "issues": 0, "task_id": "-"}
            
            ui_thread = threading.Thread(target=dashboard_loop, daemon=True)
            ui_thread.start()
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for url in urls:
                    time.sleep(0.5); executor.submit(run_scan_task, url, report_dir)
            
            while completed_tasks < total_tasks: time.sleep(1)
            stop_dashboard_flag = True; ui_thread.join(); 
            
            # 最後顯示一次完整的 Dashboard
            clear_screen()
            print(f"{ANSI.BOLD}Burp Suite Pro 自動化掃描 v10.0 (Completed){ANSI.RESET}")
            print(f"進度: {completed_tasks}/{total_tasks} | 策略: {CURRENT_SCAN_CONFIG}")
            print("-" * 90)
            print(f"{'URL':<35} | {'ID':<5} | {'Status':<15} | {'Reqs':<6} | {'Issues':<6}")
            print("-" * 90)
            with lock:
                for url, s in scan_states.items():
                    color = ANSI.CYAN if s['status'] == "Completed" else ANSI.RED
                    print(f"{(url[:32] + '..') if len(url) > 32 else url:<35} | {s.get('task_id','-'):<5} | {color}{s['status']:<15}{ANSI.RESET} | {s['reqs']:<6} | {ANSI.RED}{s['issues']:<6}{ANSI.RESET}")
            print("-" * 90)

            if all_session_results:
                g_path = os.path.join(report_dir, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_Global_Scan_Summary.json")
                try:
                    with open(g_path, "w", encoding="utf-8") as f:
                        json.dump({"session_date": datetime.now().isoformat(), "total_targets": total_tasks, "results": all_session_results}, f, ensure_ascii=False, indent=4)
                    print(f"\n{ANSI.GREEN}[+] 全域報告: {g_path}{ANSI.RESET}")
                except: pass
            input(f"\n{ANSI.CYAN}按 Enter 回主選單...{ANSI.RESET}")
        else:
            print("無效選項。"); time.sleep(0.5)

if __name__ == "__main__":
    main()

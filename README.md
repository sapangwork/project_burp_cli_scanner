# Burp Suite Pro Auto Scanner

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional-orange.svg)](https://portswigger.net/burp/pro)
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Version](https://img.shields.io/badge/Version-11.0-brightgreen.svg)]()

這是一個基於 Python 開發的高效能自動化弱點掃描工具，專為 **Burp Suite Professional** 設計。

本工具透過 Burp REST API 進行全自動化的批量掃描，具備 **API 自動偵測**、**斷線重連**、**知識庫自動載入**、**多執行緒並發處理**、**完整時間追蹤**以及**進階日誌系統**。掃描完成後，會自動生成包含詳細漏洞資訊、修復建議、時間統計與證據的 HTML、JSON 及 CSV 報告。

---

## 🚀 主要功能 (Features)

### 核心功能
* **智能 API 狀態管理**: 自動偵測 Burp API 是否存活，若未啟動會自動等待並嘗試重連，無需重啟程式。
* **知識庫整合 (KB Integration)**: 自動載入 Burp Issue Definitions，確保報告包含完整的背景知識 (Issue Background) 與修復建議 (Remediation)。
* **即時監控儀表板 (Live Dashboard)**: 透過 CLI 介面即時顯示每個任務的進度、請求數 (Requests)、發現漏洞數 (Issues) 及狀態。
* **批量並發掃描**: 支援多執行緒 (Multi-threading)，可同時對多個目標進行掃描，並自訂並發數量 (Workers)。
* **彈性策略配置**: 支援切換不同的掃描設定 (如 Fast, Balanced, Deep, Audit only 等)。

### 🆕 v11.0 新功能
* **📊 完整時間追蹤**:
  - 每個站點記錄開始/結束時間與掃描時長
  - 整個掃描會話的開始/結束時間
  - HTML 報告中新增視覺化時間資訊區塊
  - JSON 報告包含 ISO 8601 格式時間戳記

* **📝 進階日誌系統**:
  - 所有關鍵事件自動記錄 (INFO/WARNING/ERROR/SUCCESS)
  - 包含時間戳、事件等級、訊息內容與相關 URL
  - 完整會話日誌匯出為 JSON 格式

* **📈 統計報告匯出**:
  - **CSV 格式**: 包含所有站點的掃描時間、時長、各等級漏洞數量，可直接用 Excel 開啟
  - **JSON 總覽**: 會話級別的聚合統計，包含總時長、總漏洞數、各站點詳細資訊
  - 自動生成弱點嚴重性分佈統計 (High/Medium/Low/Information)

* **🎯 專業報告生成**:
  - **HTML**: 視覺化報告，包含時間資訊、漏洞嚴重性分級、詳細描述與證據
  - **JSON**: 完整的原始掃描數據，包含時間戳記，便於與 CI/CD 整合
  - **CSV**: 結構化統計表格，適合資料分析與管理報告
  - **會話總覽**: 整個掃描會話的聚合統計與詳細資訊

* **任務匯出**: 支援輸入 Task ID 匯出 Burp 上既有任務的報告。

---

## 📋 前置需求 (Prerequisites)

1.  **Burp Suite Professional**: 必須使用專業版 (Community 版不支援 REST API)。
2.  **Python 3.6+**: 建議使用 Python 3.7 或更新版本。
3.  **Python 套件**:
    ```bash
    pip install requests
    ```

---

## ⚙️ Burp Suite 設定 (Configuration)

在執行程式前，請確保 Burp Suite 已開啟 REST API 功能：

1.  開啟 Burp Suite Professional。
2.  進入 **Settings** > **Suite** > **REST API**。
3.  勾選 **Service is running**。
4.  設定 Port 為 `1337` (程式預設值)。
5.  (選用) 若勾選 **Require API key**，請複製金鑰並填入程式碼中的 `API_KEY` 欄位。

```python
# 在程式碼開頭設定 API Key (若需要)
API_KEY = "your-api-key-here"
```

---

## 🚀 使用說明 (Usage)

### 1. 準備目標清單
在程式同目錄下建立 `urls.txt`，每行輸入一個目標網址：

```text
http://example.com
https://test-site.org/login
https://api.example.com/v1
http://192.168.1.100
```

### 2. 啟動程式
```bash
python burp_cli_scanner.py
```

### 3. 操作流程
程式啟動後將顯示主選單：

#### **API 狀態檢查**
程式會自動檢查 Burp API 連線與知識庫載入狀態：
- ✅ **Online**: 顯示已載入的知識庫數量，可執行所有功能
- ⏳ **Offline**: 每 3 秒自動重試連線，無需重啟程式

#### **選項 1: 執行批量掃描 (New Scan)**
1. 輸入網址清單檔名 (預設 `urls.txt`)
2. 選擇掃描策略:
   - `1` - Crawl and Audit - Fast (推薦)
   - `2` - Crawl and Audit - Balanced
   - `3` - Crawl and Audit - Deep
   - `4` - Crawl and Audit - Lightweight
   - `5` - Audit checks - All issues
3. 設定並發執行緒數 (預設 2，建議 2-5)
4. 即時監控掃描進度
5. 完成後自動生成所有報告

#### **選項 2: 匯出既有任務 (Export Existing)**
- 輸入一個或多個 Task ID (逗號分隔，如 `1, 3, 5`)
- 自動匯出對應任務的完整報告

---

## 📂 輸出檔案結構 (Output Files)

所有報告將儲存於 `reports/` 資料夾，檔名格式為 `YYYYMMDD_HHMMSS_類型_目標.格式`：

```plaintext
reports/
├── 20250106_143022_Report_example_com.html          # 📄 HTML 視覺化報告 (含時間資訊)
├── 20250106_143022_Data_example_com.json            # 📦 JSON 完整數據 (含時間戳記)
├── 20250106_143022_Scan_Logs.json                   # 📝 完整會話日誌
├── 20250106_143022_Scan_Statistics.csv              # 📊 CSV 統計表格
└── 20250106_143022_Session_Summary.json             # 📈 會話聚合總覽
```

### 報告內容說明

#### 1. **HTML 報告** (`_Report_*.html`)
- 📊 漏洞嚴重性統計卡片 (High/Medium/Low/Info)
- 🕒 掃描時間資訊區塊 (開始/結束/時長)
- 📋 可折疊的漏洞詳細資訊
- 🔍 包含證據、修復建議、參考資料
- 🎨 專業視覺化設計，支援深色標籤

#### 2. **JSON 數據** (`_Data_*.json`)
```json
{
  "target_url": "http://example.com",
  "scan_start_time": "2025-01-06T14:30:22.123456",
  "scan_end_time": "2025-01-06T14:45:18.654321",
  "scan_duration_seconds": 896.53,
  "issue_count": 15,
  "issues": [...]
}
```

#### 3. **CSV 統計表** (`_Scan_Statistics.csv`)
| URL | Task_ID | Status | Start_Time | End_Time | Duration_Sec | High | Medium | Low | Information | Total_Issues |
|-----|---------|--------|------------|----------|--------------|------|--------|-----|-------------|--------------|
| http://example.com | 123 | Completed | 2025-01-06 14:30:22 | 2025-01-06 14:45:18 | 896 | 3 | 8 | 4 | 5 | 20 |

- ✅ UTF-8 BOM 編碼，Excel 可直接開啟
- 📊 包含所有站點的掃描時間與漏洞統計
- 📈 適合製作管理報告與趨勢分析

#### 4. **會話總覽** (`_Session_Summary.json`)
```json
{
  "session_info": {
    "start_time": "2025-01-06T14:30:00",
    "end_time": "2025-01-06T15:45:30",
    "total_duration_seconds": 4530,
    "scan_configuration": "Crawl and Audit - Fast",
    "total_targets": 10,
    "completed_targets": 10
  },
  "aggregate_statistics": {
    "total_high": 15,
    "total_medium": 42,
    "total_low": 28,
    "total_information": 67,
    "total_issues": 152
  },
  "scan_details": [...]
}
```

#### 5. **掃描日誌** (`_Scan_Logs.json`)
```json
{
  "session_start": "2025-01-06T14:30:00",
  "session_end": "2025-01-06T15:45:30",
  "total_events": 156,
  "logs": [
    {
      "timestamp": "2025-01-06T14:30:22.123456",
      "level": "INFO",
      "message": "開始掃描",
      "url": "http://example.com"
    },
    {
      "timestamp": "2025-01-06T14:30:25.456789",
      "level": "SUCCESS",
      "message": "任務 123 建立成功",
      "url": "http://example.com"
    }
  ]
}
```

---

## 💡 使用範例 (Examples)

### 範例 1: 基本批量掃描
```bash
# 1. 準備目標清單
echo "http://testsite1.com" > urls.txt
echo "http://testsite2.com" >> urls.txt

# 2. 執行掃描
python burp_cli_scanner.py

# 3. 選擇選項 1，使用預設設定
# 輸入: urls.txt
# 策略: 1 (Fast)
# 並發: 2

# 4. 等待完成，自動生成 5 種報告
```

### 範例 2: 進階掃描設定
```bash
# 使用 Deep 策略，5 個並發執行緒
# 在選單中選擇:
# - 策略: 3 (Deep)
# - 並發: 5
```

### 範例 3: 匯出既有任務
```bash
# 選擇選項 2
# 輸入 Task ID: 1, 5, 12
# 自動生成對應報告
```

---

## 🔧 進階設定 (Advanced Configuration)

### 修改 API 端點
```python
# 在程式碼開頭修改
BURP_API_URL = "http://localhost:1337/v0.1"  # 預設值
```

### 調整重試次數
```python
MAX_RETRIES = 5  # API 請求失敗重試次數
```

### 自訂報告目錄
程式會自動建立 `reports/` 資料夾，若需修改：
```python
# 在 main() 函數中修改
report_dir = "custom_reports"
```

---

## 📊 儀表板說明 (Dashboard Guide)

即時監控介面顯示以下資訊：

```
Burp Suite Pro 自動化掃描 v11.0 (Enhanced Logging)
進度: 3/10 | 策略: Crawl and Audit - Fast
會話時間: 14:30:00 - 15:45:30 (共 75分30秒)
----------------------------------------------------------------------------------
URL                                 | ID    | Status          | Reqs   | Issues
----------------------------------------------------------------------------------
http://example.com                  | 123   | Completed       | 245    | 12
http://test-site.org                | 124   | Scanning        | 156    | 8
http://api.example.com              | 125   | Waiting         | 0      | 0
----------------------------------------------------------------------------------
```

### 狀態說明
- 🟡 **Waiting**: 等待開始
- 🟢 **Scanning/Crawling**: 掃描中
- 🔵 **Completed**: 已完成
- 🔴 **Failed/Error**: 失敗
- ⚫ **Burp Lost**: 連線中斷

---

## ⚠️ 注意事項 (Notes)

1. **效能考量**: 
   - 並發數建議設定為 2-5，過高可能影響 Burp 效能
   - Deep 掃描會花費較長時間，建議用於重點目標

2. **網路穩定性**:
   - 確保 Burp API 連線穩定
   - 若出現 "Burp Lost" 狀態，請檢查 Burp Suite 是否正常運行

3. **報告大小**:
   - 大量漏洞會產生較大的報告檔案
   - JSON 和 CSV 適合程式化處理，HTML 適合人工審閱

4. **時間精確度**:
   - 所有時間記錄精確到毫秒
   - 時區為執行程式的本地時間

---

## 🐛 疑難排解 (Troubleshooting)

### 問題 1: API 連線失敗
**症狀**: 顯示 "API 狀態: Offline"

**解決方案**:
1. 確認 Burp Suite Professional 已啟動
2. 檢查 REST API 設定是否正確啟用
3. 確認 Port 為 1337
4. 檢查防火牆設定

### 問題 2: 知識庫載入失敗
**症狀**: 報告中缺少 Background 或 Remediation 資訊

**解決方案**:
1. 等待程式自動重試載入
2. 手動重啟程式，確保 API 完全就緒
3. 檢查 Burp 版本是否支援 REST API v0.1

### 問題 3: 掃描卡住不動
**症狀**: Dashboard 長時間顯示相同狀態

**解決方案**:
1. 檢查目標網站是否可訪問
2. 查看 `_Scan_Logs.json` 確認錯誤訊息
3. 降低並發數重試
4. 確認 Burp 沒有其他大量任務在執行

### 問題 4: CSV 亂碼
**症狀**: Excel 開啟 CSV 出現亂碼

**解決方案**:
- 程式已使用 UTF-8-BOM 編碼，應可直接開啟
- 若仍有問題，請用 Excel 的「資料 > 從文字/CSV」功能匯入

---

## 📈 最佳實踐 (Best Practices)

1. **分批掃描**: 將大量目標分成多個批次，避免單次任務過長
2. **策略選擇**: 
   - 快速檢測用 Fast
   - 正式評估用 Balanced
   - 深度測試用 Deep
3. **報告管理**: 定期備份 `reports/` 資料夾，建立版本控制
4. **日誌分析**: 使用 `_Scan_Logs.json` 追蹤問題，優化掃描流程
5. **統計追蹤**: 用 CSV 報告建立漏洞趨勢圖表，監控安全改善

---

## ⚠️ 免責聲明 (Disclaimer)

本工具僅供**安全性測試**、**漏洞評估**與**教育用途**。使用本工具進行掃描前，請確保您已取得目標系統擁有者的**明確授權**。

**未經授權的掃描行為可能違反相關法律法規**。使用者需自行承擔因使用本工具而產生的所有法律責任與風險。

開發者不對任何濫用行為或因使用本工具造成的損害負責。

---

## 📝 版本紀錄 (Version History)

### **v11.0 (Current) - 2025-01-06**
#### 新增功能
- ✨ **完整時間追蹤系統**: 每個站點與會話的開始/結束時間記錄
- 📝 **進階日誌系統**: 所有事件自動記錄，包含等級與時間戳
- 📊 **CSV 統計報告**: 結構化表格，包含時間與漏洞統計
- 📈 **會話總覽**: 聚合統計與詳細掃描資訊
- 🕒 **HTML 時間資訊**: 報告中新增視覺化時間區塊

#### 改進優化
- 🎨 HTML 報告新增綠色時間資訊區塊
- 💾 JSON 報告新增 `scan_start_time`, `scan_end_time`, `scan_duration_seconds` 欄位
- 📋 Dashboard 顯示會話總時長
- 🔄 掃描完成後自動匯出所有報告（HTML, JSON, CSV, 日誌, 總覽）

#### 檔案輸出
- `_Report_*.html` - 視覺化報告（含時間）
- `_Data_*.json` - 完整數據（含時間戳）
- `_Scan_Logs.json` - 會話日誌
- `_Scan_Statistics.csv` - 統計表格
- `_Session_Summary.json` - 聚合總覽

### **v10.0 - 2024-12-17**
- 🆕 **API 自動偵測機制**: 離線時進入等待模式而非崩潰
- 🆕 **知識庫載入**: 自動抓取 issue_definitions
- 🔧 報告內容整合 issue_background 和 remediation_background
- 🎨 Dashboard UI 改良，新增狀態指示燈
- 🐛 修正 JSON 編碼錯誤

### **v9.0 - 2024-12-16**
- 🆕 支援多執行緒 (ThreadPoolExecutor) 批量掃描
- 🆕 即時 Dashboard，顯示 Reqs 與 Issues
- 🆕 掃描策略選擇功能

### **v1.0 - 2024-12-16**
- 🎉 初始版本發布
- ✅ 基礎單執行緒掃描功能
- ✅ HTML 與 JSON 報告生成

---

## 👥 作者 (Authors)

* **Sapang** - *專案開發與核心邏輯* (Core Developer)
* **Gemini & Claude** - *AI 協作助手與程式優化* (AI Assistants)

## 📄 授權 (License)

MIT License - 請參閱 LICENSE 文件了解詳情

---

## 🔗 相關資源 (Resources)

- [Burp Suite Professional](https://portswigger.net/burp/pro)
- [Burp REST API 文件](https://portswigger.net/burp/documentation/desktop/tools/rest-api)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

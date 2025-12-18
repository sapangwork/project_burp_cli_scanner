# Burp Suite Pro Auto Scanner

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional-orange.svg)](https://portswigger.net/burp/pro)
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

這是一個基於 Python 開發的高效能自動化弱點掃描工具，專為 **Burp Suite Professional** 設計。

本工具透過 Burp REST API 進行全自動化的批量掃描，具備 **API 自動偵測**、**斷線重連**、**知識庫自動載入**以及**多執行緒並發處理**功能。掃描完成後，會自動生成包含詳細漏洞資訊、修復建議與證據的 HTML 及 JSON 報告。

## 🚀 主要功能 (Features)

* **智能 API 狀態管理**: 自動偵測 Burp API 是否存活，若未啟動會自動等待並嘗試重連，無需重啟程式。
* **知識庫整合 (KB Integration)**: 自動載入 Burp Issue Definitions，確保報告包含完整的背景知識 (Issue Background) 與修復建議 (Remediation)。
* **即時監控儀表板 (Live Dashboard)**: 透過 CLI 介面即時顯示每個任務的進度、請求數 (Requests)、發現漏洞數 (Issues) 及狀態。
* **批量並發掃描**: 支援多執行緒 (Multi-threading)，可同時對多個目標進行掃描，並自訂並發數量 (Workers)。
* **彈性策略配置**: 支援切換不同的掃描設定 (如 Fast, Balanced, Deep, Audit only 等)。
* **專業報告生成**:
    * **HTML**: 視覺化報告，包含漏洞嚴重性分級 (High/Medium/Low/Info)、詳細描述與證據截圖。
    * **JSON**: 完整的原始掃描數據，便於與 CI/CD 或其他資安管理平台整合。
* **任務匯出**: 支援輸入 Task ID 匯出 Burp 上既有任務的報告。

## 📋 前置需求 (Prerequisites)

1.  **Burp Suite Professional**: 必須使用專業版 (Community 版不支援 REST API)。
2.  **Python 3.6+**: 建議使用最新版本的 Python。
3.  **Python 套件**:
    ```bash
    pip install requests
    ```

## ⚙️ Burp Suite 設定 (Configuration)

在執行程式前，請確保 Burp Suite 已開啟 REST API 功能：

1.  開啟 Burp Suite Professional。
2.  進入 **Settings** > **Suite** > **REST API**。
3.  勾選 **Service is running**。
4.  設定 Port 為 `1337` (程式預設值)。
5.  (選用) 若勾選 **Require API key**，請複製金鑰並填入程式碼中的 `API_KEY` 欄位。

## 🚀 使用說明 (Usage)

### 1. 準備目標清單
在程式同目錄下建立 `urls.txt`，每行輸入一個目標網址：

```text
http://example.com
https://test-site.org/login
http://192.168.1.100
```

### 2. 啟動程式
```Bash
python main.py
```
### 3. 操作流程
程式啟動後將顯示主選單：

* **API 狀態檢查**: 程式會自動檢查連線與知識庫載入狀態。

  * **選項 1 (New Scan)**:
    * **輸入網址清單檔名 (預設 `urls.txt`)。**
    * **選擇掃描策略 (預設 `Crawl and Audit - Fast`)。**
    * **設定並發執行緒數 (預設 2)。**

  * **選項 2 (Export Existing): 輸入 Task ID (如 `1, 3, 5`) 來匯出既有任務報告。**

## 📂 輸出檔案結構
所有報告將儲存於 `reports/` 資料夾：

```Plaintext
reports/
├── YYYYMMDD_HHMMSS_Report_url.html          # 完整 HTML 報告
├── YYYYMMDD_HHMMSS_Data_url.json            # 原始 JSON 數據
└── YYYYMMDD_HHMMSS_Global_Scan_Summary.json # 當次執行總結 (若有多個目標)
```
## ⚠️ 免責聲明 (Disclaimer)
本工具僅供安全性測試、漏洞評估與教育用途。使用本工具進行掃描前，請確保您已取得目標系統擁有者的明確授權。使用者需自行承擔因使用本工具而產生的所有法律責任與風險。

## 📝 版本紀錄 (Version History)
**v10.0 (Current) - 2025-12-17**
* [新增] API 自動偵測機制: 程式啟動時自動檢查 API 存活狀態，離線時進入等待模式而非直接崩潰。
* [新增] 知識庫 (Knowledge Base) 載入: 自動從 API 抓取 issue_definitions，解決報告中缺少通用修復建議的問題。
* [優化] 報告內容: 增加 issue_background 和 remediation_background 欄位的整合，報告內容更豐富。
* [優化] Dashboard UI: 改良 CLI 介面顯示，新增「API 狀態」與「知識庫狀態」指示燈。
* [修復]: 修正部分情況下 JSON 匯出編碼錯誤的問題。

**v9.0 - 2025-12-16**
* [新增] 支援多執行緒 (ThreadPoolExecutor) 掃描，提升批量任務效率。
* [新增] 即時 Dashboard，顯示各任務請求數 (Reqs) 與漏洞數 (Issues)。
* [新增] 掃描策略選擇 (Fast, Balanced, Deep)。

**v1.0 - 2025-12-16**
* [初始] 基礎單執行緒掃描功能。
* [初始] 支援 HTML 與 JSON 報告導出。

## 👥 作者 (Authors)

* **Sapang** - *專案開發與核心邏輯 (Core Developer)
* **Gemini** - *AI 協作助手與程式優化 (AI Assistant)*

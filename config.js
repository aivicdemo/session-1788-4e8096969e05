// AIVIC Backend Configuration
// AIVIC_APP_URL 環境変数が設定されている場合は自動セットされます
// 未設定の場合: REPLACE_WITH_API_URL を AIVIC アプリの URL（例: https://your-app.amplifyapp.com）に書き換えてください

window.AIVIC_API_URL = "REPLACE_WITH_API_URL";
window.AIVIC_TABLES = {
  "脆弱性": 0,
  "脆弱性スキャン結果": 1,
  "脆弱性対応チケット": 2,
  "影響範囲分析": 3,
  "システム資産": 4,
  "権限設定": 5,
  "脆弱性マスタ": 6
};

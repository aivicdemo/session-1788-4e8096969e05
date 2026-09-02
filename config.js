// AIVIC Backend Configuration
// AIVIC_APP_URL 環境変数が設定されている場合は自動セットされます
// 未設定の場合: REPLACE_WITH_API_URL を AIVIC アプリの URL（例: https://your-app.amplifyapp.com）に書き換えてください

window.AIVIC_API_URL = "REPLACE_WITH_API_URL";
window.AIVIC_TABLES = {
  "施設": 0,
  "施設利用時間帯": 1,
  "予約": 2,
  "抽選申込": 3,
  "決済": 4,
  "決済履歴": 5,
  "キャンセル": 6,
  "施設カテゴリ": 7,
  "利用者認証ログ": 8
};

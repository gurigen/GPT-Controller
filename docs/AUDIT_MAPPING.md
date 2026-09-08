# 両監査の比較・採否と対応状況

4.1.0rc2で更新した実装・検証範囲は `RC2_CHANGES_JA.md` を参照してください。以下の表はrc1で導入された処理と監査項目の対応を保ちます。実行合格数は新しいverification/STATUS.jsonを優先し、旧アクセス障害や実機未接続の記載は現在の接続確認へ流用しません。

日付：2026年9月8日。元コミット：90a6f329ea99ade3f08bc377936f3daf43a02774。以下の「実装」は配布候補にコードが存在する意味で、PC導入済み・Windows受入済みという意味ではありません。

## 比較の採否

添付監査は別利用者の制御リポジトリに残る4件のPowerShell実行履歴を見ています。本体ソースが含まれていないため、その履歴に使われていないGUI・ブラウザー・expires_at・workspace保護を「本体にない」とする推定は採用していません。本体の61ファイルの実装を優先しています。

新しいq-agent-v5やtarget.agent_idは導入せず、q-agent-v4/target.agentを維持しました。要求ハッシュ、端末状態の公開、細かい権限、操作後の確認、依存関係、秘密情報の除去は追加しました。期限切れclaimを別PCへ自動再割当する案は二重実行リスクがあるので不採用とし、ambiguousのまま状態確認を要求します。

## 22指摘との対応

| 指摘 | 主な実装・確認 | 状態と残り |
|---|---|---|
| F01 無差別retry | workflow/state/integration、実追記後エラーの一度だけ実行 | 実装・Linux動作確認。外部サービスのexactly-once保証ではない |
| F02 GUI時間切れ後の継続 | 署名IPC/期限/取消/終了確認/隔離、別プロセスホスト試験 | 実装。Windows native UIAの停止・watchdog再起動は未確認。GUI操作毎の子プロセス隔離は未実装 |
| F03 未達が完了に変化 | 条件未達exhausted/failed、再開時検証 | 実装・回帰試験 |
| F04 checkpointの同一性 | fingerprint/所有者/手順/ポリシー/明示再開参照 | 実装・回帰試験 |
| F05 画像返却 | AES-GCM store/chunk/SHA/認証HTTP/実Chromium PNG復元 | 実装・局所経路確認。あなたのPC→会話の遠隔経路は未確認 |
| F06 対象取り違え | 完全一致・一意性・process_id・filename部品必須 | 実装・模擬要素の動作確認。Windows実ダイアログ未確認 |
| F07 タブ所有権 | 作成ページ集合・借用ページ保持・不一致拒否 | 実装・実CDP試験 |
| F08 権限抜け | 操作別policy/非干渉/前面化/clipboard、通常タスクLimited | 実装。別の最小権限OSブローカーは未実装。任意shellはsandboxではない |
| F09 同ID重複 | filename一致・claim/running/results・payload hash・SQLite | 実装・2クローン統合試験 |
| F10 bootstrap削除 | 通信エラー時中止、既存config/非空フォルダー保全、段階導入 | コード実装。PowerShell導入の実機確認は未済 |
| F11 workspace継承 | normalize/step_context共通化 | 実装・実書込先試験 |
| F12 型・未知op | bounded JSON、操作引数レジストリ、生成schema、事前検証 | 実装・回帰試験。上位の任意メタデータは互換性上許可、全step schemaは厳密一本化ではない |
| F13 メモリ | streaming stdout/stderr・結果/配列上限・部分file.read | 実装・大量出力試験。第三者ブラウザーAPIの内部割当まで制限しない |
| F14 秘密 | 認証stateローカル・通常export拒否・出力伏字 | 実装・模擬秘密試験。任意の非定型機密や画像内の機密完全除去は未実装 |
| F15 下限版 | Python3.11、DateKind依存除去、Linux/Windows版別CI定義 | コード実装。実測はPython3.13のみ、遠隔CI未実行 |
| F16 更新/復元 | 別source/venv/staging/試験/旧定義バックアップ/明示切替/health/復元 | コード実装・静的検査。Windows切替/復元未実行、依存は候補側で解決しfreezeを保存 |
| F17 porcelain | NUL区切り/先頭列保全/rename | 実装・実Git試験 |
| F18 uninstall | watchdogから先に止めて本体と解除 | コード実装。Windows実行未確認、別installのプロセス残留確認が必要 |
| F19 結果粒度 | 親子step path・状態・goal evidence・bounded stderr | 実装・別worker試験。全UI例外で前後画像を自動保存する機能は未実装 |
| F20 検証 | 旧テスト維持＋変更契約の置換＋実Git/Worker/Chromium/IPC/PNG | Linux実行済み。Windows11実画面・負DPI・UACなどの受入は未済 |
| F21 入力/座標 | physical origin/DPI/前面・画面照合/Unicode/drag finally | コード実装・純粋座標試験。Windows IME/SendInput/三画面は未確認。人の物理入力を検出する専用hookは未実装 |
| F22 診断/永続/保存期間 | doctor/host probe/fsync/SQLite/成果物TTL | 実装。未確定台帳/観察/元PNG/退避フォルダーの統一保持制御は一部未実装 |

## 添付監査の独自項目

端末manifest/status、要求とclaim/resultのハッシュ、先行Action結果のハッシュ照合、not_before/local最大経過時間、派生権限、結果だけの送信復旧を追加しています。稼働端末の状態期限は「再実行権限」にはしません。

process.list、file.list/stat、既存process.exec/PowerShellを保持しています。永続サービスの安全な起動停止APIやアプリ別の専用処理まですべて追加したわけではありません。

## 未実装と未検証の違い

コード未実装：専用OS権限ブローカー、物理人入力検出hook、任意アプリ別アダプター、汎用目的から自律計画する常駐LLM、全種類のデータの統一保持制御など。

コードあり・未検証：Windows GUI/Unicode/DPI/DPAPI/TaskScheduler切替復元、Windows Job Object再試験、遠隔PCからChatGPTへの画像表示。

アクセスにより未実施：GitHub push/PR、あなたのPCの導入済み版・設定照合、実機への配備。これらをテスト合格数から推定してはいけません。

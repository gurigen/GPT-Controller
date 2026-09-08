# GPT Controller 修正版 4.1.0rc2

作成日：2026年9月8日。これは今回の会話で作成した候補版で、公開上流のリリースではありません。

今回の差分と残りの範囲は `docs/RC2_CHANGES_JA.md` を参照してください。

## 現在の状態

本体コードへ改善を組み込んだ修正版です。提案書だけではありません。元となった61ファイル全体は Git tree `158f8361cba27442fa5b7cb1b1d47f04f8940593` と完全一致することを確認してから変更しています。元コミットは `90a6f329ea99ade3f08bc377936f3daf43a02774` です。

Linux/Python 3.13での実行結果は配布物の `verification/STATUS.json` と JUnit XML が根拠です。試験には実ファイル、実子プロセス、二つの一時Gitクローン、実Chromium、画像復元が含まれます。Windows専用のJob Object試験、実デスクトップ操作、DPAPI、Task Scheduler、導入切替・復元は作成者環境で未実行です。

GitHubへのpushとあなたのPCへの導入は行っていません。`HARDENING_BUILD.json` は生成記録、`SOURCE_MANIFEST.json` は静的ソースのハッシュ台帳です。どちらもWindows合格証ではありません。

## 主な変更

実行台帳に要求ハッシュと段階別の結果を記録します。副作用の成否が不明なら `ambiguous` にして後続操作を止め、自動再実行しません。完了条件が未達なら、チェックポイント再開でも成功へ変えません。明示した継続手順と所有者・内容が一致する場合だけ再開します。

画面操作の要求と応答には署名・期限を付けます。時間切れ後、実行側の終了を確認できない間は新しい入力を隔離します。入力中にも取消と前面ウィンドウを確認します。Windowsホストが既に送ったネイティブ操作まで取り消せるとは主張しません。

ブラウザーは自分で作ったタブだけを片付けます。指定タブが見つからない場合は別タブを推測して操作しません。ファイル名とダイアログの候補も一意性・所属プロセスを確認します。

画像を暗号化して保存し、容量・期限・ハッシュ付きの分割取得を行えます。画像取得用の認証付きHTTPはループバック専用です。これだけでインターネット越しに接続できるわけではありません。Git経由で画像を返す `artifact.get` には、公開してよい画像かのローカル承認が必要です。取得した画像はprivate Git履歴にも残ります。

ファイル出力は標準で上書きを拒否し、削除は標準で退避にします。処理の出力は受信中から上限を適用します。既知の秘密情報の形式や設定済み環境変数の秘密値を伏せますが、任意の文章や画像内の機密を完全に検知する機能ではありません。

ゴール条件、先行処理の成功確認、端末状態の報告、読み取り中心の診断、未送信結果だけの再送、非破壊的な導入準備を追加しています。

## ゴール設定

`examples/hardening-goal.action.json` が実装済みの形式です。最初に `target.agent` を実際の端末IDへ、`id` を一度しか使わない値へ変更してください。標準例は `scratch/verification/report.csv` を新規作成します。既存ファイルがある場合は勝手に上書きしません。

`goal.description` だけでは成功判定できません。`goal.conditions` に観測可能な条件を指定します。現在はファイル存在、SHA256、テキスト包含、CSVヘッダー、構造化した操作結果の比較を実装しています。すべての条件を実際に確認して初めて `goal_achieved: true` を返します。

ゴールの文章から手順を考えるのはChatGPTです。PC RuntimeにLLMや無期限の自律計画機構を組み込んだものではありません。ChatGPTが判断して明示的なActionを送り、その結果を見て次のActionを選ぶ設計を維持します。

## 導入前の確認

この候補版は既に登録済みのインストールに対する段階的な移行用です。自動で制御リポジトリを新設したり、別ユーザーやSYSTEMの資格情報を推測したりしません。トークンやパスワードをチャットへ貼る必要はありません。

元の設定・作業フォルダー・未送信結果を保全してください。既存GUIホストと新しい署名付きIPCは混在させないでください。通常使用PCではなく、テスト用環境でWindowsの受入試験を先に行います。

PowerShell 7から、展開した修正版フォルダーで次を実行します。

```powershell
pwsh -NoProfile -File .\scripts\install-candidate.ps1 -InstallRoot C:\GPT-Controller
```

これは**準備だけ**です。別のreleaseフォルダーと仮想環境で依存関係・Chromiumを導入して試験し、Gitと設定を診断します。既存タスクの実行先を切り替えません。元のInstall/Update BATもこの準備処理を呼ぶよう変更しています。

準備済みの候補は同じソースハッシュで識別します。依存バージョンは `requirements-frozen.txt` に保存します。過去の仮想環境を再解決して戻すのではなく、元の環境を残したままタスク定義を切り替える方式です。全Windows構成での復元を検証済みという意味ではありません。

## 明示的な切替

制御キューが空で、命令送信元を止めていることを確認してください。実行中や未確定の処理があれば切替は拒否します。管理者のPowerShellで次を実行します。

```powershell
pwsh -NoProfile -File .\scripts\install-candidate.ps1 -InstallRoot C:\GPT-Controller -Activate
```

物理入力が既に許可されている設定では、作成者によるWindows実機確認が未済であるため、テスト環境での検証を済ませたうえで `-AcknowledgeDesktopValidationPending` も必要です。スクリプト自身が入力権限を有効化することはありません。

通常RuntimeはLimitedへ変更します。既存Interactive Hostの明示的な実行レベルは保持します。SYSTEM/別ユーザーでの既存登録は自動移行しません。GUIホストが元からない場合、勝手に追加せずGUI非対応のままです。

切替時には旧タスクXMLと設定を保存し、旧プロセスの終了と新しい版の心拍、Git疎通、既存GUIホストの無害な応答を確認します。失敗時は旧タスク・設定を復元する処理があります。ただしWindowsで実行していないので、重要な環境へ無検証で適用しないでください。

## 停止・承認・診断

候補の仮想環境のPythonを `$python` に指定します。

```powershell
& $python -m agent_runtime.hardening.cli --config C:\GPT-Controller\agent.config.json doctor --require-git
& $python -m agent_runtime.hardening.cli --config C:\GPT-Controller\agent.config.json pause
& $python -m agent_runtime.hardening.cli --config C:\GPT-Controller\agent.config.json cancel ACTION_ID
& $python -m agent_runtime.hardening.cli --config C:\GPT-Controller\agent.config.json resume
```

`pause` は新しい画面入力を止めます。全プログラムを即時終了させるボタンではありません。特定処理の終了要求には `cancel` を使い、返った `stopped_confirmed` と最終結果を確認します。終了未確認のGUI処理があれば `resume` でも解除しません。

承認はActionの実際の内容を読んだうえで、正規化JSONのSHA256に対して一度だけ与えます。

```powershell
& $python -m agent_runtime.hardening.cli --config C:\GPT-Controller\agent.config.json approve .\reviewed-action.json --expected-sha256 ACTUAL_CANONICAL_SHA256 --ttl 300
```

通常のファイルSHA256と正規化JSONのSHA256は異なります。`agent_runtime.hardening.common.digest` で計算します。承認コマンドにはハッシュと対象Actionの一致確認があり、内容変更後の古い承認は使えません。拒否されたActionを自動再投入しないため、必要な承認はキューへ投入する前に作成します。

## 制約と残りの受入項目

Windowsで実際のウィンドウ・日本語IME・多画面DPI・ロック復帰・UAC・署名IPC・Task Scheduler切替を試験していません。Linux上のUIロジック試験を、それらの合格とは数えません。

専用の最小権限OSブローカー、物理的な人の入力だけを検出して譲る常駐フック、Premiere/Discordなど個別製品の専用アダプターは未実装です。既存の汎用UIA・ブラウザー・明示コマンドは残っていますが、全アプリの全仕事を保証する状態ではありません。

成果物の暗号化DBには期限・容量制限があります。元のブラウザー保存ファイルやGUIのPNG、観察記録、取消記録、復旧台帳、退避ファイルの一括保存期間管理は完全ではありません。未確定の実行証拠を勝手に削除しません。

制御リポジトリへの書込権限は強い実行権限です。trustedモードの任意shellをOSが閉じ込める設計ではありません。ループバックHTTP、SHA/HMAC、暗号化も、同じWindowsアカウントの悪意あるプログラムから完全に保護するものではありません。

対応状況の詳細は `docs/AUDIT_MAPPING.md`、形式は `docs/HARDENING_CONTRACT.md`、検証の根拠は配布物の `verification/` を参照してください。

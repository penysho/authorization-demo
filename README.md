# Authorization Demo

Golang + Gin + Casbin を使ったRBAC/ABAC認可システムのサンプルアプリケーション

## 概要

ECサイトのバックエンドAPIを想定し、商品管理における認可制御を実装したデモアプリケーションです。

### 機能

- **RBAC (Role-Based Access Control)**
  - 管理者ロール: 商品の閲覧、編集、削除が可能
  - 運用者ロール: 商品の閲覧、編集が可能
  - 顧客ロール: 商品の閲覧が可能

- **ABAC (Attribute-Based Access Control)**
  - 商品IDごとに、ユーザーの年齢に応じて閲覧可能かどうかを判定

### 使用技術

- Go 1.23+
- Gin Web Framework
- Casbin v2 (認可ライブラリ)
- JWT認証

## セットアップ

1. 依存関係をインストール

```bash
go mod tidy
```

2. アプリケーションを起動

```bash
go run main.go
```

3. サーバーが起動します（デフォルト: <http://localhost:8080）>

## API エンドポイント

### 認証

- `POST /api/auth/login` - ログイン（JWT トークン取得）

### 商品管理

- `GET /api/products` - 商品一覧取得
- `GET /api/products/:id` - 商品詳細取得
- `PUT /api/products/:id` - 商品更新
- `DELETE /api/products/:id` - 商品削除

## テストユーザー

以下のテストユーザーでログインできます：

- **管理者**: alice (全権限)
- **運用者**: bob (閲覧・編集)
- **顧客**: charlie (閲覧のみ)

ログイン時はパスワードとして `password` を使用してください。

## 設定ファイル

- `config/rbac_model.conf` - RBAC モデル定義
- `config/abac_model.conf` - ABAC モデル定義

## ディレクトリ構成

```
.
├── main.go                 # エントリーポイント
├── config/                 # Casbin設定ファイル
├── internal/
│   ├── auth/              # 認証関連
│   ├── middleware/        # ミドルウェア
│   ├── handler/           # HTTPハンドラー
│   ├── model/             # データモデル
│   └── service/           # ビジネスロジック
└── README.md
```

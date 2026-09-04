# DNSクエリー送信ツール

ブラウザからDNSクエリーを送信し、DNSパケットの応答内容を解析して表示するWebアプリケーションです。`dig` や `drill` のような確認を、DNSの委任や各種オプションを意識しながらWebブラウザで行えます。

## 公開サイト

https://www.on-link.jp/dnsquerytool/

## 主な機能

- DNSサーバーを指定したクエリーの送信
- UDPまたはTCPによるDNS通信
- IPv4またはIPv6を優先したDNSサーバー名の解決
- 非再帰検索と再帰検索（RD）の切り替え
- QNAME minimisation（RFC 7816 / RFC 9156）を利用した反復検索
- EDNS0、DNSSEC OK（DO）、Checking Disabled（CD）、NSIDの指定
- UDPメッセージサイズの指定
- MQTYPE-Query（RFC 10029）の指定と応答表示
- A、AAAA、MX、NS、SOA、TXT、CNAME、DNSKEY、DS、HTTPS、SVCBなどのレコード表示
- DNS応答の `ANSWER`、`AUTHORITY`、`ADDITIONAL` セクションの解析
- TCフラグ、rcode、DNSSEC関連情報、Extended DNS Errorの表示
- 応答に含まれるドメイン名やIPアドレスから、次のクエリーを実行
- クエリー条件をURLのクエリーパラメーターとして保持

## 使い方

1. 「対象ドメイン名」に問い合わせたいドメイン名を入力します。
2. 必要に応じて「クエリー先DNSサーバー」、「クエリータイプ」、「RD」などを変更します。
3. 「DNSパケットを送信」をクリックします。
4. 表示された `ANSWER`、`AUTHORITY`、`ADDITIONAL` の内容を確認します。

デフォルトでは `a.root-servers.net` を問い合わせ先とする非再帰検索です。委任を辿る場合は、応答に表示されたNSやIPアドレスをクリックして次の問い合わせを実行できます。

フルサービスリゾルバーに名前解決を任せる場合は、問い合わせ先にフルサービスリゾルバーを指定し、「RD」にチェックを入れてください。

## ローカルで実行する

### 必要な環境

- Node.js
- DNSサーバーへUDPまたはTCPの53番ポートで接続できるネットワーク

### 起動

```sh
npm install
node dns-web-tool.js
```

起動後、次のURLを開きます。

http://localhost:3000/dnsquerytool/

サーバーはポート `3000` で待ち受けます。公開環境などでアプリケーションのパスを変更する場合は、`APPLICATION_PATH` 環境変数を指定できます。

PowerShellの例:

```powershell
$env:APPLICATION_PATH = '/dnsquerytool'
node dns-web-tool.js
```

## クエリーオプション

画面で指定できる主なオプションは次のとおりです。

| 項目 | URLパラメーター | 説明 |
| --- | --- | --- |
| 問い合わせ先 | `server` | DNSサーバーのホスト名またはIPアドレス。省略時は `a.root-servers.net` |
| ドメイン名 | `name` | 問い合わせ対象のドメイン名 |
| クエリータイプ | `type` | `A`、`AAAA`、`MX`、`NS`、`SOA`、`TXT`、`CNAME`、`DNAME`、`CAA`、`DNSKEY`、`DS`、`NSEC`、`NSEC3`、`RRSIG`、`SRV`、`HTTPS`、`SVCB`、`PTR`、`PTR-x`、`ANY`、`VERSION` |
| 再帰検索 | `rd=1` | RDフラグを付ける |
| チェック無効化 | `cd=1` | CDフラグを付ける |
| QNAME minimisation | `qmini=1` | QNAME minimisationを有効にする |
| QNAME位置 | `qposi` | QNAME minimisationで問い合わせるラベル位置 |
| QNAMEタイプ | `qtype` | `A` または `NS` |
| EDNS0 | `edns0=1` | EDNS0を付与する |
| DNSSEC情報 | `dnssec=1` | DOフラグを付ける |
| UDPサイズ | `udpsize` | EDNS0のUDPメッセージサイズ。`512`～`65535` |
| NSID | `nsid=1` | NSIDオプションを要求する |
| MQTYPE | `mqtype` | 例: `A,AAAA,MX` |
| TCP | `tcp=1` | TCPで問い合わせる |
| IPv6 | `ipv6=1` | DNSサーバー名の解決・通信でIPv6を優先する |

APIのエンドポイントは、アプリケーションパスからの相対パスで `api/query` です。ブラウザ画面はこのエンドポイントへリクエストし、解析済みのHTMLを受け取って結果欄に表示します。

例:

```text
http://localhost:3000/dnsquerytool/api/query?server=8.8.8.8&name=example.com&type=A&rd=1
```

## ファイル構成

| ファイル | 役割 |
| --- | --- |
| `index.html` | 入力フォーム、説明、結果表示領域 |
| `dns-web-tool-client.js` | フォーム送信、履歴操作、結果表示、リンクからの再クエリー |
| `dns-web-tool.js` | HTTPサーバー、DNSパケット生成、UDP/TCP通信、応答解析、HTML生成 |
| `test-mqtype.js` | MQTYPEオプションの構築と応答解析の簡易テスト |
| `package.json` | Node.js依存関係の定義 |

## MQTYPEテスト

依存関係をインストールした後、次のコマンドでMQTYPEの簡易テストを実行できます。

```sh
node test-mqtype.js
```

このテストはMQTYPEのバイト列の構築と、`A,AAAA,MX` のような応答データの解析を確認します。実際のDNSサーバーがRFC 10029に対応しているかどうかは検証しません。

## 注意事項

- このツールはDNSの動作確認・学習を目的としています。
- DNSSECの検証処理は行いません。DO/CDなどのフラグを付けて問い合わせるためのツールです。
- `localhost`、ループバックアドレス、プライベートアドレスなどのDNSサーバーは問い合わせ先に指定できません。
- DNSサーバーへの問い合わせは、実行環境から対象サーバーの53番ポートへ直接行われます。ネットワークやファイアウォールの設定によっては応答を受信できません。
- DNSクエリーの結果は問い合わせ先サーバーやネットワークの状態によって変わります。
- 公開サーバーとして運用する場合は、アクセス制御、レート制限、ログ、HTTPS、Node.jsの更新などを別途検討してください。

## 依存関係

- [dns-packet](https://www.npmjs.com/package/dns-packet) `^5.6.1`
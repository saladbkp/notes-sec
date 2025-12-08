# Notes Zero-Trust

A minimal Notion-like notes app with end-to-end encryption and a zero-trust server. The server never receives plaintext content; all encryption/decryption happens in the browser.

## Requirements

- Node.js 18+
- Windows, macOS, or Linux

## Install

```bash
npm install
```

## Start Server

```bash
npm run server
```

Entry: `http://localhost:3333/` → redirects to `http://localhost:3333/login`

Pages:
- `http://localhost:3333/login` – login/register (centered box)
- `http://localhost:3333/dashboard` – unlocked dashboard with sidebar and editor

## Usage

- Login/Register at `http://localhost:3333/login`. After success you are redirected to `http://localhost:3333/dashboard`.
- The dashboard auto-unlocks your vault for the current browser session; no separate unlock step.
- Create Note: enter title and content; encryption happens locally. You can paste an image directly into the content area; it will be embedded as a data URL and encrypted.
- Search: type a title term; client computes a blind index hash and queries the server.
- Open Note: click an item in Your Notes or a search result to decrypt locally.
- Manage Notes: use the sidebar dashboard to view, search, create, and delete notes.
- Share Note: click Share on a note, enter the recipient’s email. A share link is generated like `/ui/?share=<token>#key=<b64>`. Only the recipient account can open the link, and the `#key` fragment never reaches the server.
- Logout: clears session and local vault state.

## API Base

- UI uses the same origin. All API paths are under `/` (e.g. `/auth/login`).

## Security

- Content is encrypted client-side using AES-GCM.
- Vault and per-note keys are envelope-encrypted; the server stores only ciphertext.
- CSRF tokens are required for mutating requests and are automatically sent by the UI.
- Helmet and rate limiting are enabled on the server.

## Project Structure

- `server/index.js`: Express server and SQLite data store.
- `client/index.html`: UI shell.
- `client/main.js`: Client-side crypto and app logic.
- `client/style.css`: Styling.
- `server/data/notes.db`: SQLite database (created at runtime).

## Commands

- `npm install` – install dependencies
- `npm run server` – start the server on `http://localhost:3333`

## Notes

- First vault unlock creates your vault key if none exists.
- The list view fetches titles per note to decrypt client-side.

## PROGRESS

8/12
http://localhost:3333/ui/
login register /

vault password ? abit shit 
create note 
search 
you note 
share note

delete note x 
layout 参考 我给的照片 x
no refresh for created note x
refresh http://localhost:3333/ui/ -> re login ?

1
login page 我要 box 放中间 
然后 不要用 http://localhost:3333/ui/
改成 http://localhost:3333/login
2
Unlock Vault 我不要了 
直接 进 dashboard http://localhost:3333/dashboard
3 
这个 dashboard layout 有问题 参考 照片2 左边的 section 应该 init 就 load all note 
add page -> 就是 加 新 note 
这个 时候 才放 Vault password 每一个 笔记 都有自己的密码 用户可以选择设置密码或者不设置 但是鼓励
然后 这个 content title 不会 encrypt 所以 我可以在 左边 section 看到 但是 我 ceate 了 后 -> set password -> 按左边的 Note 
右边 就会 show title, content 
4
search note 不要 放右边 section 放在 最高的 header beside of Notes Zero-Trust, 然后 找到的是 关键title 用 regex 
5
右边 section 很奇怪 Create Note
Title
Note title
Content
Create
Title
Untitled
Content
Save
Share
Delete

我只要 
title 可以改 
content 可以改 
然后 一个 save button 

share 和 delete button 是一个 emoji 在 左边 选 note 的 bar

下一步是 改
lock unlock status /
还没check search regex  / auto update 是最好
为什么 all note 会不见  {"error":"unauthorized"}


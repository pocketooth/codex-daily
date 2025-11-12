# Live Markdown Search

A full-stack demo application for searching, uploading, downloading, and managing Markdown documents with live updates.

## Features

- 🔐 JWT-based authentication with viewer, editor, and admin roles
- 🔎 Fuzzy Markdown search with AND, regex, and wildcard modes powered by Fuse.js
- ⬆️ Upload, ⬇️ download, and 🗑️ delete Markdown files
- 📡 Real-time notifications when files change or the index rebuilds
- 📝 Upload history tracking for administrators
- 🌐 Simple HTML/CSS/JavaScript frontend with Socket.IO live updates

## Getting Started

1. **Install dependencies**

   ```bash
   npm install
   ```

   > **Note:** If your environment restricts access to npm, install the listed dependencies manually: `express`, `socket.io`, `fuse.js`, `multer`, `jsonwebtoken`, `cors`, and `chokidar`.

2. **Run the server**

   ```bash
   npm start
   ```

   The API and static frontend are served from `http://localhost:3000` by default.

3. **Open the app**

   Navigate to `http://localhost:3000` in your browser. Use the login panel to request a JWT for the desired role.

## API Reference

| Method | Endpoint | Description | Role |
| ------ | -------- | ----------- | ---- |
| `GET` | `/get-token?user=Alice&role=viewer` | Issue a short-lived JWT. | Public |
| `GET` | `/search-doc?keywords=socket,live&mode=and` | Search Markdown lines (supports AND, regex, and wildcard modes). | Viewer+ |
| `POST` | `/upload-doc` | Upload a `.md` file (form field `file`). | Editor/Admin |
| `GET` | `/download-doc/:filename` | Download a Markdown file. | Viewer+ |
| `DELETE` | `/delete-doc/:filename` | Delete a Markdown file. | Admin |
| `GET` | `/upload-history` | View upload audit log. | Admin |
| `POST` | `/force-reindex` | Manually rebuild the search index. | Admin |

All authenticated routes expect an `Authorization: Bearer <token>` header.

## Project Structure

```
.
├── docs/             # Markdown documents live here
├── index.html        # Frontend UI
├── package.json      # npm metadata and dependencies
├── server.js         # Express + Socket.IO backend
└── uploads.json      # Upload history log
```

## Development Notes

- Uploaded files overwrite existing documents with the same name.
- The search index automatically rebuilds when Markdown files are added, modified, or removed.
- Upload history entries capture username, role, filename, and upload timestamp.
- Customize the JWT secret by setting `JWT_SECRET` in your environment.
- Search supports multiple strategies via the `mode` query parameter:
  - `and` (default): comma-separated keywords must all appear in a matching line.
  - `regex`: full JavaScript regular expressions with operators such as `|` for OR.
  - `wildcard`: simple patterns using `*` (any sequence), `?` (single character), and `|` for alternation.

## License

This project is provided as part of the University Coding Challenge 2025 practice scenario.

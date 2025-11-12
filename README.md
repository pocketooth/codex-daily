# Live Markdown Search

A full-stack demo application for searching, uploading, downloading, and managing Markdown documents with live updates.

## Features

- Role-based authentication with built-in viewer, editor, and admin accounts.
- Secure JWT issuance via POST /login plus /session validation for auto-restore.
- Fuzzy Markdown search (AND, regex, wildcard) powered by Fuse.js.
- Upload, download, delete, preview, and inline edit Markdown files (editors/admins).
- Real-time file change notifications via Socket.IO, including preview auto-refresh.
- Upload history tracking with live filtering (admin only).
- Split preview with optional synchronized scrolling and Markdown rendering via Marked.
- Dark/light theme toggle with persistence across visits.

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

   Navigate to `http://localhost:3000` in your browser. Sign in with one of the seeded accounts (passwords follow `username_123!`):

   | Username | Role   | Password      |
   | -------- | ------ | ------------- |
   | `admin`  | admin  | `admin_123!`  |
   | `manager`| editor | `manager_123!`|
   | `guest`  | viewer | `guest_123!`  |

   Editors and admins can upload and edit Markdown directly from the preview panel; viewers have read-only access.

## API Reference

| Method | Endpoint | Description | Role |
| ------ | -------- | ----------- | ---- |
| `POST` | `/login` | Exchange username/password for a JWT (8h expiry). | Public |
| `GET` | `/session` | Validate a stored JWT and return the active profile. | Viewer+ |
| `GET` | `/search-doc?keywords=socket,live&mode=and` | Search Markdown lines (supports AND, regex, and wildcard modes). | Viewer+ |
| `GET` | `/preview-doc/:filename` | Return Markdown content and metadata for preview. | Viewer+ |
| `GET` | `/download-doc/:filename` | Download a Markdown file. | Viewer+ |
| `POST` | `/upload-doc` | Upload a `.md` file (form field `file`). | Editor/Admin |
| `PUT` | `/edit-doc/:filename` | Overwrite a Markdown file with JSON `{ content }`. | Editor/Admin |
| `DELETE` | `/delete-doc/:filename` | Delete a Markdown file. | Admin |
| `GET` | `/upload-history` | View upload audit log. | Admin |
| `POST` | `/force-reindex` | Manually rebuild the search index. | Admin |

All authenticated routes expect an `Authorization: Bearer <token>` header.

## Preview Editing & Sync

- Click **Preview** on any search hit to open the side-by-side viewer.
- Editors and admins will see an **Edit File** button. Toggling it reveals an in-browser editor that can save straight back to disk (and automatically rebuilds the search index).
- The split preview offers a floating **Sync** toggle so you can lock scrolling between raw and rendered panes or turn it off for independent scrolling.
- Live Socket.IO events automatically refresh any open preview or rerun the last search when a file changes.

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
- Use the preview button to inspect Markdown content without downloading. Toggle between raw, rendered, or split views via the preview toolbar—your choice persists, and previews refresh automatically when the underlying file changes.
- Admins can type in the history filter field to instantly narrow the upload log by filename, user, role, or timestamp.
- Toggle light and dark themes via the header button—your selection is remembered across visits.

## License

This project is provided as part of the University Coding Challenge 2025 practice scenario.


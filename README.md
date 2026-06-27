# 🛡️ VestPanel - Secure File Manager

**VestPanel** is a lightweight, secure, and self-hosted file manager built for Ubuntu servers. It features a one-line installation, auto-generated strong passwords, hidden admin path, and a full-featured web-based file explorer with code editor, upload manager, and terminal emulator (optional).

## ✨ Features

- 🔒 **Secure by default** – CSRF protection, rate limiting, IP blocking, session validation, and more.
- 🚀 **One-line installation** – No manual configuration. Just run a single command.
- 🎲 **Random admin path** – The panel URL is randomly generated during installation (e.g., `/x7k9p2m4/panel.php`).
- 🔑 **Auto-generated strong password** – 16-character secure password with symbols, numbers, and letters.
- 📁 **Full file management** – Upload, download, delete, rename, move, zip, unzip, and edit files.
- 🖥️ **Built-in code editor** – Monaco Editor (VS Code-like) with syntax highlighting for PHP, JS, HTML, CSS, and more.
- 📊 **Server stats dashboard** – Real-time RAM, CPU, and disk usage monitoring.
- 🛡️ **Login protection** – Failed login attempts are logged and IPs are temporarily blocked.
- 🌐 **HTTP/HTTPS compatible** – Works on both HTTP and HTTPS environments.
- 🧹 **Clean and modern UI** – Built with Tailwind CSS and dark mode support.

## 📦 Requirements

- **Ubuntu 20.04 / 22.04 / 24.04** (or any Debian-based system)
- **Nginx** (installed and running)
- **PHP 8.1 or 8.3** with `php-fpm`, `zip`, `mbstring`, `xml`, and `curl`
- **curl** and **openssl** (usually pre-installed)
- **Root or sudo access** for installation

## 🚀 Quick Installation

Run the following command on your Ubuntu server:

```bash
sudo bash <(curl -sSL https://raw.githubusercontent.com/vesalalizadeh08/vestpanel/main/install.sh)
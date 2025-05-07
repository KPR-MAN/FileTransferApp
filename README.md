# File Transfer App

<p align="center">
  <img src="https://drive.google.com/uc?export=view&id=1n2P0hfeAq3lNUdC6YcDbw1nDcF7cfpAy" alt="FileTransferApp Shared Files Tab" width="600"/>
</p>

A desktop application built with Python and Tkinter/ttk for easy local network file sharing and receiving, featuring a web interface for clients.

**Project Status:** First Release

**Author:** [KPR-MAN](https://github.com/KPR-MAN)

**License:** [The Unlicense](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Code Highlights](#code-highlights)
- [Performance Note](#performance-note)
- [Prerequisites](#prerequisites)
- [Setup and Installation](#setup-and-installation)
- [Usage](#usage)
  - [Sharing Files](#sharing-files)
  - [Receiving Files (Approving Uploads)](#receiving-files-approving-uploads)
  - [Web Interface](#web-interface)
  - [Settings](#settings)
  - [Logs](#logs)
- [Key Files](#key-files)
- [To-Do / Potential Enhancements](#to-do--potential-enhancements)
- [Contributing](#contributing)

## Overview

FileTransferApp provides a user-friendly graphical interface (built with Tkinter) to simplify sharing files over your local network. It starts an HTTP server, allowing other devices on the network to access a web page where they can download shared files or upload files to the host machine. Designed to make local file transfers more straightforward, uploaded files require approval from the desktop application before being saved to their final destination.

## Features

*   **Desktop GUI:** Easy-to-use interface built with Tkinter and ttk for managing shared files and server status.
*   **Local HTTP Server:** Shares files via a built-in web server.
*   **Web Interface (`file_transfer.html`):**
    *   Lists available files for download.
    *   Allows users to download shared files.
    *   Provides an interface for uploading files to the host.
    *   Includes upload progress bar and status messages.
*   **File Sharing Management (GUI):**
    *   Add individual files or entire folders (recursively) to the shared list.
    *   Remove files from the shared list.
    *   Clear all shared files.
    *   Context menu for shared files (Open containing folder, Copy path, Remove).
    *   Sortable file list.
*   **Upload Approval System:**
    *   Uploaded files are first saved to a temporary directory.
    *   The desktop GUI lists pending uploads in a dedicated "Pending Receives" tab.
    *   Users can accept (move to final destination) or reject (delete temporary file) pending uploads.
    *   Context menu for pending uploads (Accept, Reject, Reject All).
*   **Configurable Settings:**
    *   Set the directory for saving accepted uploads.
    *   Customize application appearance:
        *   Theme selection (supports standard ttk themes and `ttkthemes` if installed).
        *   Font family and size.
    *   Settings are saved to `settings.json`.
*   **Logging:**
    *   Comprehensive logging of application events and server activity.
    *   Logs displayed in a dedicated "Logs" tab in the GUI.
    *   Log level configurable at runtime (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    *   Logs also saved to `file_transfer_app.log`.
    *   Stderr redirection to `app_stderr.log` for GUI-only execution scenarios (e.g., when using `.pyw` on Windows).
*   **Cross-Platform (Designed for):** Works on Windows, macOS, and Linux (with Tkinter support).
*   **Optional Dependencies:** Gracefully handles missing `Pillow` (for PNG icons) and `ttkthemes`.
*   **Automatic IP Detection:** Attempts to find a suitable local IP address for the server URL.
*   **Placeholder HTML:** Generates a functional `file_transfer.html` if it's missing, allowing immediate use of the web UI.
*   **Background Operations:** Uses threading for server operations, folder scanning, and background commands to keep the GUI responsive.

## Screenshots

<table>
  <tr>
    <td align="center"><b>Shared Files Tab (Desktop App)</b></td>
    <td align="center"><b>Pending Receives Tab (Desktop App)</b></td>
  </tr>
  <tr>
    <td><img src="https://drive.google.com/uc?export=view&id=1n2P0hfeAq3lNUdC6YcDbw1nDcF7cfpAy" alt="FileTransferApp Shared Files Tab" width="400"/></td>
    <td><img src="https://drive.google.com/uc?export=view&id=1YoZfVy4YQUwRwbi8xi57OQQmD8tj5EKB" alt="FileTransferApp Pending Receives Tab" width="400"/></td>
  </tr>
  <tr>
    <td align="center"><b>Settings Tab (Desktop App)</b></td>
    <td align="center"><b>Logs Tab (Desktop App)</b></td>
  </tr>
  <tr>
    <td><img src="https://drive.google.com/uc?export=view&id=13l2fwro_HJptvS9vlPJY5PuQUvgc0LRO" alt="FileTransferApp Settings Tab" width="400"/></td>
    <td><img src="https://drive.google.com/uc?export=view&id=10csZWUgn3jFE31HXpK4P9zay1Z3jABLT" alt="FileTransferApp Logs Tab" width="400"/></td>
  </tr>
  <tr>
    <td align="center" colspan="2"><b>Web Interface (Client Browser View)</b></td>
  </tr>
  <tr>
    <td align="center" colspan="2"><img src="https://drive.google.com/uc?export=view&id=1lw7GjRVuZCJRRhf7YN5oryk8CPZdQN9r" alt="FileTransferApp Web Interface" width="600"/></td>
  </tr>
</table>

## Code Highlights

This project demonstrates several good coding practices:

*   **Modularity:** Clear separation between the GUI (`FileTransferApp`), HTTP request handling (`FileTransferHandler`), and the HTTP server (`FileTransferHTTPServer`).
*   **Robust Error Handling:** Extensive use of `try-except` blocks to manage potential runtime errors gracefully.
*   **Comprehensive Logging:** Effective use of the `logging` module for debugging and monitoring.
*   **Thread Safety for GUI:** Utilizes a `queue.Queue` (`gui_queue`) for safe Tkinter GUI updates from background threads.
*   **Graceful Handling of Optional Features:** Checks for libraries like `Pillow` and `ttkthemes` and adjusts functionality accordingly.
*   **Persistent Configuration:** User preferences are saved to `settings.json` with sensible defaults.
*   **User-Centric Design:** Code structured to support an intuitive tabbed interface, context menus, and clear status indicators for both desktop and web users.
*   **Secure by Default (Basic):** Uploaded files are sandboxed in a temporary directory requiring manual approval.
*   **Modern Python Features:** Uses type hints, f-strings, and context managers.
*   **Graceful Shutdown:** Implements an `on_close` handler to stop the server and clean up temporary files.

## Performance Note

Please be aware that the choice of **GUI theme** (especially some complex themes from the optional `ttkthemes` library) can impact the application's UI responsiveness. Simpler themes tend to be lighter. This does **not** affect network file transfer speeds, only the performance of the desktop GUI itself.

## Prerequisites

*   Python 3.7+
*   Tkinter/ttk (usually included with standard Python installations)

**Optional Libraries (for enhanced features):**

*   **Pillow:** For wider image format support for the application icon (e.g., PNG).
    ```bash
    pip install Pillow
    ```
*   **ttkthemes:** For additional GUI themes.
    ```bash
    pip install ttkthemes
    ```

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/KPR-MAN/FileTransferApp.git
    cd FileTransferApp
    ```
    (All necessary files, including `main.pyw` and `file_transfer.html`, should be in this directory).

2.  **(Optional but Recommended) Install dependencies for enhanced features:**
    ```bash
    pip install Pillow ttkthemes
    ```

3.  **Run the application:**
    ```bash
    python main.pyw
    ```
    On Windows, you can often also double-click `main.pyw` to run it without a console window. On other systems, `python main.pyw` or `python3 main.pyw` should work.

    *   Upon first run, if `file_transfer.html` is not present, a basic placeholder HTML file will be created.
    *   Icon files (`icon.ico`, `icon.png`, `icon.gif`) should be placed in the same directory for a custom application icon.

## Usage

### Sharing Files

1.  Launch the application (`main.pyw`).
2.  Navigate to the **"Shared Files"** tab.
3.  Click **"Add Files"** to select individual files or **"Add Folder"** to share all files within a selected folder (and its subfolders).
4.  The selected files will appear in the list.
5.  Click **"Start Server"**. The status will change to "Running", and a local URL (e.g., `http://192.168.1.10:8080`) will be displayed.

### Receiving Files (Approving Uploads)

1.  When a user uploads a file via the web interface, it will appear in the **"Pending Receives"** tab of the desktop application.
2.  The list shows the filename, size, and time of receipt.
3.  Right-click on an item in the list to:
    *   **Accept Upload:** Moves the file to your configured "Accepted receives Directory".
    *   **Reject Upload:** Deletes the temporary file.
    *   **Reject All:** Rejects all currently pending uploads.
4.  The "Pending Receives" tab text will indicate new uploads (e.g., `* Pending Receives *`) if the tab is not currently active.

### Web Interface

1.  Once the server is started in the desktop application, other devices on the same local network can access the displayed URL (e.g., `http://<your-ip>:<port>`) in a web browser. This will load `file_transfer.html`.
2.  **Downloading:** The web page lists all files shared by the host. Click the "Download" button next to a file.
3.  **Uploading:** Use the "Upload File" section on the web page to select a file and upload it to the host. The upload will then appear in the host's "Pending Receives" tab for approval.

### Settings

Navigate to the **"Settings"** tab in the desktop application to configure:

*   **Accepted receives Directory:** The folder where files are saved after you accept them.
*   **Appearance:**
    *   **Theme:** Choose a visual theme for the application.
    *   **Font:** Select the font family and size for the GUI.
*   Click **"Save and Apply Settings"** to persist your changes.

### Logs

The **"Logs"** tab displays real-time application activity, server requests, errors, and other informational messages.

*   **Log Level:** Change the verbosity of the logs using the "Log Level" dropdown.
*   **Clear Logs:** Clears the log display in the GUI (does not affect the log file content already written).

## Key Files

*   `main.pyw`: The main Python script for the application.
*   `file_transfer.html`: The HTML file served to clients for the web interface. A basic version is auto-generated if missing. Users can customize this file.
*   `settings.json`: Stores user-configured settings (created after first save).
*   `file_transfer_app.log`: Main application log file.
*   `app_stderr.log`: Stores standard error output, especially when running without a console (e.g., with `main.pyw` on Windows).
*   `icon.ico`, `icon.png`, `icon.gif` (optional): Application icon files placed in the script directory.
*   `temp_receives/` (directory): Created by the application at runtime to store incoming uploads temporarily before approval. Cleaned on exit.

## To-Do / Potential Enhancements

*   [ ] Implement WebSocket support for real-time updates in the web UI.
*   [ ] More advanced user/access control for the web interface.
*   [ ] Option to set a password for accessing the web interface.
*   [ ] Bandwidth limiting options.
*   [ ] Progress display for downloads in the web UI.
*   [ ] Option to configure the server port directly in the GUI settings.
*   [ ] Drag-and-drop support for adding files to the shared list in the GUI.
*   [ ] Packaging for easier distribution (e.g., using PyInstaller).

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1.  Fork the repository (`https://github.com/KPR-MAN/FileTransferApp/fork`).
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Make your changes.
4.  Commit your changes (`git commit -am 'Add some feature'`).
5.  Push to the branch (`git push origin feature/your-feature-name`).
6.  Create a new Pull Request.

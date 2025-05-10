# File Transfer App

A desktop application for easy file sharing and transfer across your local network, built with Python and Tkinter.

![FileTransferApp Main Interface](https://drive.google.com/uc?export=view&id=1n2P0hfeAq3lNUdC6YcDbw1nDcF7cfpAy)

## Features

- **Easy File Sharing**: Share files instantly across your local network
- **Web Interface**: Access shared files through any web browser
- **Upload Management**: Review and approve incoming file uploads
- **Real-time Logging**: Monitor all file transfer activities
- **Customizable Settings**: Configure download locations and preferences
- **Cross-Platform**: Works on Windows and Linux

## Screenshots

### Desktop Application

<table>
  <tr>
    <td align="center"><b>Shared Files Tab</b></td>
    <td align="center"><b>Pending Receives Tab</b></td>
  </tr>
  <tr>
    <td><img src="https://drive.google.com/uc?export=view&id=1n2P0hfeAq3lNUdC6YcDbw1nDcF7cfpAy" alt="FileTransferApp Shared Files Tab" width="400"/></td>
    <td><img src="https://drive.google.com/uc?export=view&id=1YoZfVy4YQUwRwbi8xi57OQQmD8tj5EKB" alt="FileTransferApp Pending Receives Tab" width="400"/></td>
  </tr>
  <tr>
    <td align="center"><b>Settings Tab</b></td>
    <td align="center"><b>Logs Tab</b></td>
  </tr>
  <tr>
    <td><img src="https://drive.google.com/uc?export=view&id=13l2fwro_HJptvS9vlPJY5PuQUvgc0LRO" alt="FileTransferApp Settings Tab" width="400"/></td>
    <td><img src="https://drive.google.com/uc?export=view&id=10csZWUgn3jFE31HXpK4P9zay1Z3jABLT" alt="FileTransferApp Logs Tab" width="400"/></td>
  </tr>
</table>

### Web Interface

![Web Interface](https://drive.google.com/uc?export=view&id=1lw7GjRVuZCJRRhf7YN5oryk8CPZdQN9r)

## Technical Features

- **Built with Python & Tkinter**: Native GUI application with cross-platform compatibility
- **HTTP Server**: Built-in web server for browser-based file access
- **File Management**:
  - Drag & drop file sharing
  - Multiple file selection
  - Folder sharing with recursive scanning
  - Upload approval system
- **Security**:
  - Upload verification
  - Temporary file handling
  - Safe file path handling
- **Logging System**:
  - Detailed activity logging
  - Configurable log levels
  - Log rotation
- **Error Handling**:
  - Robust error recovery
  - User-friendly error messages
  - Detailed debug logging

## Requirements

- Python 3.6 or higher
- Required Python packages:
  ```
  tkinter (usually comes with Python)
  Pillow (optional, for PNG icon support)
  ```

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/file-transfer-app.git
   cd file-transfer-app
   ```

2. **Install dependencies** (if Pillow is needed for PNG support)
   ```bash
   pip install Pillow
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

## Usage

1. **Starting the Application**
   - Launch the application
   - Click "Start Server" to begin sharing
   - The application will display your local IP address

2. **Sharing Files**
   - Use "Add Files" or "Add Folder" to share content
   - Files appear in the "Shared Files" tab
   - Right-click files for additional options

3. **Accessing Files**
   - Open the displayed URL in any web browser
   - Download shared files directly
   - Upload files through the web interface

4. **Managing Uploads**
   - Review incoming uploads in "Pending Receives"
   - Accept or reject uploads
   - Configure save location in Settings

5. **Monitoring Activity**
   - Check the "Logs" tab for activity history
   - Adjust log level in settings
   - Clear logs as needed

## Configuration

The application creates a `settings.json` file with configurable options:

```json
{
    "download_dir": "path/to/downloads"
}
```

## Development

### Project Structure

```
file-transfer-app/
├── main.py              # Main application entry point
├── icon.ico            # Application icon
├── file_transfer.html  # Web interface template
└── logs/              # Application logs directory
```

### Key Components

- **HTTP Server**: Custom implementation using `http.server`
- **File Handler**: Manages file operations and temporary storage
- **GUI**: Tkinter-based interface with multiple tabs
- **Settings Manager**: JSON-based configuration system
- **Logger**: Custom logging implementation

## Building

For Windows users, you can create a standalone executable:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico main.py
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors and users of the application
- Icon and design elements from various open-source projects

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## Roadmap

- [ ] Add file encryption support
- [ ] Implement user authentication
- [ ] Add file preview capabilities
- [ ] Support for direct peer-to-peer transfers
- [ ] Mobile app companion

## Notes

- The application creates temporary files during uploads
- Logs are stored in the user's application data directory
- Server runs on port 8080 by default

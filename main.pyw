# --- Imports ---
import sys
import os
import json
import socket
import tkinter as tk
from tkinter import ttk, filedialog, font, messagebox
import threading
import subprocess
import http.server
import socketserver
import urllib.parse
import shutil
import uuid
import webbrowser
import logging
from datetime import datetime
import mimetypes
from queue import Queue, Empty as QueueEmpty
import math
import cgi  # For robust form parsing
from typing import Optional, Dict, Any, List, Tuple, Callable

# --- Optional Imports ---
try:
    from PIL import Image, ImageTk
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    from ttkthemes import ThemedTk
    TTKTHEMES_AVAILABLE = True
except ImportError:
    ThemedTk = None # type: ignore # Make linters happy if not available
    TTKTHEMES_AVAILABLE = False

# --- Define SCRIPT_DIR early ---
try:
    # If running as a script, __file__ is defined
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    # Fallback for interactive interpreters or frozen environments
    SCRIPT_DIR = os.path.abspath(os.getcwd())

# --- Redirect stderr if running without console ---
_has_console = hasattr(sys.stdout, 'fileno') and sys.stdout.isatty() # More reliable check
_stderr_log_file = None
if '--force-log-stderr' not in sys.argv and (not _has_console or sys.platform == 'win32' and 'pythonw.exe' in sys.executable.lower()):
    try:
        error_log_path = os.path.join(SCRIPT_DIR, "app_stderr.log")
        _stderr_log_file = open(error_log_path, "w", encoding="utf-8", buffering=1)
        sys.stderr = _stderr_log_file
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Standard error redirected to: {error_log_path}", file=sys.stderr)
    except Exception as e:
        # Use original stderr if redirection fails
        print(f"ERROR: Failed to redirect stderr to {error_log_path}: {e}", file=sys.__stderr__)

# --- Configure Logging (AFTER potential stderr redirection) ---
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] - %(message)s')
log_level = logging.DEBUG # Default to DEBUG, can be changed via GUI
log_file_path = os.path.join(SCRIPT_DIR, "file_transfer_app.log")
log_handlers: List[logging.Handler] = []

try:
    # Use RotatingFileHandler for larger logs
    # from logging.handlers import RotatingFileHandler
    # file_handler = RotatingFileHandler(log_file_path, maxBytes=5*1024*1024, backupCount=2, encoding='utf-8') # 5MB limit, 2 backups
    # Using simple FileHandler for now:
    file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8') # 'w' overwrites on start
    file_handler.setFormatter(log_formatter)
    log_handlers.append(file_handler)
except Exception as e:
    print(f"ERROR: Could not configure file logging handler: {e}", file=sys.stderr)

if _has_console:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    log_handlers.append(console_handler)

# Configure root logger
logging.basicConfig(level=log_level, handlers=log_handlers)
# Silence overly verbose libraries if needed
# logging.getLogger("PIL").setLevel(logging.WARNING)

logger = logging.getLogger(__name__) # Get logger for this module

# --- Log Initial State ---
logger.info("--- Application Starting ---")
logger.info(f"Python Version: {sys.version.split()[0]}")
logger.info(f"Platform: {sys.platform}")
logger.info(f"Executable: {sys.executable}")
logger.info(f"Script Directory: {SCRIPT_DIR}")
logger.info(f"Working Directory: {os.getcwd()}")
logger.info(f"Arguments: {sys.argv}")
logger.info(f"Console Detected: {_has_console}")
if not PILLOW_AVAILABLE: logger.warning("Pillow library not found. PNG icon support disabled.")
if not TTKTHEMES_AVAILABLE: logger.warning("ttkthemes library not found. Custom themes disabled.")

# --- Constants ---
HTML_FILE_NAME = "file_transfer.html"
HTML_FILE_PATH = os.path.join(SCRIPT_DIR, HTML_FILE_NAME)
DEFAULT_PORT = 8080
SETTINGS_FILE_NAME = "settings.json"
SETTINGS_FILE_PATH = os.path.join(SCRIPT_DIR, SETTINGS_FILE_NAME)
DEFAULT_SETTINGS = {
    # This now controls where ACCEPTED receives are saved.
    "download_dir": os.path.join(os.path.expanduser("~"), "Downloads", "FileTransferAppReceives"),
    "font_family": "Segoe UI" if sys.platform == "win32" else "TkDefaultFont",
    "font_size": 10,
    "theme": "adapta" if TTKTHEMES_AVAILABLE else ("clam" if sys.platform != "darwin" else "aqua")
}
TEMP_DIR_NAME = "temp_receives"
TEMP_DIR = os.path.join(SCRIPT_DIR, TEMP_DIR_NAME)


# --- Global State ---
files_to_serve: Dict[int, Dict[str, Any]] = {}  # Files available for download {file_id: info}
next_file_id = 1 # Simple counter for download IDs
pending_uploads: Dict[str, Dict[str, Any]] = {}  # {tree_item_id: upload_info} - Files awaiting approval
gui_queue: Queue[Callable[[], None]] = Queue()  # Queue for thread-safe GUI updates

# --- Ensure Temporary Upload Directory Exists ---
# The target directory for accepted uploads (from settings) is checked/created later.
try:
    os.makedirs(TEMP_DIR, exist_ok=True)
    logger.info(f"Temporary upload directory ensured: {TEMP_DIR}")
except OSError as e:
    logger.critical(f"Could not create temporary upload directory {TEMP_DIR}: {e}", exc_info=True)
    # Attempt GUI error message if possible, even if main app fails later
    try:
        root_err = tk.Tk();
        root_err.withdraw() # Hide the dummy window
        messagebox.showerror("Fatal Startup Error",
                             f"Could not create temporary directory:\n{TEMP_DIR}\n\nApplication cannot continue.\nError: {e}",
                             parent=None) # No parent yet
        root_err.destroy()
    except Exception as tk_err:
        logger.error(f"Could not display startup error messagebox: {tk_err}")
    sys.exit(1) # Cannot continue without temp dir


# ----------------------------------------
# --- Helper Function for Background Commands ---
# ----------------------------------------
def run_command_background_silent(command_list: List[str]):
    """Executes a command list in a background thread without showing a console window."""
    thread = threading.Thread(target=_execute_command, args=(command_list,), daemon=True, name=f"Cmd-{os.path.basename(command_list[0])}")
    thread.start()

def _execute_command(command_list: List[str]):
    """Internal function to execute the command."""
    try:
        command_str = subprocess.list2cmdline(command_list) # Safer way to represent command
        logger.debug(f"Executing background command: {command_str}")
        startupinfo = None
        creationflags = 0
        # Prevent console window pop-up on Windows
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            # CREATE_NO_WINDOW is more aggressive but might break some commands
            # creationflags = subprocess.CREATE_NO_WINDOW

        # Use context manager for process handling
        with subprocess.Popen(
            command_list, startupinfo=startupinfo, creationflags=creationflags,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding='utf-8', errors='replace' # Best effort decoding
        ) as process:
            stdout, stderr = process.communicate() # Wait for command to finish
            if process.returncode != 0:
                logger.error(f"Command failed (Code: {process.returncode}): {command_str}\nStderr: {stderr.strip()}")
            else:
                logger.debug(f"Command successful: {command_str}")
                # Optional stdout logging:
                # if stdout.strip(): logger.debug(f"Stdout: {stdout.strip()}")
    except FileNotFoundError:
        logger.error(f"Command not found: {command_list[0]}", exc_info=False) # Don't need full traceback
    except Exception:
        logger.exception(f"Unexpected error executing command: {subprocess.list2cmdline(command_list)}")


# ----------------------------------------
# --- Utility Function ---
# ----------------------------------------
def format_file_size(size_bytes: Optional[float]) -> str:
    """Format file size in bytes to a human-readable format using math."""
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
        return "Invalid size"
    if size_bytes == 0:
        return "0 B"
    try:
        # Using standard base-1024 units
        size_name = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB")
        if size_bytes < 1: # Handle fractional bytes? (Unlikely for file sizes)
             return f"{size_bytes:.2f} B"

        # Calculate the index 'i' for the unit name
        # Use max(0, ...) to handle potential log(small_number) issues if size_bytes < 1
        i = int(math.floor(math.log(max(1, size_bytes), 1024)))

        # Prevent index out of bounds if size is extremely large
        i = min(i, len(size_name) - 1)

        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"
    except ValueError: # Catch math domain error (e.g., log of negative number)
        logger.error(f"Math domain error formatting file size: {size_bytes}")
        return "Error"
    except Exception:
        logger.exception(f"Error formatting file size: {size_bytes}")
        return "Error"

# ----------------------------------------
# --- Server Handler ---
# ----------------------------------------
class FileTransferHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler for file transfer operations."""
    # Class variable to hold reference to the main application instance
    app_instance: Optional['FileTransferApp'] = None
    # Disable default directory listing provided by SimpleHTTPRequestHandler
    directory = None

    # Override __init__ only if necessary, super() call is usually sufficient
    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)

    # --- Safe Error Sending Helper ---
    def _safe_send_error(self, code: int, message: Optional[str] = None):
        """Send error only if headers not already sent."""
        # hasattr check is safer than relying on _headers_buffer existence
        if not self.wfile.closed and not getattr(self, 'headers_sent', False):
            try:
                self.send_error(code, message)
                self.headers_sent = True # Mark headers as sent
            except Exception as e_resp:
                logger.error(f"Could not send {code} error response: {e_resp}")
        else:
             logger.warning(f"Cannot send HTTP error {code} - headers already sent or connection closed.")

    def do_GET(self):
        """Handle GET requests (Serving UI, file list, downloads)."""
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            query = parsed_path.query
            logger.debug(f"GET request received for path: {path} (Query: {query}) from {self.client_address}")

            if path == '/':
                self.serve_html_template()
            elif path == '/available-files':
                self.serve_available_files()
            elif path.startswith('/download/'):
                self.process_download_request(path)
            else:
                logger.warning(f"GET request for unknown path: {path} from {self.client_address}")
                self._safe_send_error(404, "Resource not found")
        except ConnectionResetError:
            logger.warning(f"GET ConnectionResetError from client {self.client_address}")
        except BrokenPipeError:
            logger.warning(f"GET BrokenPipeError (client likely closed connection): {self.client_address}")
        except TimeoutError:
             logger.warning(f"GET TimeoutError from client {self.client_address}")
        except Exception:
            logger.exception(f"Unhandled exception processing GET request for {self.path} from {self.client_address}")
            self._safe_send_error(500, "Internal Server Error")

    def do_POST(self):
        """Handle POST requests (Uploads)."""
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            logger.debug(f"POST request received for path: {path} from {self.client_address}")

            if path == '/upload':
                self.handle_file_upload() # Upload goes to temp for approval
            else:
                logger.warning(f"POST request for unknown path: {path} from {self.client_address}")
                self._safe_send_error(404, "Endpoint not found")
        except ConnectionResetError:
            logger.warning(f"POST ConnectionResetError from client {self.client_address}")
        except BrokenPipeError:
            logger.warning(f"POST BrokenPipeError (client likely closed connection): {self.client_address}")
        except TimeoutError:
             logger.warning(f"POST TimeoutError from client {self.client_address}")
        except Exception:
            logger.exception(f"Unhandled exception processing POST request for {self.path} from {self.client_address}")
            self._safe_send_error(500, "Internal Server Error")

    def serve_html_template(self):
        """Serve the HTML template file."""
        logger.debug(f"Attempting to serve HTML from: {HTML_FILE_PATH}")
        if not os.path.exists(HTML_FILE_PATH):
            logger.error(f"HTML template not found at path: {HTML_FILE_PATH}")
            self._safe_send_error(404, "HTML template file not found on server")
            return
        try:
            with open(HTML_FILE_PATH, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            # Prevent caching of the main page
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            self.wfile.write(content)
            logger.debug(f"Successfully served HTML template to {self.client_address}.")
        except FileNotFoundError:
            logger.error(f"HTML template disappeared before serving (race condition?): {HTML_FILE_PATH}")
            self._safe_send_error(404, "HTML template file not found")
        except IOError as e:
            logger.error(f"IOError serving HTML: {e}")
            self._safe_send_error(500, "Server error reading HTML file")
        except Exception:
            logger.exception("Unexpected error serving HTML template:")
            self._safe_send_error(500, "Internal server error serving HTML")

    def serve_available_files(self):
        """Serve the list of available files (files_to_serve) as JSON."""
        global files_to_serve # Access the global dictionary
        files_json = []
        # Create a stable copy for iteration in case dict changes during processing
        current_files = list(files_to_serve.items())
        for file_id, file_info in current_files:
            try:
                # Ensure necessary keys exist, provide defaults if not
                files_json.append({
                    "id": file_id,
                    "name": file_info.get("name", "Unknown Filename"),
                    "size": format_file_size(file_info.get("size")), # Use formatter
                    "size_bytes": file_info.get("size", 0), # Include raw bytes
                })
            except Exception as e:
                logger.error(f"Error processing file info for ID {file_id} ('{file_info.get('name', '?')}'): {e}")
                # Optionally skip this file or add an error entry
        try:
            json_output = json.dumps(files_json).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(json_output)))
            # Prevent caching of the dynamic file list
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            self.wfile.write(json_output)
            logger.debug(f"Served available files list ({len(files_json)} items) to {self.client_address}.")
        except Exception:
            logger.exception("Error sending available files JSON response:")
            # Don't use _safe_send_error here if response already started
            if not getattr(self, 'headers_sent', False):
                 self._safe_send_error(500, "Error preparing file list")

    def process_download_request(self, path: str):
        """Extract file ID and serve the download from files_to_serve."""
        try:
            # Example path: /download/123
            parts = path.strip('/').split('/')
            if len(parts) != 2 or parts[0] != 'download':
                raise ValueError("Invalid download path format")
            file_id = int(parts[1]) # Convert ID part to integer
            self.serve_file_download(file_id)
        except (ValueError, IndexError):
            logger.warning(f"Invalid file ID format in download path: {path} from {self.client_address}")
            self._safe_send_error(404, "Invalid or missing file ID")
        except Exception:
            logger.exception(f"Error processing download path: {path} from {self.client_address}")
            self._safe_send_error(500, "Error processing download request")

    def serve_file_download(self, file_id: int):
        """Serve a specific file for download (from files_to_serve)."""
        logger.debug(f"Attempting to serve download for file ID: {file_id} to {self.client_address}")
        global files_to_serve # Access global

        file_info = files_to_serve.get(file_id)

        if not file_info:
            logger.warning(f"Download requested for invalid or removed file ID: {file_id} from {self.client_address}")
            self._safe_send_error(404, "File ID not found or file removed")
            return

        file_path = file_info.get("path")
        file_name = file_info.get("name", f"download_{file_id}") # Default name if missing

        # Combine checks for path validity
        if not file_path or not isinstance(file_path, str) or not os.path.isfile(file_path):
            logger.error(f"File path is invalid, missing, or not a file for ID {file_id} ('{file_name}'). Path: '{file_path}'")
            # Automatically remove this invalid entry from the list
            if self.app_instance and hasattr(self.app_instance, 'remove_file_by_id_threadsafe'):
                self.app_instance.remove_file_by_id_threadsafe(file_id)
            self._safe_send_error(404, "File not found on server disk (invalid entry removed)")
            return

        # Log download start using the app's threadsafe logger
        log_msg_start = f"Download started: '{file_name}' (ID: {file_id}) by {self.client_address}"
        if self.app_instance and hasattr(self.app_instance, 'log_threadsafe'):
            self.app_instance.log_threadsafe(log_msg_start, level="info")
        else:
            logger.info(log_msg_start) # Fallback if app instance not available

        try:
            file_size = os.path.getsize(file_path)
            # Guess MIME type
            content_type, encoding = mimetypes.guess_type(file_path)
            content_type = content_type or 'application/octet-stream' # Default if unknown

            self.send_response(200)
            self.send_header('Content-Type', content_type)
            if encoding: # e.g., gzip
                self.send_header('Content-Encoding', encoding)
            self.send_header('Content-Length', str(file_size))

            # --- Content-Disposition for correct filename handling ---
            # RFC 6266: Use both filename and filename* for compatibility
            try:
                # Simple ASCII/Latin-1 compatible filename
                ascii_name = file_name.encode('ascii', 'ignore').decode('ascii')
                # Sanitize slightly for header value (though quotes handle most things)
                safe_ascii_name = ascii_name.replace('"', "'")
                header_val = f'attachment; filename="{safe_ascii_name}"'

                # Add UTF-8 version if needed (contains non-ASCII)
                if ascii_name != file_name:
                    utf8_name_encoded = urllib.parse.quote(file_name, safe='')
                    header_val += f"; filename*=UTF-8''{utf8_name_encoded}"

                self.send_header('Content-Disposition', header_val)
            except Exception as e_disp:
                logger.error(f"Error creating Content-Disposition header for '{file_name}': {e_disp}")
                # Fallback to simple disposition if encoding fails
                self.send_header('Content-Disposition', 'attachment')
            # ---------------------------------------------------------

            self.send_header('X-Content-Type-Options', 'nosniff') # Security header
            self.end_headers()
            self.headers_sent = True # Mark headers as sent

            # Send file content efficiently
            with open(file_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile, length=1024*1024) # Use a buffer

            log_msg_end = f"Download completed: '{file_name}' (ID: {file_id}, Size: {format_file_size(file_size)}) by {self.client_address}"
            if self.app_instance and hasattr(self.app_instance, 'log_threadsafe'):
                 self.app_instance.log_threadsafe(log_msg_end, level="info")
            else:
                 logger.info(log_msg_end)

        except FileNotFoundError:
            logger.warning(f"File disappeared before sending could complete: {file_path} (ID: {file_id})")
            # Don't try sending error if headers already sent, just close
            if not getattr(self, 'headers_sent', False):
                self._safe_send_error(404, "File disappeared during transfer")
            else:
                self.wfile.close() # Close the connection abruptly
        except BrokenPipeError:
            logger.warning(f"Client {self.client_address} disconnected during download of '{file_name}' (ID: {file_id}).")
            # No response possible here
        except ConnectionResetError:
            logger.warning(f"Connection reset by client {self.client_address} during download of '{file_name}' (ID: {file_id}).")
            # No response possible here
        except TimeoutError:
            logger.warning(f"Timeout during download of '{file_name}' (ID: {file_id}) to client {self.client_address}.")
        except IOError as e:
            logger.error(f"IOError reading file for download '{file_name}' (ID: {file_id}): {e}")
            if not getattr(self, 'headers_sent', False):
                 self._safe_send_error(500, "Server error reading file")
            else:
                 self.wfile.close() # Close connection if error happens mid-stream
        except Exception:
            logger.exception(f"Unexpected error serving file download '{file_name}' (ID: {file_id}):")
            if not getattr(self, 'headers_sent', False):
                self._safe_send_error(500, "Internal server error during download")
            else:
                 self.wfile.close()

    def handle_file_upload(self):
        """
        Handle file upload using cgi module, save to TEMP_DIR,
        and notify the main app to add it to the pending list.
        """
        logger.debug(f"Handling file upload from {self.client_address} (for approval)...")
        temp_file_path = None # Track for potential cleanup on error

        try:
            # --- Use cgi.FieldStorage for robust parsing ---
            # It requires specific environment variables and headers.
            env = {'REQUEST_METHOD': 'POST',
                   'CONTENT_TYPE': self.headers['Content-Type'],
                   'CONTENT_LENGTH': self.headers['Content-Length']}

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ=env,
                keep_blank_values=True # Important for file fields
            )
            # -----------------------------------------

            # Check for the 'file' field
            if 'file' not in form:
                logger.error(f"Upload request from {self.client_address} missing 'file' part in form data.")
                self._safe_send_error(400, 'Bad request: Missing "file" field in upload form')
                return

            file_item = form['file']

            # Check if it's actually a file upload
            if not isinstance(file_item, cgi.FieldStorage) or not file_item.filename:
                logger.error(f"Received 'file' part from {self.client_address} but it's not a file upload or has no filename.")
                self._safe_send_error(400, 'Bad request: "file" field is not a valid file upload')
                return

            # Get original filename and sanitize it
            original_filename = os.path.basename(file_item.filename) # Basic protection
            logger.info(f"Received upload intent from {self.client_address}: '{original_filename}' (for approval)")

            # More robust sanitization (allow spaces, dots, underscores, hyphens)
            safe_filename_base = ''.join(c for c in original_filename if c.isalnum() or c in '._- ')
            if not safe_filename_base: # Handle case where filename becomes empty after sanitizing
                safe_filename_base = "uploaded_file"
            safe_filename = safe_filename_base[:200] # Limit length

            # --- Generate unique temporary path in TEMP_DIR ---
            upload_id = str(uuid.uuid4()) # Unique ID for this upload instance
            # Include unique ID in the temp filename to prevent collisions
            temp_file_path = os.path.join(TEMP_DIR, f"{upload_id}_{safe_filename}")
            # --------------------------------------------------

            logger.debug(f"Saving uploaded file temporarily to: {temp_file_path}")
            bytes_written = 0
            # Write the file content to the temporary location
            try:
                with open(temp_file_path, 'wb') as temp_f:
                    # Use file_item.file which is the file-like object
                    shutil.copyfileobj(file_item.file, temp_f, length=1024*1024) # Use buffer
                bytes_written = os.path.getsize(temp_file_path)
                logger.info(f"Finished writing temp file: '{safe_filename}' ({format_file_size(bytes_written)}) to {temp_file_path}")
            except IOError as e:
                logger.error(f"IOError writing temporary uploaded file {temp_file_path}: {e}")
                self._safe_send_error(500, 'Server error saving temporary file')
                # Cleanup happens in the main exception handler's finally block
                return # Stop processing this request
            except Exception:
                logger.exception(f"Unexpected error writing temporary file {temp_file_path}")
                self._safe_send_error(500, 'Internal server error during temporary save')
                # Cleanup happens in the main exception handler's finally block
                return # Stop processing this request

            # --- Log and queue for GUI PENDING confirmation ---
            if self.app_instance and hasattr(self.app_instance, 'add_pending_upload'):
                log_msg = f"Upload received: '{safe_filename}' ({format_file_size(bytes_written)}) from {self.client_address}. Awaiting approval."
                # Log using the app's threadsafe logger
                self.app_instance.log_threadsafe(log_msg, level="info")

                # Call the method to add to the pending list (will use GUI queue internally)
                # Pass the sanitized filename, temp path, and size
                self.app_instance.add_pending_upload(upload_id, safe_filename, temp_file_path, bytes_written)
            else:
                logger.error("Critical: No app_instance or add_pending_upload method available. Cannot process upload approval.")
                # Clean up the temp file as it cannot be handled by the app
                # Cleanup happens in the main exception handler's finally block
                self._safe_send_error(500, "Server configuration error: Cannot process upload approval.")
                return # Stop here
            # -------------------------------------------------

            # Send success response back to the browser (indicating received for approval)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.headers_sent = True
            self.wfile.write(f"Upload received successfully. Pending approval.".encode('utf-8'))
            logger.debug(f"Sent 'pending approval' response for upload ID {upload_id} ('{safe_filename}') to client {self.client_address}.")

        except Exception as e:
            # Catch-all for errors during cgi parsing or initial checks
            logger.exception("Critical error handling file upload (approval method):")
            # Ensure cleanup of the temporary file if created during the failed attempt
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    logger.debug(f"Cleaned up temporary file during error: {temp_file_path}")
                except OSError as e_rem:
                    logger.error(f"Could not remove temporary file during error handling: {temp_file_path}, Error: {e_rem}")

            # Use _safe_send_error as headers might not have been sent
            self._safe_send_error(500, f'Internal server error during upload processing.')

    # Override send_error to add logging AND use our safe sender
    def send_error(self, code: int, message: Optional[str] = None):
        # Log the error attempt first
        full_message = message or self.responses.get(code, ('Unknown error',))[0]
        try:
            # Try to get more context if available
            request_line = self.requestline
        except AttributeError:
            request_line = "Unknown request"
        logger.error(f"HTTP Server Error: Code={code}, Message='{full_message}', Client={self.client_address}, Request='{request_line}'")
        # Now attempt to send using the original method (which might fail if already sent)
        if not self.wfile.closed and not getattr(self, 'headers_sent', False):
            try:
                 # Call the original SimpleHTTPRequestHandler send_error
                super().send_error(code, message)
                self.headers_sent = True # Mark as sent after successful call
            except Exception as e_send:
                 logger.error(f"Exception calling super().send_error for code {code}: {e_send}")
        else:
            logger.warning(f"Did not attempt to send HTTP error {code} - headers likely already sent or connection closed.")

    # Override log_message to disable default logging to stderr/stdout
    def log_message(self, format_str: str, *args: Any):
        # Example: Log basic access to our logger instead
        # logger.debug(f"HTTP Access ({self.client_address[0]}): " + (format_str % args))
        pass # Completely disable default access logging

    # Override log_error to send errors specifically to our logger
    def log_error(self, format_str: str, *args: Any):
        # This captures internal errors from the http.server module itself
        logger.error(f"Internal HTTP Server Error ({self.client_address[0]}): " + (format_str % args))


# ----------------------------------------
# --- Server Class ---
# ----------------------------------------
class FileTransferHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threading TCP server for handling HTTP requests."""
    allow_reuse_address = True # Allow quick restarts on the same port
    daemon_threads = True # Allow application to exit even if server threads are running

    def __init__(self, server_address: Tuple[str, int], handler_class: type, app_instance: 'FileTransferApp'):
        # Store the app instance reference so the handler class can access it
        self.app_instance = app_instance
        # Make the app instance available to handler instances via a class variable
        # This is done *before* calling super().__init__ which initializes the handler
        handler_class.app_instance = self.app_instance

        # Call the TCPServer constructor
        super().__init__(server_address, handler_class)
        logger.info(f"FileTransferHTTPServer initialized, binding to {server_address}")

    def finish_request(self, request: socket.socket, client_address: Tuple[str, int]):
        """Finish one request by instantiating RequestHandlerClass."""
        logger.debug(f"Incoming connection from {client_address}")
        try:
            # This calls the handler's __init__ method
            self.RequestHandlerClass(request, client_address, self)
        except ConnectionResetError:
            # Common if client disconnects during handshake
            logger.warning(f"Connection reset by peer during request setup: {client_address}")
        except BrokenPipeError:
            # Common if client disconnects early
            logger.warning(f"Broken pipe during request setup (client disconnected): {client_address}")
        except TimeoutError:
             logger.warning(f"Timeout during request setup from {client_address}")
        except Exception:
            # Catch potential errors within the handler's __init__ itself
            logger.exception(f"Exception during handler initialization for {client_address}")

    def handle_error(self, request: socket.socket, client_address: Tuple[str, int]):
        """Handle an error gracefully. Called when handle() raises an exception."""
        # This method is called if an exception propagates up from the handler's handle() method
        # (or do_GET/do_POST if handle() isn't overridden).
        # We already log exceptions within do_GET/do_POST, so this might be redundant,
        # but can catch errors happening outside those specific methods within the handler.
        logger.exception(f"Unhandled exception processing request from {client_address}")
        # Optionally, try to close the connection cleanly
        # try:
        #     request.shutdown(socket.SHUT_RDWR)
        #     request.close()
        # except Exception:
        #     pass # Ignore errors during cleanup


# ----------------------------------------
# --- Main Application Class ---
# ----------------------------------------
class FileTransferApp:
    """Main application class for the File Transfer GUI."""

    def __init__(self, root: tk.Tk):
        """Initialize the application."""
        self.root = root
        self.style = ttk.Style()
        self.server: Optional[FileTransferHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_server_running = False
        self.port = DEFAULT_PORT # Can be made configurable later
        self.local_ip = self.get_local_ip() # Get best guess local IP

        # State for pending receives: {tree_item_id: upload_info_dict}
        self.pending_uploads: Dict[str, Dict[str, Any]] = {}
        # Mapping shared tree item IDs (GUI) to internal file_ids (data)
        # {tree_item_gui_id: file_data_id}
        self.tree_items: Dict[str, int] = {}
        # Sorting state for the shared files treeview
        self._files_sort_column = "Name"
        self._files_sort_reverse = False

        logger.debug("Loading settings...")
        self.settings = self.load_settings()

        logger.debug("Initializing GUI...")
        # Basic GUI setup needs to happen before applying theme/font from settings
        self.root.title("File Transfer App")
        self.root.geometry("850x650") # Initial size, might be adjusted by content
        self.center_window()

        # Configure root window close behavior *early*
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Initialize GUI components (placeholders for widgets are created here)
        self.init_gui() # Builds the notebook, tabs, and widgets

        logger.debug("Applying theme and font from settings...")
        self.apply_theme() # Applies loaded settings to GUI elements

        logger.debug("Starting GUI event queue processor...")
        self.process_gui_queue() # Start checking the queue for cross-thread updates

        logger.info("FileTransferApp initialized.")
        # Log messages using the threadsafe method
        self.log_threadsafe("Application ready. Add files and start the server.", level="info")
        self.log_threadsafe(f"Accepted receives will be saved to: {self.settings['download_dir']}", level="info")
        self.log_threadsafe(f"Temporary receives stored in: {TEMP_DIR}", level="debug")

        # Initial refresh of file list (if any were loaded from a persistent state - not implemented here)
        self.refresh_files_tree()

    def init_gui(self):
        """Initialize the main GUI components."""
        # Theme application is handled in apply_theme after settings are loaded
        # The ThemedTk instance handles setting the theme if available.

        # --- Main Structure: Notebook ---
        self.notebook = ttk.Notebook(self.root)

        # Create frames for each tab
        self.main_tab = ttk.Frame(self.notebook, padding="10")
        self.pending_tab = ttk.Frame(self.notebook, padding="10")
        self.logs_tab = ttk.Frame(self.notebook, padding="10")
        self.settings_tab = ttk.Frame(self.notebook, padding="10")

        # Add tabs to the notebook
        self.notebook.add(self.main_tab, text=" Shared Files ")
        self.notebook.add(self.pending_tab, text=" Pending Receives")
        self.notebook.add(self.logs_tab, text=" Logs ")
        self.notebook.add(self.settings_tab, text=" Settings ")

        # Pack the notebook to fill the window
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)

        # --- Setup Individual Tabs ---
        # These methods will populate the frames created above
        self.setup_main_tab()
        self.setup_pending_tab()
        self.setup_logs_tab()
        self.setup_settings_tab()

        # --- Configure Styles (can be done here or in apply_theme) ---
        # Style for the URL label to make it look clickable
        self.style.configure("URL.TLabel", foreground="blue", cursor="hand2")
        # Default font is applied globally in apply_theme, but configure specific styles if needed
        font_fam = self.settings.get("font_family", DEFAULT_SETTINGS["font_family"])
        font_sz = self.settings.get("font_size", DEFAULT_SETTINGS["font_size"])
        default_font = (font_fam, font_sz)
        # Underlined style for URL hover
        self.style.configure("URLHover.TLabel", foreground="purple", font=(font_fam, font_sz, "underline"))
        # Initial status label color
        self.style.configure("Status.TLabel", foreground="red", font=default_font) # Initial state is stopped

        # Bindings for URL hover effect (done after label exists)
        if hasattr(self, 'url_label'):
             self.url_label.bind("<Enter>", lambda e: self.url_label.configure(style="URLHover.TLabel"))
             self.url_label.bind("<Leave>", lambda e: self.url_label.configure(style="URL.TLabel"))


    def center_window(self):
        """Center the application window on the screen."""
        if not self.root: return
        self.root.update_idletasks() # Ensure window dimensions are calculated
        try:
            # Get screen dimensions
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()

            # Get window dimensions
            width = self.root.winfo_width()
            height = self.root.winfo_height()

            # Fallback if dimensions are too small (can happen before fully drawn)
            if width <= 1 or height <= 1:
                try:
                    # Try parsing geometry string "WxH+X+Y"
                    geom = self.root.geometry().split('+')[0] # Get "WxH" part
                    width, height = map(int, geom.split('x'))
                except Exception:
                    logger.warning("Could not parse geometry, using default size for centering.")
                    width, height = 850, 650 # Use the default size

            # Calculate position (ensure non-negative coordinates)
            x = max(0, (screen_width // 2) - (width // 2))
            y = max(0, (screen_height // 2) - (height // 2))

            # Set the geometry
            self.root.geometry(f'{width}x{height}+{x}+{y}')
            logger.debug(f"Centered window to {width}x{height}+{x}+{y}")
        except Exception:
            logger.exception("Error centering window")

    def setup_main_tab(self):
        """Set up the main 'Shared Files' tab interface."""
        # Configure grid weights for resizing
        self.main_tab.columnconfigure(0, weight=1) # Main column expands
        self.main_tab.rowconfigure(1, weight=1) # Files frame row expands

        # --- Server Control Frame ---
        server_frame = ttk.LabelFrame(self.main_tab, text="Server Control", padding="10")
        server_frame.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="ew")
        server_frame.columnconfigure(1, weight=1) # Make status area expand horizontally

        # Frame for buttons on the left
        button_frame = ttk.Frame(server_frame)
        button_frame.grid(row=0, column=0, sticky="w")
        self.toggle_server_button = ttk.Button(button_frame, text="Start Server", command=self.toggle_server, width=15)
        self.toggle_server_button.pack(side=tk.LEFT, padx=(0, 5), pady=5)
        self.open_browser_button = ttk.Button(button_frame, text="Open in Browser", command=self.open_in_browser, state=tk.DISABLED, width=15)
        self.open_browser_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Frame for status labels on the right
        status_frame = ttk.Frame(server_frame)
        status_frame.grid(row=0, column=1, sticky="e") # Align to the right
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, padx=(10, 2), pady=5, sticky="w")
        self.status_label = ttk.Label(status_frame, text="Not running", width=12, anchor="w", style="Status.TLabel")
        self.status_label.grid(row=0, column=1, padx=(0, 10), pady=5, sticky="w")

        ttk.Label(status_frame, text="URL:").grid(row=1, column=0, padx=(10, 2), pady=5, sticky="w")
        self.url_label = ttk.Label(status_frame, text="N/A", cursor="hand2", anchor="w", style="URL.TLabel")
        self.url_label.grid(row=1, column=1, padx=(0, 10), pady=5, sticky="ew")
        self.url_label.bind("<Button-1>", self.open_in_browser) # Click to open
        # Hover bindings are set in init_gui after style is configured

        # --- Shared Files Frame ---
        files_frame = ttk.LabelFrame(self.main_tab, text="Shared Files", padding="10")
        files_frame.grid(row=1, column=0, padx=5, pady=(5, 0), sticky="nsew") # Expand in all directions
        files_frame.columnconfigure(0, weight=1) # Treeview column expands
        files_frame.rowconfigure(1, weight=1) # Treeview row expands

        # Button bar for file actions
        files_buttons_frame = ttk.Frame(files_frame)
        files_buttons_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5)) # Span across tree+scrollbar col
        self.add_files_button = ttk.Button(files_buttons_frame, text="Add Files", command=self.add_files, width=12)
        self.add_files_button.pack(side=tk.LEFT, padx=(0, 5))
        self.add_folder_button = ttk.Button(files_buttons_frame, text="Add Folder", command=self.add_folder, width=12)
        self.add_folder_button.pack(side=tk.LEFT, padx=5)
        self.remove_file_button = ttk.Button(files_buttons_frame, text="Remove Selected", command=self.remove_selected_file, width=15)
        self.remove_file_button.pack(side=tk.LEFT, padx=5)
        self.clear_files_button = ttk.Button(files_buttons_frame, text="Clear All", command=self.clear_files_confirm, width=12)
        self.clear_files_button.pack(side=tk.LEFT, padx=5)

        # Shared Files Treeview Frame (to hold tree and scrollbars)
        tree_frame = ttk.Frame(files_frame)
        tree_frame.grid(row=1, column=0, sticky='nsew')
        tree_frame.rowconfigure(0, weight=1) # Treeview expands vertically
        tree_frame.columnconfigure(0, weight=1) # Treeview expands horizontally

        self.files_tree = ttk.Treeview(tree_frame, columns=("Name", "Size", "Path"), show="headings", selectmode="browse")
        # Headings
        self.files_tree.heading("Name", text="Name", anchor="w", command=lambda: self.sort_files_tree("Name"))
        self.files_tree.heading("Size", text="Size", anchor="e", command=lambda: self.sort_files_tree("Size"))
        self.files_tree.heading("Path", text="Path", anchor="w", command=lambda: self.sort_files_tree("Path"))
        # Columns
        self.files_tree.column("Name", width=250, stretch=tk.YES, anchor="w")
        self.files_tree.column("Size", width=100, stretch=tk.NO, anchor="e") # Fixed size, right align
        self.files_tree.column("Path", width=400, stretch=tk.YES, anchor="w")

        # Scrollbars
        tree_scrollbar_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.files_tree.yview)
        tree_scrollbar_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.files_tree.xview)
        self.files_tree.configure(yscrollcommand=tree_scrollbar_y.set, xscrollcommand=tree_scrollbar_x.set)

        # Layout tree and scrollbars using grid within tree_frame
        self.files_tree.grid(row=0, column=0, sticky='nsew')
        tree_scrollbar_y.grid(row=0, column=1, sticky='ns')
        tree_scrollbar_x.grid(row=1, column=0, sticky='ew')

        # Right-click context menu for Shared Files
        self.files_menu = tk.Menu(self.root, tearoff=0) # Associated with root window
        self.files_menu.add_command(label="Remove From List", command=self.remove_selected_file)
        self.files_menu.add_separator()
        self.files_menu.add_command(label="Open Containing Folder", command=self.open_containing_folder)
        self.files_menu.add_command(label="Copy Path", command=self.copy_selected_path)

        # Bind right-click (Button-3 on Win/Linux, Button-2 or Ctrl+Click on Mac)
        self.files_tree.bind("<Button-3>", self.show_files_menu) # Standard right-click
        # Consider adding Mac specific binding if needed: self.files_tree.bind("<Button-2>", self.show_files_menu)

        # Bind double-click
        self.files_tree.bind("<Double-Button-1>", self.open_containing_folder_event)

    def setup_pending_tab(self):
        """Set up the pending uploads tab."""
        # Configure grid weights
        self.pending_tab.columnconfigure(0, weight=1)
        self.pending_tab.rowconfigure(1, weight=1) # Treeview row expands

        # Instructions label
        instr_label = ttk.Label(self.pending_tab, text="Review incoming receives. Right-click on an item to Accept or Reject.", justify=tk.LEFT, wraplength=600) # Wrap long text
        instr_label.grid(row=0, column=0, pady=(0, 10), sticky="w")

        # Treeview Frame (to hold tree and scrollbars)
        tree_frame = ttk.Frame(self.pending_tab)
        tree_frame.grid(row=1, column=0, sticky='nsew')
        tree_frame.grid_rowconfigure(0, weight=1) # Tree expands vertically
        tree_frame.grid_columnconfigure(0, weight=1) # Tree expands horizontally

        # Pending receives Treeview
        self.pending_tree = ttk.Treeview(tree_frame, columns=("Filename", "Size", "Received"), show="headings", selectmode="browse")
        # Headings (No sorting commands added here, could be added if needed)
        self.pending_tree.heading("Filename", text="Filename", anchor="w")
        self.pending_tree.heading("Size", text="Size", anchor="e")
        self.pending_tree.heading("Received", text="Received", anchor="center")
        # Columns
        self.pending_tree.column("Filename", width=350, stretch=tk.YES, anchor="w")
        self.pending_tree.column("Size", width=120, stretch=tk.NO, anchor="e")
        self.pending_tree.column("Received", width=150, stretch=tk.NO, anchor="center")

        # Scrollbars
        tree_scrollbar_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.pending_tree.yview)
        tree_scrollbar_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.pending_tree.xview)
        self.pending_tree.configure(yscrollcommand=tree_scrollbar_y.set, xscrollcommand=tree_scrollbar_x.set)

        # Layout tree and scrollbars
        self.pending_tree.grid(row=0, column=0, sticky='nsew')
        tree_scrollbar_y.grid(row=0, column=1, sticky='ns')
        tree_scrollbar_x.grid(row=1, column=0, sticky='ew')

        # Right-click context menu for pending receives
        self.pending_menu = tk.Menu(self.root, tearoff=0)
        self.pending_menu.add_command(label="Accept Upload", command=self.accept_selected_upload)
        self.pending_menu.add_command(label="Reject Upload", command=self.reject_selected_upload)
        self.pending_menu.add_separator()
        self.pending_menu.add_command(label="Reject All", command=self.reject_all_uploads_confirm)

        # Bind right-click
        self.pending_tree.bind("<Button-3>", self.show_pending_menu)
        # Optional Mac binding: self.pending_tree.bind("<Button-2>", self.show_pending_menu)

    def setup_logs_tab(self):
        """Set up the logs tab interface."""
        # Configure grid weights
        self.logs_tab.columnconfigure(0, weight=1) # Log text area expands horizontally
        self.logs_tab.rowconfigure(0, weight=1) # Log text area expands vertically

        # Frame for the Text widget and its scrollbar
        text_frame = ttk.Frame(self.logs_tab)
        text_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        # Log display Text widget
        # Use relief="sunken" and bd=1 for a slight border matching other widgets
        self.logs_text = tk.Text(text_frame, wrap="word", height=10, state=tk.DISABLED, relief="sunken", bd=1, undo=False)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.logs_text.yview)
        self.logs_text.configure(yscrollcommand=scrollbar.set)

        # Layout Text and Scrollbar
        self.logs_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Frame for bottom controls (Log Level, Clear button)
        bottom_frame = ttk.Frame(self.logs_tab)
        bottom_frame.grid(row=1, column=0, sticky="ew") # Span horizontally
        # Allow space between label/combo and clear button to expand
        bottom_frame.columnconfigure(1, weight=1)

        # Log Level Controls
        ttk.Label(bottom_frame, text="Log Level:").pack(side=tk.LEFT, padx=(0, 5), pady=5)
        # Ensure logger.level is valid before setting String Var
        current_level_name = logging.getLevelName(logger.level)
        self.log_level_var = tk.StringVar(value=current_level_name)
        log_levels = [logging.getLevelName(lvl) for lvl in sorted([logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL])]
        level_combo = ttk.Combobox(bottom_frame, textvariable=self.log_level_var, values=log_levels, state="readonly", width=10)
        level_combo.pack(side=tk.LEFT, padx=5, pady=5)
        level_combo.bind("<<ComboboxSelected>>", self.change_log_level) # Trigger on selection change

        # Clear Logs Button (aligned right)
        self.clear_logs_button = ttk.Button(bottom_frame, text="Clear Logs", command=self.clear_logs, width=12)
        self.clear_logs_button.pack(side=tk.RIGHT, padx=5, pady=5)

    def setup_settings_tab(self):
        """Set up the settings tab with scrollable frame."""
        # Create a Canvas widget for scrolling
        canvas = tk.Canvas(self.settings_tab, bd=0, highlightthickness=0)
        # Create a vertical scrollbar linked to the canvas
        scrollbar = ttk.Scrollbar(self.settings_tab, orient="vertical", command=canvas.yview)
        # Create the Frame that will contain the actual settings widgets
        # This frame will be placed *inside* the canvas
        settings_frame = ttk.Frame(canvas, padding="15")

        # --- Canvas/Scrollbar Configuration ---
        # Tell the canvas to use the scrollbar
        canvas.configure(yscrollcommand=scrollbar.set)
        # Pack the canvas and scrollbar into the main settings_tab frame
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        # Place the settings_frame inside the canvas
        canvas_frame_id = canvas.create_window((0, 0), window=settings_frame, anchor="nw", tags="settings_frame")

        # --- Binding for Scroll Region ---
        # When the settings_frame changes size, update the canvas scrollregion
        settings_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        # When the canvas itself changes size, update the width of the frame inside it
        # This ensures the content frame uses the available width within the canvas viewport
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_frame_id, width=e.width))

        # --- Widgets Inside the Scrollable Frame (settings_frame) ---
        current_row = 0
        settings_frame.columnconfigure(1, weight=1) # Allow entry/combobox column to expand

        # --- Storage Section ---
        storage_frame = ttk.LabelFrame(settings_frame, text="Storage", padding="10")
        storage_frame.grid(row=current_row, column=0, columnspan=3, padx=5, pady=10, sticky="ew")
        storage_frame.columnconfigure(1, weight=1) # Make entry expand
        current_row += 1

        # Accepted receives Directory Setting
        ttk.Label(storage_frame, text="Accepted receives Directory:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.dir_var = tk.StringVar(value=self.settings.get("download_dir", DEFAULT_SETTINGS["download_dir"]))
        dir_entry = ttk.Entry(storage_frame, textvariable=self.dir_var, width=50) # Initial width
        dir_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        browse_button = ttk.Button(storage_frame, text="Browse...", command=self.browse_download_dir, width=10)
        browse_button.grid(row=0, column=2, padx=5, pady=5)
        ttk.Label(storage_frame, text="(Where approved files from browser receives are saved)", foreground="grey").grid(row=1, column=1, columnspan=2, padx=5, pady=(0, 5), sticky="w")

        # --- Appearance Section ---
        appearance_frame = ttk.LabelFrame(settings_frame, text="Appearance", padding="10")
        appearance_frame.grid(row=current_row, column=0, columnspan=3, padx=5, pady=10, sticky="ew")
        appearance_frame.columnconfigure(1, weight=0) # Don't make theme/font columns expand excessively
        current_row += 1

        # Theme Selection
        ttk.Label(appearance_frame, text="Theme:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.theme_var = tk.StringVar(value=self.settings.get("theme", DEFAULT_SETTINGS["theme"]))
        available_themes = self.get_available_themes()
        self.theme_combo = ttk.Combobox(appearance_frame, textvariable=self.theme_var, values=available_themes, state="readonly", width=20)
        self.theme_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        if not TTKTHEMES_AVAILABLE or not isinstance(self.root, ThemedTk):
             pass # Still allow selection of standard ttk themes

        # Font Selection (using a sub-frame for better alignment)
        font_frame = ttk.Frame(appearance_frame)
        font_frame.grid(row=1, column=0, columnspan=3, padx=0, pady=5, sticky="ew")

        ttk.Label(font_frame, text="Font:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        # Get available font families (with error handling)
        available_fonts = ["Segoe UI", "Arial", "Calibri", "Helvetica", "Verdana", "TkDefaultFont"] # Sensible defaults
        try:
            families = [f for f in sorted(font.families()) if not f.startswith('@')] # Filter symbol fonts
            if families:
                available_fonts = families
        except Exception:
            logger.error("Could not retrieve system font families, using defaults.", exc_info=False)

        self.font_family_var = tk.StringVar(value=self.settings.get("font_family", DEFAULT_SETTINGS["font_family"]))
        # Use Combobox for font family
        self.font_family_combo = ttk.Combobox(font_frame, textvariable=self.font_family_var, values=available_fonts, width=20)
        self.font_family_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(font_frame, text="Size:").grid(row=0, column=2, padx=(15, 5), pady=5, sticky="w") # Add padding before Size
        self.font_size_var = tk.IntVar(value=self.settings.get("font_size", DEFAULT_SETTINGS["font_size"]))
        # Use Spinbox for font size (tk.Spinbox does support border/relief, but default is usually fine)
        self.font_size_spinbox = tk.Spinbox(font_frame, textvariable=self.font_size_var, from_=8, to=24, width=5, justify=tk.RIGHT)
        self.font_size_spinbox.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        # --- Save Button ---
        save_button = ttk.Button(settings_frame, text="Save and Apply Settings", command=self.save_settings, width=25)
        save_button.grid(row=current_row, column=0, columnspan=3, padx=10, pady=20) # Centered below sections
        current_row += 1

    def get_available_themes(self) -> List[str]:
        """Get list of available ttk themes, handling potential errors."""
        themes = set()
        # Add known standard themes that usually exist
        themes.update(["clam", "alt", "default", "classic"])
        if sys.platform == "win32": themes.update(["vista", "xpnative"])
        if sys.platform == "darwin": themes.update(["aqua"])

        try:
            # Try getting themes from ttk.Style first
            if hasattr(self.root, 'style') and isinstance(self.style, ttk.Style):
                themes.update(self.style.theme_names())
        except Exception as e:
            logger.error(f"Error getting themes from ttk.Style: {e}")

        try:
            # If using ThemedTk, get its themes
            if TTKTHEMES_AVAILABLE and isinstance(self.root, ThemedTk):
                themes.update(self.root.get_themes())
        except Exception as e:
            logger.error(f"Error getting themes from ThemedTk: {e}")

        return sorted(list(themes))


    # --- Pending Upload Handling Methods ---

    def add_pending_upload(self, upload_id: str, filename: str, temp_file_path: str, file_size: int):
        """
        Add an upload request to the pending list.
        This method is called from the server thread (FileTransferHandler).
        It queues the GUI update to run safely in the main thread.
        """
        timestamp = datetime.now()
        # Put the GUI update function and its arguments into the queue
        gui_queue.put(lambda: self._add_pending_upload_gui(upload_id, filename, temp_file_path, file_size, timestamp))

    def _add_pending_upload_gui(self, upload_id: str, filename: str, temp_file_path: str, file_size: int, timestamp: datetime):
        """Update the GUI with a new pending upload (runs in main/GUI thread)."""
        # Check if GUI elements are still valid before trying to update
        if not self.root or not self.root.winfo_exists() or not hasattr(self, 'pending_tree') or not self.pending_tree.winfo_exists():
            logger.warning(f"Pending tree GUI not available or destroyed, cannot add upload '{filename}' visually.")
            # If the GUI is gone, we should probably reject/delete the temp file
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    logger.info(f"Removed orphaned temp file (GUI unavailable): {temp_file_path}")
                except OSError as e_rem:
                    logger.error(f"Could not remove orphaned temp file (GUI unavailable): {temp_file_path}, Error: {e_rem}")
            return

        try:
            # Format data for display
            size_str = format_file_size(file_size)
            time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            # Insert into the pending treeview
            # Using iid allows us to potentially reference this item later if needed
            item_id = self.pending_tree.insert("", "end", values=(filename, size_str, time_str))

            # Store the full information associated with this GUI item ID
            self.pending_uploads[item_id] = {
                "upload_id": upload_id, # The unique ID generated during upload
                "filename": filename,   # The sanitized filename
                "path": temp_file_path, # Full path to the temporary file
                "size": file_size,      # File size in bytes
                "timestamp": timestamp, # When it was received
            }
            logger.debug(f"Pending upload added to GUI list: '{filename}' (Item ID: {item_id})")

            # Optional: Visual indication of new pending item (e.g., changing tab text)
            try:
                tab_id = self.notebook.select() # Get current tab ID
                pending_tab_id = self.notebook.tabs()[self.notebook.tabs().index(self.pending_tab._w)] # Get ID of pending tab

                # Only update if pending tab is not currently selected
                if tab_id != pending_tab_id:
                    tab_idx = self.notebook.index(self.pending_tab)
                    current_text = self.notebook.tab(tab_idx, "text")
                    # Add marker only if not already present
                    if not current_text.strip().startswith("*"):
                        self.notebook.tab(tab_idx, text=f"* {current_text.strip()} *")
            except tk.TclError:
                 pass # Ignore if tab not found or notebook destroyed
            except Exception as e_tab:
                 logger.debug(f"Minor error updating pending tab text: {e_tab}")

        except tk.TclError as e:
            # Catch specific Tcl errors, often related to widget destruction
            logger.warning(f"TclError adding pending upload '{filename}' to GUI tree (widget likely destroyed): {e}")
        except Exception:
            # Catch any other unexpected errors during GUI update
            logger.exception("Unexpected error adding pending upload to GUI tree.")


    def accept_selected_upload(self):
        """Accept the selected pending upload: Move temp file to final dir and add to shared list."""
        if not hasattr(self, 'pending_tree') or not self.pending_tree.winfo_exists():
            logger.error("Accept Upload: Pending tree does not exist.")
            return
        selection = self.pending_tree.selection() # Get selected item IDs (should be only one due to selectmode='browse')
        if not selection:
            messagebox.showwarning("Accept Upload", "Please select an upload from the list to accept.", parent=self.root)
            return

        item_id = selection[0] # Get the first (and likely only) selected item ID

        if item_id in self.pending_uploads:
            # Retrieve and remove the upload info from our pending dictionary
            upload_info = self.pending_uploads.pop(item_id)
            filename = upload_info.get("filename", "UnknownFile")
            temp_path = upload_info.get("path")
            logger.info(f"Attempting to accept upload: '{filename}' (Item ID: {item_id}, Temp Path: {temp_path})")

            # Remove from the pending GUI list *immediately*
            try:
                if self.pending_tree.exists(item_id): # Check if it still exists in tree
                    self.pending_tree.delete(item_id)
            except tk.TclError:
                logger.warning(f"Item {item_id} already deleted from pending tree?")

            # --- Determine Target Directory (from settings) ---
            target_dir = self.settings.get("download_dir", DEFAULT_SETTINGS["download_dir"])
            try:
                # Ensure the target directory exists, create if not
                os.makedirs(target_dir, exist_ok=True)
                logger.debug(f"Ensured target directory exists: {target_dir}")
            except OSError as e:
                logger.error(f"Cannot create target directory '{target_dir}': {e}")
                messagebox.showerror("Accept Error",
                                     f"Fatal Error: Cannot create target directory:\n{target_dir}\n\nError: {e}\n\nPlease check permissions or choose a different directory in Settings.\n\nFile remains in temporary directory:\n{temp_path}",
                                     parent=self.root)
                # Since we couldn't create the dir, put the item back in the pending list conceptually
                # (It's already removed from GUI, but keep the data)
                self.pending_uploads[item_id] = upload_info
                # Log the failure
                self.log_threadsafe(f"Accept failed for '{filename}': Could not create target directory {target_dir}. File left in temp.", level="error")
                return # Stop the accept process here
            # --------------------------------------------------

            # --- Handle Filename Collisions in Target Directory ---
            base, ext = os.path.splitext(filename)
            counter = 1
            final_filename = filename
            final_path = os.path.join(target_dir, final_filename)

            while os.path.exists(final_path):
                # Append _1, _2, etc. before the extension
                final_filename = f"{base}_{counter}{ext}"
                final_path = os.path.join(target_dir, final_filename)
                counter += 1
            if final_filename != filename:
                 logger.info(f"Filename collision: Renaming accepted file to '{final_filename}'")
            # ----------------------------------------------------

            # --- Move the File ---
            try:
                if not temp_path or not os.path.exists(temp_path):
                     raise FileNotFoundError(f"Temporary file does not exist: {temp_path}")

                logger.debug(f"Moving '{temp_path}' to '{final_path}'")
                shutil.move(temp_path, final_path)
                logger.info(f"Successfully moved accepted upload '{filename}' to '{final_path}'")

                # --- Add to Main Shared Files List ---
                # Use the potentially renamed final_filename
                if self._add_file_to_serve_internal(final_filename, final_path, upload_info.get("size")):
                    self.log_threadsafe(f"Upload accepted and added to shared files: '{final_filename}'", level="info")
                    self.refresh_files_tree() # Update the main files list display
                else:
                    # This case is less likely if the move succeeded, but could happen
                    # if _add_file_to_serve_internal fails for some reason (e.g., duplicate path check if somehow added manually)
                    logger.error(f"File moved to '{final_path}', but FAILED to add to shared list (internal error or duplicate?).")
                    messagebox.showerror("Accept Warning",
                                         f"File moved successfully to:\n{final_path}\n\nHowever, it failed to automatically add to the shared list.\nYou may need to add it manually.",
                                         parent=self.root)
                # ------------------------------------

            except FileNotFoundError as e:
                logger.error(f"Error accepting file: Temporary file missing. {e}")
                messagebox.showerror("Accept Error", f"Temporary file for '{filename}' seems to be missing.\nCannot complete acceptance.", parent=self.root)
                self.log_threadsafe(f"Accept failed for '{filename}': Temp file missing.", level="error")
                # Don't re-add here, the temp file is gone.

            except (OSError, IOError) as e:
                logger.error(f"Error moving accepted file '{temp_path}' to '{final_path}': {e}")
                messagebox.showerror("Accept Error",
                                     f"Could not move file to destination directory:\n{target_dir}\n\nError: {e}\n\nPlease check permissions.\n\nFile remains in temporary directory:\n{temp_path}",
                                     parent=self.root)
                self.log_threadsafe(f"Accept failed for '{filename}'. Could not move file. File left in temp.", level="error")
                # Re-add to pending dict since move failed
                self.pending_uploads[item_id] = upload_info
                # Re-add to GUI is tricky, maybe just log it? User has the error message.
            except Exception:
                logger.exception(f"Unexpected error processing accepted file: '{filename}'")
                messagebox.showerror("Accept Error",
                                     f"An unexpected error occurred while accepting:\n'{filename}'\n\nFile may remain in temp directory. Check logs.",
                                     parent=self.root)
                self.log_threadsafe(f"Unexpected error accepting '{filename}'. Check logs.", level="error")
                # Re-add to pending dict as outcome is uncertain
                self.pending_uploads[item_id] = upload_info
        else:
            # This case means the item was selected in the GUI, but wasn't in our internal dict.
            # This might happen if there's a race condition or state mismatch.
            logger.warning(f"Selected item ID {item_id} not found in pending uploads dictionary. Attempting to remove from GUI if present.")
            try:
                if hasattr(self, 'pending_tree') and self.pending_tree.exists(item_id):
                    self.pending_tree.delete(item_id) # Clean up GUI anyway
            except tk.TclError:
                pass # Ignore if already gone

    def reject_selected_upload(self):
        """Reject the selected pending upload and delete its temporary file."""
        if not hasattr(self, 'pending_tree') or not self.pending_tree.winfo_exists():
            logger.error("Reject Upload: Pending tree does not exist.")
            return
        selection = self.pending_tree.selection()
        if not selection:
            messagebox.showwarning("Reject Upload", "Please select an upload from the list to reject.", parent=self.root)
            return

        item_id = selection[0]

        if item_id in self.pending_uploads:
            # Retrieve info and remove from pending dict
            upload_info = self.pending_uploads.pop(item_id)
            filename = upload_info.get("filename", "Unknown file")
            file_path_to_delete = upload_info.get("path")
            logger.info(f"Rejecting upload: '{filename}' (Item ID: {item_id}, Path: {file_path_to_delete})")

            # Remove from GUI list
            try:
                if self.pending_tree.exists(item_id):
                    self.pending_tree.delete(item_id)
            except tk.TclError:
                logger.warning(f"Item {item_id} was already deleted from pending tree during rejection.")
                pass # Ignore if already gone

            # Delete the temporary file
            if file_path_to_delete and isinstance(file_path_to_delete, str):
                if os.path.exists(file_path_to_delete):
                    try:
                        os.remove(file_path_to_delete)
                        self.log_threadsafe(f"Upload rejected and temporary file deleted: '{filename}'", level="info")
                    except OSError as e:
                        logger.error(f"Error removing rejected temporary file '{file_path_to_delete}': {e}")
                        messagebox.showerror("Reject Error", f"Could not delete temporary file:\n'{filename}'\n\nError: {e}\n\nYou may need to delete it manually from:\n{TEMP_DIR}", parent=self.root)
                        # Even if deletion fails, it's still rejected from the app's perspective.
                else:
                    # Temp file was already gone
                    self.log_threadsafe(f"Rejected upload '{filename}', but temporary file was already missing: {file_path_to_delete}", level="warning")
            else:
                # Path was missing or invalid in the upload_info
                self.log_threadsafe(f"Rejected upload '{filename}', but temporary path was missing or invalid in records.", level="warning")
        else:
            # Item selected in GUI but not in our dictionary - state mismatch
            logger.warning(f"Selected item ID {item_id} for rejection not found in pending uploads dictionary.")
            # Attempt to remove from GUI if it still exists there
            try:
                if hasattr(self, 'pending_tree') and self.pending_tree.exists(item_id):
                    self.pending_tree.delete(item_id)
            except tk.TclError:
                pass

    def reject_all_uploads(self):
        """Rejects all currently pending uploads and deletes their temp files."""
        if not self.pending_uploads:
            self.log_threadsafe("Reject All: No pending uploads to reject.", level="info")
            return

        # Get a snapshot of item IDs to reject
        item_ids_to_reject = list(self.pending_uploads.keys())
        num_to_reject = len(item_ids_to_reject)
        rejected_count = 0
        error_count = 0
        logger.info(f"Starting 'Reject All' for {num_to_reject} pending uploads.")

        for item_id in item_ids_to_reject:
            if item_id in self.pending_uploads: # Check again in case of race conditions
                upload_info = self.pending_uploads.pop(item_id) # Remove from dict
                filename = upload_info.get("filename", f"Item {item_id}")
                file_path_to_delete = upload_info.get("path")

                # Remove from GUI
                try:
                    if hasattr(self, 'pending_tree') and self.pending_tree.winfo_exists() and self.pending_tree.exists(item_id):
                        self.pending_tree.delete(item_id)
                except tk.TclError:
                    pass # Ignore GUI errors

                # Delete temp file
                if file_path_to_delete and isinstance(file_path_to_delete, str):
                    if os.path.exists(file_path_to_delete):
                        try:
                            os.remove(file_path_to_delete)
                            rejected_count += 1
                        except OSError as e:
                            logger.error(f"Error removing '{file_path_to_delete}' during Reject All: {e}")
                            error_count += 1
                    else:
                        # File already gone, still counts as rejected
                        logger.warning(f"Temp file '{file_path_to_delete}' for rejected item '{filename}' was already missing.")
                        rejected_count += 1 # Count it as successfully rejected conceptually
                else:
                    # Path missing/invalid
                    logger.warning(f"Missing or invalid temp path during Reject All for '{filename}'")
                    error_count += 1 # Count as an error because we couldn't verify deletion

        log_msg = f"Reject All finished. Rejected {rejected_count} of {num_to_reject} uploads."
        if error_count > 0:
            log_msg += f" Encountered {error_count} errors (e.g., failed deletions or missing paths)."
            messagebox.showwarning("Reject All Complete",
                                   f"Finished rejecting uploads, but encountered {error_count} errors.\nSome temporary files might remain.\nPlease check logs.",
                                   parent=self.root)

        self.log_threadsafe(log_msg, level="warning" if error_count else "info")

    def reject_all_uploads_confirm(self):
        """Ask for confirmation before rejecting all pending uploads."""
        if not self.pending_uploads:
            messagebox.showinfo("Reject All", "There are no pending uploads to reject.", parent=self.root)
            return

        num_pending = len(self.pending_uploads)
        if messagebox.askyesno("Confirm Reject All",
                               f"Are you sure you want to reject all {num_pending} pending uploads?\n\nTheir temporary files will be deleted.",
                               icon='warning', parent=self.root):
            self.reject_all_uploads()

    def show_pending_menu(self, event: tk.Event):
        """Show the right-click context menu for pending uploads."""
        if not hasattr(self, 'pending_tree') or not self.pending_tree.winfo_exists(): return
        # Identify the item under the cursor
        item_id = self.pending_tree.identify_row(event.y)
        if item_id:
            # Select the item if it's not already selected
            if item_id not in self.pending_tree.selection():
                self.pending_tree.selection_set(item_id)
            # Post the context menu
            if hasattr(self, 'pending_menu'):
                self.pending_menu.post(event.x_root, event.y_root)
            else:
                logger.error("Pending uploads context menu (self.pending_menu) not initialized.")

    # --- Server Control Methods ---

    def start_server(self):
        """Start the web server in a background thread."""
        if self.is_server_running:
            messagebox.showwarning("Server Running", "The server is already running.", parent=self.root)
            return

        # Optional: Warn if using a loopback or potentially non-routable IP
        # if not self.local_ip or self.local_ip in ["127.0.0.1", "0.0.0.0"]:
        #     messagebox.showwarning("Network Warning",
        #                            f"Server starting with IP: {self.local_ip}.\nThis might only be accessible from this computer.\nCheck network configuration if external access is needed.",
        #                            parent=self.root)

        try:
            server_address = ("0.0.0.0", self.port) # Listen on all interfaces
            logger.info(f"Attempting to start HTTP server on {server_address}...")
            # Create the server instance, passing the app instance to it
            self.server = FileTransferHTTPServer(server_address, FileTransferHandler, app_instance=self)

            # Start the server's serve_forever loop in a separate thread
            self.server_thread = threading.Thread(target=self.run_server, name="HTTPServerThread", daemon=True)
            self.server_thread.start()

            self.is_server_running = True
            server_url = f"http://{self.local_ip}:{self.port}" # URL for local access display
            logger.info(f"Server thread started. Access URL for this machine: {server_url}")

            # Update GUI via the queue
            self.log_threadsafe(f"Server started successfully. Listening on {server_url}", level="info")
            gui_queue.put(lambda: self.update_server_status_gui(server_url, True, "green", "Running"))

        except OSError as e:
            # Common error: Port already in use
            if e.errno == 98 or e.errno == 10048 or 'Address already in use' in str(e): # errno 98 (Linux), 10048 (Win)
                 error_msg = f"Failed to start server: Port {self.port} is already in use.\n\nPlease close the other application using this port or change the port in settings (if implemented)."
                 logger.error(f"Failed to bind server to port {self.port}: Address already in use.", exc_info=False)
            else:
                 error_msg = f"Failed to start server due to an OS error:\n{e}\n\nCheck logs for details."
                 logger.error(f"Failed to start server on port {self.port}: {e}", exc_info=True) # Log full trace for other OS errors

            messagebox.showerror("Server Startup Error", error_msg, parent=self.root)
            self.server = None # Ensure server object is None
            # Update GUI via queue
            gui_queue.put(lambda: self.update_server_status_gui("Start Failed", False, "red", "Start Failed"))
        except Exception:
            # Catch any other unexpected errors during setup
            logger.exception("Unexpected error occurred during server startup")
            messagebox.showerror("Server Startup Error", "An unexpected error occurred while starting the server.\nCheck logs for details.", parent=self.root)
            self.server = None
            gui_queue.put(lambda: self.update_server_status_gui("Start Error", False, "red", "Start Error"))


    def run_server(self):
        """Target function for the server thread. Runs serve_forever()."""
        if not self.server:
            logger.error("run_server called but self.server is None.")
            return
        try:
            current_thread_name = threading.current_thread().name
            logger.info(f"Server thread '{current_thread_name}' entering serve_forever loop...")
            self.server.serve_forever()
            # This line is reached only after shutdown() is called
            logger.info(f"Server thread '{current_thread_name}' exited serve_forever loop normally.")
        except Exception:
            # Log exceptions that occur within the server's core loop (less common)
            logger.exception("Exception caught directly in server's serve_forever loop:")
            # If the app is still running, update the GUI to show error state
            if self.root and self.root.winfo_exists() and self.is_server_running:
                 self.log_threadsafe("Server stopped unexpectedly due to an internal error.", level="critical")
                 gui_queue.put(lambda: self.update_server_status_gui("Server Error", False, "red", "Server Error"))
                 self.is_server_running = False # Update state flag
                 self.server = None # Clear server instance


    def stop_server(self):
        """Initiate the server shutdown sequence."""
        if not self.is_server_running:
            logger.debug("Stop server called, but server is not running.")
            return
        if not self.server:
            logger.error("Stop server called, but self.server object is None. Forcing state to not running.")
            self.is_server_running = False
            gui_queue.put(lambda: self.update_server_status_gui("Error State", False, "red", "Error"))
            return

        logger.info("Initiating server shutdown...")
        self.is_server_running = False # Update state flag immediately
        self.log_threadsafe("Stopping server...", "info")

        # Update GUI to show "Stopping..." state and disable button temporarily
        gui_queue.put(lambda: self.update_server_status_gui("N/A", False, "orange", "Stopping..."))

        # Perform the actual shutdown in a separate thread to avoid blocking the GUI
        shutdown_thread = threading.Thread(target=self._shutdown_server_thread, name="ShutdownThread", daemon=True)
        shutdown_thread.start()


    def _shutdown_server_thread(self):
        """Performs the actual server shutdown (called in a background thread)."""
        server_instance = self.server # Get reference before potentially setting to None
        if not server_instance:
             logger.warning("_shutdown_server_thread called but server instance is already None.")
             # Ensure GUI updates correctly if shutdown was attempted on null server
             if self.root and self.root.winfo_exists():
                  gui_queue.put(lambda: self.update_server_status_gui("Not running", False, "red", "Not running"))
             return

        try:
            logger.debug("Calling server.shutdown()...")
            server_instance.shutdown() # Stop the serve_forever loop
            logger.debug("Calling server.server_close()...")
            server_instance.server_close() # Release the socket
            logger.info("Server shutdown sequence complete.")
        except Exception:
            logger.exception("Error during server shutdown sequence:")
            # Update GUI to show error if shutdown failed
            if self.root and self.root.winfo_exists():
                 gui_queue.put(lambda: self.update_server_status_gui("Shutdown Error", False, "red", "Shutdown Error"))
        finally:
            # Clear the server instance variable
            self.server = None
            # Update GUI to final "Not running" state if no error occurred during shutdown
            if self.root and self.root.winfo_exists():
                 # Check if status is still "Stopping..." before setting to "Not running"
                 # This avoids overriding a "Shutdown Error" state set in the except block
                 try:
                      current_status = self.status_label.cget("text") if hasattr(self, 'status_label') else ""
                      if current_status == "Stopping...":
                           gui_queue.put(lambda: self.update_server_status_gui("Not running", False, "red", "Not running"))
                 except tk.TclError:
                      pass # Widget might be destroyed


    def update_server_status_gui(self, url_or_status: str, is_running: bool, color: str, status_text: str):
        """Update server status GUI elements (designed to run in the main GUI thread via queue)."""
        if not self.root or not self.root.winfo_exists():
            logger.debug("Skipping GUI update - root window gone.")
            return

        try:
            # Determine display texts and states
            button_text = "Stop Server" if is_running else "Start Server"
            url_text = url_or_status if is_running else "N/A"
            # Disable toggle button only while stopping (orange color) to prevent rapid clicks
            button_state = tk.DISABLED if color == "orange" else tk.NORMAL
            # Enable/disable URL label interaction
            url_state = "!disabled" if is_running else "disabled" # Use ttk state specifiers
            # Enable/disable Open Browser button
            browser_button_state = tk.NORMAL if is_running else tk.DISABLED

            # Update Status Label
            if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                self.status_label.config(text=status_text)
                # Update the style associated with the status label
                font_fam = self.settings.get("font_family", DEFAULT_SETTINGS["font_family"])
                font_sz = self.settings.get("font_size", DEFAULT_SETTINGS["font_size"])
                self.style.configure("Status.TLabel", foreground=color, font=(font_fam, font_sz))
            else: logger.warning("Status label not found or destroyed during GUI update.")

            # Update URL Label
            if hasattr(self, 'url_label') and self.url_label.winfo_exists():
                self.url_label.config(text=url_text)
                self.url_label.state([url_state]) # Apply state using list
            else: logger.warning("URL label not found or destroyed during GUI update.")

            # Update Toggle Server Button
            if hasattr(self, 'toggle_server_button') and self.toggle_server_button.winfo_exists():
                self.toggle_server_button.config(text=button_text, state=button_state)
            else: logger.warning("Toggle server button not found or destroyed.")

            # Update Open Browser Button
            if hasattr(self, 'open_browser_button') and self.open_browser_button.winfo_exists():
                 self.open_browser_button.config(state=browser_button_state)
            else: logger.warning("Open browser button not found or destroyed.")

        except tk.TclError as e:
             logger.error(f"TclError updating server status GUI (widget likely destroyed): {e}")
        except Exception:
            logger.exception("Unexpected error updating server status GUI.")


    def toggle_server(self):
        """Starts or stops the server based on current state."""
        # Prevent action if the button is disabled (e.g., during shutdown)
        if hasattr(self, 'toggle_server_button') and self.toggle_server_button.cget('state') == tk.DISABLED:
             logger.debug("Toggle server called, but button is disabled (likely stopping). Ignoring.")
             return

        if self.is_server_running:
            self.stop_server()
        else:
            self.start_server()


    # --- Browser and File Methods ---

    def open_in_browser(self, event=None): # Allow binding to event or direct call
        """Open the web UI in the default system browser."""
        if not self.is_server_running:
            messagebox.showwarning("Server Not Running", "The server must be running to open the interface in a browser.", parent=self.root)
            return
        if not self.server:
             messagebox.showerror("Error", "Server is marked as running, but server object is missing.", parent=self.root)
             return

        try:
            # Construct the URL using the determined local IP and port
            server_url = f"http://{self.local_ip}:{self.port}"
            logger.info(f"Opening '{server_url}' in default web browser.")
            # new=2: open in a new tab if possible
            webbrowser.open(server_url, new=2)
            self.log_threadsafe(f"Opened '{server_url}' in browser.", "info")
        except Exception as e:
            logger.error(f"Failed to open URL '{server_url}' in browser: {e}")
            messagebox.showerror("Browser Error", f"Could not open the URL in your web browser:\n{e}", parent=self.root)


    def add_files(self):
        """Add one or more files to the shared list via a file dialog."""
        # Use initialdir maybe? os.path.expanduser("~")
        paths = filedialog.askopenfilenames(parent=self.root, title="Select Files to Share")
        if not paths:
             logger.debug("Add files dialog cancelled.")
             return # User cancelled

        added_count = 0
        skipped_count = 0
        added_filenames = []

        for file_path in paths:
            if not isinstance(file_path, str) or not file_path: continue # Skip empty/invalid paths
            try:
                 file_name = os.path.basename(file_path)
                 # Call internal helper to add to data structure
                 if self._add_file_to_serve_internal(file_name, file_path):
                     added_count += 1
                     added_filenames.append(file_name)
                 else:
                     skipped_count += 1 # Already exists or is invalid
            except Exception as e:
                 logger.error(f"Error processing selected file '{file_path}': {e}")
                 skipped_count += 1

        if added_count > 0:
            self.refresh_files_tree() # Update the GUI list
            log_msg = f"Added {added_count} file(s)."
            # Optionally list added files if not too many:
            # if added_count <= 5: log_msg += f" ({', '.join(added_filenames)})"
            if skipped_count > 0: log_msg += f" Skipped {skipped_count} (duplicates/errors/invalid)."
            self.log_threadsafe(log_msg, "info")
        elif skipped_count > 0:
            self.log_threadsafe(f"Skipped {skipped_count} file(s) (duplicates/errors/invalid).", "warning")
        else:
            logger.debug("No files were added or skipped (paths might have been empty).")


    def add_folder(self):
        """Add files from a selected folder (and its subfolders) to the shared list."""
        # Ask the user to select a directory
        folder_path = filedialog.askdirectory(parent=self.root, title="Select Folder to Share (Includes Subfolders)", mustexist=True)
        if not folder_path:
             logger.debug("Add folder dialog cancelled.")
             return # User cancelled

        self.log_threadsafe(f"Scanning folder: '{folder_path}'...", "info")
        # Run the potentially long-running scan in a background thread
        scan_thread = threading.Thread(target=self._add_folder_files_thread, args=(folder_path,), daemon=True, name="FolderScanThread")
        scan_thread.start()


    def _add_folder_files_thread(self, folder_path: str):
        """Worker thread to scan a folder recursively and collect files."""
        files_to_add_info = [] # List of dicts: {"name": name, "path": path}
        skipped_count = 0
        error_count = 0
        scanned_count = 0

        try:
            for root, _, files in os.walk(folder_path):
                for filename in files:
                    scanned_count += 1
                    file_path = os.path.join(root, filename)
                    try:
                        # Check if it's a file and readable before adding
                        if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                            files_to_add_info.append({"name": filename, "path": file_path})
                        elif not os.path.isfile(file_path):
                            # logger.debug(f"Skipping non-file entry: {file_path}") # Optional: log skipped non-files
                            skipped_count += 1
                        else: # Is a file but not readable
                            logger.warning(f"Skipping unreadable file: {file_path}")
                            skipped_count += 1
                    except OSError as e_os: # Catch permission errors etc. during checks
                        logger.warning(f"OS error accessing '{file_path}': {e_os}")
                        error_count += 1
                    except Exception as e_acc: # Catch other unexpected errors
                        logger.warning(f"Unexpected error accessing '{file_path}': {e_acc}")
                        error_count += 1
        except Exception as e_walk:
            # Catch errors during os.walk itself (e.g., top-level directory permissions)
            logger.exception(f"Critical error occurred during folder scan of '{folder_path}'")
            # Notify user via GUI queue
            gui_queue.put(lambda: messagebox.showerror("Folder Scan Error", f"An error occurred while scanning the folder:\n{folder_path}\n\nError: {e_walk}\n\nCheck logs for details.", parent=self.root if self.root and self.root.winfo_exists() else None))
            return # Stop the thread

        # --- Process collected files in GUI thread ---
        def process_scan_results():
            if not self.root or not self.root.winfo_exists():
                 logger.warning("Folder scan finished, but GUI is gone. Cannot add files.")
                 return

            added_count = 0
            folder_basename = os.path.basename(folder_path)

            if not files_to_add_info:
                 log_msg = f"Scan of '{folder_basename}' complete. No readable files found to add."
                 if skipped_count > 0: log_msg += f" Skipped {skipped_count} non-files or unreadable files."
                 if error_count > 0: log_msg += f" Encountered {error_count} access errors."
                 self.log_threadsafe(log_msg, "info")
                 return

            logger.debug(f"Adding {len(files_to_add_info)} files found in '{folder_basename}' to the list...")
            for file_info in files_to_add_info:
                # Use internal add function, which handles duplicates based on path
                if self._add_file_to_serve_internal(file_info["name"], file_info["path"]):
                    added_count += 1
                else:
                     # Increment skipped count if internal add fails (likely duplicate)
                     skipped_count += 1

            if added_count > 0:
                self.refresh_files_tree() # Update GUI only if files were actually added

            # Log summary
            log_msg = f"Folder Scan '{folder_basename}': Added {added_count} file(s)."
            # Report skipped/errors only if non-zero
            if skipped_count > 0: log_msg += f" Skipped {skipped_count} (duplicates/unreadable/invalid)."
            if error_count > 0: log_msg += f" Encountered {error_count} access errors."
            self.log_threadsafe(log_msg, level="warning" if error_count or (skipped_count > 0 and added_count == 0) else "info")

        # Queue the processing function to run in the main GUI thread
        gui_queue.put(process_scan_results)


    def _add_file_to_serve_internal(self, name: str, path: str, size: Optional[int] = None) -> bool:
        """
        Internal helper to add a single file to the `files_to_serve` dictionary.
        Checks for validity and prevents duplicates based on absolute path.
        Designed to be called from the main GUI thread.
        Returns True if added successfully, False otherwise.
        """
        global next_file_id, files_to_serve

        # Basic type validation
        if not isinstance(name, str) or not name or not isinstance(path, str) or not path:
            logger.error(f"Invalid name or path provided for adding file: name='{name}', path='{path}'")
            return False

        try:
            # Always work with absolute paths for reliable duplicate checking
            abs_path = os.path.abspath(path)

            # Check 1: Is it actually a file?
            if not os.path.isfile(abs_path):
                logger.warning(f"Cannot add '{name}': Path is not a file or does not exist. Path: {abs_path}")
                return False

            # Check 2: Is it readable?
            if not os.access(abs_path, os.R_OK):
                logger.warning(f"Cannot add '{name}': File is not readable (permissions?). Path: {abs_path}")
                return False

            # Check 3: Is this exact path already being served?
            if any(info.get("path") == abs_path for info in files_to_serve.values()):
                logger.debug(f"Skipping duplicate file path: {abs_path}")
                return False # Indicate not added (was duplicate)

            # Get file size if not provided
            file_size = size if size is not None and isinstance(size, int) else os.path.getsize(abs_path)

            # Generate the next unique file ID
            file_id = next_file_id
            next_file_id += 1

            # Add the file information to the dictionary
            files_to_serve[file_id] = {
                "name": name,         # Original or potentially sanitized filename
                "path": abs_path,     # Absolute path on the server's filesystem
                "size": file_size,    # Size in bytes
                "added_time": datetime.now() # Timestamp when added
            }
            logger.debug(f"Added to serve list: '{name}' (ID: {file_id}, Path: {abs_path})")
            return True # Indicate successful addition

        except OSError as e:
            # Catch OS-level errors (e.g., during getsize or abspath)
            logger.error(f"OS Error adding file '{name}' (Path: {path}): {e}")
            return False
        except Exception:
            # Catch any other unexpected errors
            logger.exception(f"Unexpected error adding file '{name}' (Path: {path}) to serve list:")
            return False


    def remove_selected_file(self):
        """Remove the selected file from the 'Shared Files' list."""
        if not hasattr(self, 'files_tree') or not self.files_tree.winfo_exists():
             logger.error("Remove File: Files tree does not exist.")
             return
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Remove File", "Please select a file from the list to remove.", parent=self.root)
            return

        item_id = selection[0] # GUI Tree item ID

        # Find the internal file_id associated with this GUI item
        file_id_to_remove = self.tree_items.pop(item_id, None) # Remove from mapping, get value

        removed_from_dict = False
        file_name_for_log = f"Item {item_id}" # Default log name

        if file_id_to_remove is not None:
            # Remove the file info from the main data dictionary
            file_info = files_to_serve.pop(file_id_to_remove, None)
            if file_info:
                 removed_from_dict = True
                 file_name_for_log = file_info.get("name", f"ID {file_id_to_remove}")
                 logger.debug(f"Removed file ID {file_id_to_remove} ('{file_name_for_log}') from files_to_serve.")
            else:
                 # Mapping existed, but file_id wasn't in files_to_serve (shouldn't normally happen)
                 logger.warning(f"Removed tree item {item_id} mapping, but corresponding file ID {file_id_to_remove} was not found in files_to_serve.")
        else:
             # No mapping found for the selected GUI item (shouldn't normally happen if tree is in sync)
             logger.warning(f"Could not find internal file ID mapping for selected tree item {item_id} during removal.")

        # Remove the item from the GUI Treeview regardless of dictionary state
        try:
            if self.files_tree.exists(item_id):
                 self.files_tree.delete(item_id)
                 logger.debug(f"Removed item {item_id} from GUI tree.")
                 # Log only after successful GUI removal if desired
                 if removed_from_dict or file_id_to_remove is not None:
                     self.log_threadsafe(f"Removed from shared list: '{file_name_for_log}'", "info")

        except tk.TclError:
            logger.warning(f"TclError removing item {item_id} from tree (might have been already removed).")
            # Log based on whether we found it in the dictionary earlier
            if removed_from_dict or file_id_to_remove is not None:
                self.log_threadsafe(f"Removed from shared list: '{file_name_for_log}' (GUI removal failed/race?)", "info")


    def remove_file_by_id_threadsafe(self, file_id: int):
        """Request file removal by its internal file_id from any thread."""
        logger.debug(f"Queueing removal request for file ID: {file_id}")
        # Queue the actual removal logic to run in the main GUI thread
        gui_queue.put(lambda: self._remove_file_by_id_gui(file_id))

    def _remove_file_by_id_gui(self, file_id: int):
        """Remove file by internal file_id (runs in main GUI thread)."""
        if not isinstance(file_id, int):
             logger.error(f"Invalid file_id type provided for removal: {file_id}")
             return

        logger.debug(f"Processing removal request for file ID: {file_id}")
        # Remove from the main data dictionary
        file_info = files_to_serve.pop(file_id, None)

        if file_info:
            file_name = file_info.get("name", f"ID {file_id}")
            logger.info(f"Removing file by ID {file_id} ('{file_name}') from internal list.")
            self.log_threadsafe(f"Removed '{file_name}' from sharing list (triggered by ID).", "info")

            # Find and remove corresponding item(s) from the GUI tree
            # Need to iterate through the mapping to find the GUI item ID(s)
            items_to_remove_from_gui = [gui_id for gui_id, data_id in self.tree_items.items() if data_id == file_id]

            if not items_to_remove_from_gui:
                 logger.warning(f"Removed file ID {file_id} ('{file_name}') from data, but no corresponding GUI item found in tree_items mapping.")
            else:
                 for item_id_gui in items_to_remove_from_gui:
                     # Remove from the mapping dictionary
                     if item_id_gui in self.tree_items:
                         del self.tree_items[item_id_gui]
                         logger.debug(f"Removed mapping for GUI item {item_id_gui}")

                     # Remove from the actual Treeview widget
                     try:
                         if hasattr(self, 'files_tree') and self.files_tree.winfo_exists() and self.files_tree.exists(item_id_gui):
                             self.files_tree.delete(item_id_gui)
                             logger.debug(f"Removed item {item_id_gui} from files_tree GUI.")
                     except tk.TclError:
                         logger.warning(f"TclError removing GUI item {item_id_gui} for file ID {file_id} (already gone?).")
        else:
            # file_id was not found in files_to_serve
            logger.warning(f"Request received to remove file ID {file_id}, but it was not found in the active sharing list.")


    def clear_files_confirm(self):
        """Ask for confirmation before clearing the entire shared files list."""
        if not files_to_serve:
            messagebox.showinfo("Clear Files", "The shared files list is already empty.", parent=self.root)
            return

        if messagebox.askyesno("Confirm Clear All",
                               "Are you sure you want to remove ALL files from the sharing list?\n\n(This action does not delete the actual files from your disk.)",
                               icon='warning', parent=self.root):
            self.clear_files()


    def clear_files(self):
        """Clear the shared files data structure and the GUI treeview."""
        global files_to_serve # Need to modify the global dict
        num_files = len(files_to_serve)

        if num_files == 0:
            logger.debug("Clear files called, but list is already empty.")
            return

        logger.info(f"Clearing all {num_files} files from the sharing list.")

        # Clear the data structures
        files_to_serve = {}
        self.tree_items = {} # Clear the GUI item to file_id mapping

        # Clear the GUI Treeview
        try:
            if hasattr(self, 'files_tree') and self.files_tree.winfo_exists():
                # Efficiently delete all top-level items and their children
                children = self.files_tree.get_children()
                if children:
                    self.files_tree.delete(*children)
                logger.debug("Cleared all items from the files_tree GUI.")
            else:
                 logger.warning("Files tree widget not available during clear_files.")
        except tk.TclError as e:
            logger.error(f"TclError clearing files_tree GUI: {e}")
        except Exception:
             logger.exception("Unexpected error clearing files_tree GUI.")

        self.log_threadsafe(f"Cleared all {num_files} shared files from the list.", "info")


    # --- CORRECTED refresh_files_tree ---
    def refresh_files_tree(self):
        """Clears and repopulates the 'Shared Files' treeview based on `files_to_serve` data."""

        # --- Pre-checks ---
        if not hasattr(self, 'files_tree'):
            logger.error("refresh_files_tree called but self.files_tree attribute does not exist.")
            return
        if not self.root or not self.root.winfo_exists():
            logger.warning("refresh_files_tree called but root window no longer exists.")
            return
        if not self.files_tree.winfo_exists():
             logger.warning("refresh_files_tree called but files_tree widget no longer exists.")
             return

        logger.debug(f"Refreshing shared files tree (Sorting by '{self._files_sort_column}', Reverse: {self._files_sort_reverse})...")

        # --- Clear Existing GUI Items ---
        try:
            # Efficiently delete all existing items
            existing_items = self.files_tree.get_children()
            if existing_items:
                self.files_tree.delete(*existing_items)
        except tk.TclError as e:
            # Log error if clearing fails (e.g., widget destroyed during operation)
            logger.error(f"TclError while clearing files_tree: {e}. Aborting refresh.")
            return
        except Exception:
            logger.exception("Unexpected error while clearing files_tree. Aborting refresh.")
            return

        # --- Clear Internal Mapping ---
        # This dictionary maps GUI item IDs (like 'I001') to internal file IDs (like 1, 2, 3...)
        self.tree_items = {}

        # --- Sorting ---
        # Define a key function for sorting based on the current column
        def sort_key_function(item_tuple):
            # item_tuple is (file_id, file_info_dict)
            _file_id, info_dict = item_tuple
            column = self._files_sort_column # Get current sort column name

            if column == "Size":
                # Sort by raw size (integer) for numerical sorting
                return info_dict.get("size", 0)
            elif column == "Path":
                # Sort by path string, case-insensitive
                return str(info_dict.get("path", "")).lower()
            elif column == "Name":
                # Default: Sort by name string, case-insensitive
                 return str(info_dict.get("name", "")).lower()
            else:
                 # Fallback if column name is unexpected
                 return ""

        try:
            # Get items from the global dictionary and sort them
            sorted_file_list = sorted(
                list(files_to_serve.items()), # Convert dict items to list of (id, info) tuples
                key=sort_key_function,        # Use our key function
                reverse=self._files_sort_reverse # Use current sort direction
            )
        except Exception:
             logger.exception("Error sorting files for tree refresh. Displaying unsorted.")
             # Fallback to unsorted list if sorting fails
             sorted_file_list = list(files_to_serve.items())

        # --- Repopulate the Tree ---
        try:
            logger.debug(f"Populating tree with {len(sorted_file_list)} items.")
            for file_id, file_info in sorted_file_list:
                # Extract data, providing defaults for safety
                display_name = file_info.get("name", "? Unknown Name")
                display_size = format_file_size(file_info.get("size"))
                display_path = file_info.get("path", "N/A")

                # Insert the item into the Treeview GUI
                # "" means insert at the root level, "end" means append to the end
                # values must be a tuple matching the order defined in columns=("Name", "Size", "Path")
                gui_item_id = self.files_tree.insert("", "end", values=(display_name, display_size, display_path))

                # Store the mapping from the newly created GUI item ID back to the internal file ID
                self.tree_items[gui_item_id] = file_id

            logger.debug("Finished repopulating shared files tree.")
        except tk.TclError as e:
             logger.error(f"TclError populating shared files tree (widget likely destroyed): {e}")
        except Exception:
            logger.exception("Error populating shared files treeview.")
    # --- End CORRECTED refresh_files_tree ---


    def sort_files_tree(self, column: str):
        """Sort the shared files treeview by the clicked column header."""
        if not hasattr(self, 'files_tree') or not self.files_tree.winfo_exists(): return

        logger.debug(f"Sorting files tree by column: {column}")
        # Determine sort direction
        if self._files_sort_column == column:
             # If clicking the same column, reverse the sort order
             self._files_sort_reverse = not self._files_sort_reverse
        else:
             # If clicking a new column, sort ascending initially
             self._files_sort_column = column
             self._files_sort_reverse = False

        # Update column header display (optional visual indicator)
        # for col in ("Name", "Size", "Path"):
        #     arrow = ""
        #     if col == self._files_sort_column:
        #         arrow = " ↓" if self._files_sort_reverse else " ↑"
        #     self.files_tree.heading(col, text=f"{col}{arrow}")


        # Refresh the treeview content with the new sorting applied
        self.refresh_files_tree()


    def show_files_menu(self, event: tk.Event):
        """Show the right-click context menu for the shared files treeview."""
        if not hasattr(self, 'files_tree') or not self.files_tree.winfo_exists(): return
        # Identify the item under the cursor
        item_id = self.files_tree.identify_row(event.y)
        if item_id:
            # Select the item if it's not already selected
            if item_id not in self.files_tree.selection():
                self.files_tree.selection_set(item_id) # Make it the active selection
                self.files_tree.focus(item_id) # Give focus to the item

            # Post the context menu at the cursor's location
            if hasattr(self, 'files_menu'):
                self.files_menu.post(event.x_root, event.y_root)
            else:
                logger.error("Shared files context menu (self.files_menu) not initialized.")


    def open_containing_folder_event(self, event: tk.Event):
        """Handle double-click event on a shared file item."""
        if not hasattr(self, 'files_tree') or not self.files_tree.winfo_exists(): return
        # Check if the double-click was on an actual item row
        if self.files_tree.identify_row(event.y):
            self.open_containing_folder()


    def open_containing_folder(self):
        """Open the folder containing the selected shared file in the system's file explorer."""
        if not hasattr(self, 'files_tree') or not self.files_tree.winfo_exists(): return
        selection = self.files_tree.selection()
        if not selection:
             # This shouldn't happen if called from menu/double-click, but check anyway
             logger.debug("Open Containing Folder called with no selection.")
             return

        item_id = selection[0]
        file_id = self.tree_items.get(item_id)
        if file_id is None:
            logger.error(f"Cannot open folder: No internal file ID found for selected item {item_id}.")
            messagebox.showerror("Error", "Could not retrieve file information for the selected item.", parent=self.root)
            return

        file_info = files_to_serve.get(file_id)
        if not file_info or "path" not in file_info:
            logger.error(f"Cannot open folder: File info or path missing for file ID {file_id}.")
            messagebox.showerror("Error", "File information is missing or incomplete.", parent=self.root)
            return

        file_path = file_info["path"]

        # Check if the file still exists before trying to open its folder
        if not os.path.exists(file_path):
            logger.warning(f"Cannot open folder: File '{file_path}' no longer exists.")
            messagebox.showwarning("File Not Found", f"The file:\n{file_path}\nno longer exists on disk.\n\nRemoving it from the list.", parent=self.root)
            # Remove the now-invalid entry automatically
            self.remove_file_by_id_threadsafe(file_id)
            return

        # Get the directory containing the file
        folder_path = os.path.dirname(file_path)
        logger.info(f"Attempting to open containing folder: {folder_path} (for file: {file_path})")

        try:
            # Platform-specific ways to open the folder and select the file
            if sys.platform == "win32":
                # explorer.exe /select,"C:\path\to\file.txt"
                subprocess.Popen(['explorer', '/select,', file_path])
            elif sys.platform == "darwin": # macOS
                # open -R /path/to/file.txt (reveals in Finder)
                subprocess.Popen(['open', '-R', file_path])
            else: # Linux and other POSIX-like systems
                # Try xdg-open first (common standard)
                # Need to run in background silently
                run_command_background_silent(['xdg-open', folder_path])
                # Fallback ideas (less common, might need specific file managers):
                # run_command_background_silent(['nautilus', folder_path])
                # run_command_background_silent(['dolphin', folder_path])
                # run_command_background_silent(['thunar', folder_path])
            self.log_threadsafe(f"Opened containing folder for: {os.path.basename(file_path)}", "info")
        except FileNotFoundError as e_fnf:
             # This might happen if 'explorer', 'open', or 'xdg-open' isn't in the PATH
             logger.error(f"Command not found for opening folder: {e_fnf}")
             messagebox.showerror("Error", f"Could not find the command needed to open the folder.\nIs your system's file explorer configured correctly?\n\nCommand: {e_fnf.filename}", parent=self.root)
        except Exception as e:
            logger.exception(f"An unexpected error occurred while trying to open folder: {folder_path}")
            messagebox.showerror("Error", f"Could not open the containing folder.\nError: {e}", parent=self.root)


    def copy_selected_path(self):
        """Copy the full path of the selected shared file to the clipboard."""
        if not hasattr(self, 'files_tree') or not self.files_tree.winfo_exists(): return
        selection = self.files_tree.selection()
        if not selection:
            # logger.debug("Copy path called with no selection.") # Maybe show warning?
            messagebox.showwarning("Copy Path", "Please select a file first to copy its path.", parent=self.root)
            return

        item_id = selection[0]
        file_id = self.tree_items.get(item_id)
        if file_id is None:
            logger.error(f"Cannot copy path: No internal file ID found for selected item {item_id}.")
            return # No user message needed? Or maybe show error?

        file_info = files_to_serve.get(file_id)
        if not file_info or "path" not in file_info:
            logger.error(f"Cannot copy path: File info or path missing for file ID {file_id}.")
            return

        path_to_copy = file_info["path"]

        try:
            logger.debug(f"Copying path to clipboard: {path_to_copy}")
            # Access the Tkinter clipboard
            self.root.clipboard_clear() # Clear previous content
            self.root.clipboard_append(path_to_copy) # Append the new path
            self.root.update() # Process clipboard event immediately (might be needed on some systems)
            self.log_threadsafe(f"Copied path to clipboard: {os.path.basename(path_to_copy)}", "info")
        except tk.TclError as e:
            # This can happen if clipboard access fails (e.g., running headless without X server)
            logger.error(f"TclError accessing clipboard: {e}")
            messagebox.showerror("Clipboard Error", f"Could not access the system clipboard.\nError: {e}", parent=self.root)
        except Exception:
             logger.exception("Unexpected error copying path to clipboard.")
             messagebox.showerror("Clipboard Error", "An unexpected error occurred while copying the path.", parent=self.root)


    # --- Logging and Settings Methods ---

    def log_threadsafe(self, message: str, level: str = "info"):
        """Log a message using the standard logger and queue an update for the GUI log display."""
        # Get the numeric logging level
        level_num = getattr(logging, level.upper(), logging.INFO) # Default to INFO if level invalid

        # Log using the standard Python logger
        logger.log(level_num, message)

        # Format message for GUI display and queue it
        gui_msg = f"[{datetime.now():%H:%M:%S}] {level.upper()}: {message}"
        # Use the queue to ensure the GUI update happens in the main thread
        gui_queue.put(lambda: self._update_logs_text_gui(gui_msg))


    def _update_logs_text_gui(self, formatted_message: str):
        """Update the logs Text widget in the GUI (runs in the main GUI thread)."""
        # Check if the widget exists and the window is still alive
        if not self.root or not self.root.winfo_exists() or not hasattr(self, 'logs_text') or not self.logs_text.winfo_exists():
            # Don't try to update if GUI is gone
            return

        try:
            # Temporarily enable the widget to insert text
            self.logs_text.config(state=tk.NORMAL)
            # Insert the new message at the end
            self.logs_text.insert("end", formatted_message + "\n")

            # --- Optional: Limit the number of lines in the log display ---
            # Get current line count (this can be slow for very large text widgets)
            # index 'end-1c' gives the position of the last character
            # index 'end-2c' if the last char is \n
            # float(index) gives line number
            # Example: Keep max 1000 lines
            max_lines = 1000
            num_lines = int(float(self.logs_text.index('end-2c'))) # Get line number of second-to-last char
            if num_lines > max_lines:
                 # Delete lines from the beginning ('1.0') up to the calculated threshold
                 lines_to_delete = num_lines - max_lines
                 # '1.0' is the first line, first char. '{line}.0' is the start of a specific line.
                 self.logs_text.delete('1.0', f'{lines_to_delete + 1}.0')
            # -------------------------------------------------------------

            # Automatically scroll to the end to show the latest message
            self.logs_text.see("end")
            # Disable the widget again to make it read-only
            self.logs_text.config(state=tk.DISABLED)

        except tk.TclError as e:
             # Catch errors if the widget is destroyed between the check and the update
             logger.warning(f"TclError updating log GUI (widget likely destroyed): {e}")
        except Exception:
            # Catch any other unexpected errors during the GUI update
            logger.exception("Unexpected error updating log GUI")


    def clear_logs(self):
        """Clear the content of the logs display Text widget."""
        if hasattr(self, 'logs_text') and self.logs_text.winfo_exists():
            try:
                logger.debug("Clearing GUI logs display.")
                # Enable, delete content, disable
                self.logs_text.config(state=tk.NORMAL)
                self.logs_text.delete(1.0, "end") # Delete from start (1.0) to end
                self.logs_text.config(state=tk.DISABLED)
                # Log the action itself (using the threadsafe method)
                self.log_threadsafe("GUI Logs display cleared.", "info")
            except tk.TclError as e:
                 logger.error(f"TclError clearing logs GUI: {e}")
            except Exception:
                 logger.exception("Unexpected error clearing logs GUI")
        else:
             logger.warning("Clear logs called, but logs_text widget not found or destroyed.")


    def change_log_level(self, event=None): # Triggered by Combobox selection
        """Change the application's runtime logging level."""
        if not hasattr(self, 'log_level_var'): return # Safety check

        level_name = self.log_level_var.get()
        level_num = logging.getLevelName(level_name) # Convert name (e.g., "DEBUG") to number (e.g., 10)

        if isinstance(level_num, int):
            try:
                 # Set level on the root logger affects all handlers unless they have their own level set higher
                 logging.getLogger().setLevel(level_num)
                 # Optionally set level on specific handlers if needed (e.g., keep file log DEBUG, console INFO)
                 # for handler in logging.getLogger().handlers:
                 #    handler.setLevel(level_num) # Sets all handlers to the same level

                 logger.info(f"Logging level changed to {level_name} ({level_num})") # Log the change itself
                 # Use threadsafe log to also update GUI log
                 self.log_threadsafe(f"Runtime logging level set to: {level_name}", "warning") # Use warning to make it visible
            except Exception:
                 logger.exception(f"Failed to apply logging level {level_name}")
        else:
            # Should not happen with read-only Combobox, but good practice
            logger.error(f"Invalid log level selected: {level_name}")


    def browse_download_dir(self):
        """Open a directory selection dialog for the 'Accepted Uploads Directory' setting."""
        if not hasattr(self, 'dir_var'):
             logger.error("Cannot browse: dir_var (StringVar for download directory) not found.")
             return

        current_dir = self.dir_var.get()
        # Start browsing from the currently set directory if it's valid, otherwise start from user's home/Downloads
        initial_dir = current_dir if os.path.isdir(current_dir) else os.path.join(os.path.expanduser("~"), "Downloads")

        # Open the directory selection dialog
        folder_path = filedialog.askdirectory(
            parent=self.root,
            title="Select Directory for Accepted Receives",
            initialdir=initial_dir,
            mustexist=True # Require the selected directory to exist
        )

        # If the user selected a directory (didn't cancel)
        if folder_path and isinstance(folder_path, str):
            logger.debug(f"User selected accepted receives directory: {folder_path}")
            # Update the StringVar, which automatically updates the Entry widget
            self.dir_var.set(folder_path)


    def save_settings(self):
        """Save the current settings from the GUI to the JSON file and apply them."""
        logger.info("Attempting to save settings...")

        if not all(hasattr(self, attr) for attr in ['settings', 'dir_var', 'font_family_var', 'theme_var', 'font_size_spinbox']):
             logger.critical("Cannot save settings: One or more required GUI variable attributes are missing.")
             messagebox.showerror("Save Error", "Internal error: Cannot access all settings fields.", parent=self.root)
             return

        # Create a temporary copy to modify and validate
        settings_to_save = self.settings.copy()

        # --- Get values from GUI elements ---
        new_download_dir = self.dir_var.get()
        new_font_family = self.font_family_var.get()
        new_theme = self.theme_var.get()
        try:
            # Validate font size is integer within reasonable range
            new_font_size = int(self.font_size_spinbox.get())
            if not (8 <= new_font_size <= 36):
                 logger.warning(f"Invalid font size '{new_font_size}', reverting to default {DEFAULT_SETTINGS['font_size']}.")
                 new_font_size = DEFAULT_SETTINGS["font_size"]
                 self.font_size_var.set(new_font_size) # Update GUI Spinbox value
        except (ValueError, tk.TclError):
            logger.warning(f"Invalid font size input, reverting to default {DEFAULT_SETTINGS['font_size']}.")
            new_font_size = DEFAULT_SETTINGS["font_size"]
            self.font_size_var.set(new_font_size) # Update GUI Spinbox value

        # --- Validate Accepted Receives Directory ---
        validated_download_dir = None
        if new_download_dir and isinstance(new_download_dir, str):
            try:
                # Check if it exists, try to create if not
                if not os.path.isdir(new_download_dir):
                    logger.warning(f"Accepted receives directory '{new_download_dir}' does not exist. Attempting to create.")
                    try:
                         os.makedirs(new_download_dir, exist_ok=True)
                         logger.info(f"Successfully created accepted receives directory: {new_download_dir}")
                         validated_download_dir = new_download_dir
                    except OSError as e_create:
                         logger.error(f"Cannot create accepted receives directory '{new_download_dir}': {e_create}")
                         messagebox.showerror("Settings Error", f"Invalid Directory:\n'{new_download_dir}'\n\nCould not create directory.\nError: {e_create}\nPlease choose or create a valid directory.", parent=self.root)
                    except Exception as e_create_other: # Catch other potential errors
                         logger.error(f"Unexpected error creating directory '{new_download_dir}': {e_create_other}")
                         messagebox.showerror("Settings Error", f"Error creating directory:\n'{new_download_dir}'\n\n{e_create_other}", parent=self.root)
                else:
                     # Directory exists, check if writable (basic check)
                     if os.access(new_download_dir, os.W_OK):
                          logger.debug(f"Accepted receives directory is valid: {new_download_dir}")
                          validated_download_dir = new_download_dir
                     else:
                          logger.error(f"Accepted receives directory '{new_download_dir}' exists but is not writable.")
                          messagebox.showerror("Settings Error", f"Directory Not Writable:\n'{new_download_dir}'\n\nPlease choose a directory where the application can save files.", parent=self.root)

            except Exception as e_val: # Catch errors during validation (e.g., path too long on Windows)
                logger.error(f"Error validating directory '{new_download_dir}': {e_val}")
                messagebox.showerror("Settings Error", f"Error validating directory path:\n'{new_download_dir}'\n\nError: {e_val}", parent=self.root)
        else:
            # Path was empty or not a string
            logger.error(f"Invalid value provided for accepted receives directory: '{new_download_dir}'")
            messagebox.showerror("Settings Error", "Accepted receives directory path is missing or invalid.", parent=self.root)

        # If validation failed, revert to default and update GUI
        if validated_download_dir is None:
            validated_download_dir = DEFAULT_SETTINGS["download_dir"]
            self.dir_var.set(validated_download_dir) # Update GUI Entry widget
            logger.warning(f"Reverted accepted receives directory to default: {validated_download_dir}")
            # Prevent saving if the crucial directory setting failed validation
            # messagebox.showinfo("Settings Not Saved", "Settings were not saved due to the invalid directory.", parent=self.root)
            # return # Or allow saving other settings? For now, let's allow saving others.

        # --- Update settings_to_save dictionary ---
        settings_to_save["download_dir"] = validated_download_dir
        settings_to_save["font_family"] = new_font_family
        settings_to_save["theme"] = new_theme
        settings_to_save["font_size"] = new_font_size

        # --- Save to JSON file ---
        try:
            # Ensure parent directory for settings file exists
            os.makedirs(os.path.dirname(SETTINGS_FILE_PATH), exist_ok=True)

            with open(SETTINGS_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(settings_to_save, f, indent=4, ensure_ascii=False)

            # Update the application's active settings
            self.settings = settings_to_save
            self.log_threadsafe("Settings saved successfully.", "info")
            messagebox.showinfo("Settings Saved", "Settings have been saved and applied.", parent=self.root)

            # --- Apply Changes Immediately ---
            self.apply_theme() # Re-apply theme and font

        except IOError as e_io:
            logger.exception("IOError writing settings file")
            messagebox.showerror("Settings Save Error", f"Could not write settings file:\n{SETTINGS_FILE_PATH}\n\nError: {e_io}", parent=self.root)
        except Exception as e_json:
            logger.exception("Error serializing or writing settings JSON")
            messagebox.showerror("Settings Save Error", f"Could not save settings due to an unexpected error:\n{e_json}", parent=self.root)


    def load_settings(self) -> Dict[str, Any]:
        """Load settings from the JSON file, merging with defaults for missing keys."""
        # Start with default settings
        loaded_settings = DEFAULT_SETTINGS.copy()

        if os.path.exists(SETTINGS_FILE_PATH):
            logger.debug(f"Loading settings from: {SETTINGS_FILE_PATH}")
            try:
                with open(SETTINGS_FILE_PATH, 'r', encoding='utf-8') as f:
                    from_file = json.load(f)

                # Validate loaded data types (simple checks)
                validated_update = {}
                for key, default_value in DEFAULT_SETTINGS.items():
                    loaded_value = from_file.get(key)
                    if loaded_value is not None and isinstance(loaded_value, type(default_value)):
                         validated_update[key] = loaded_value
                    elif loaded_value is not None:
                         logger.warning(f"Settings file: Type mismatch for key '{key}'. Expected {type(default_value)}, got {type(loaded_value)}. Using default.")
                    # If key missing in file, default is already in loaded_settings

                # Update defaults with validated values from file
                loaded_settings.update(validated_update)
                logger.info(f"Settings successfully loaded and merged from {SETTINGS_FILE_PATH}.")

            except json.JSONDecodeError as e_json:
                logger.error(f"Error decoding settings file '{SETTINGS_FILE_PATH}': {e_json}. Using default settings.")
                # Keep loaded_settings as defaults
            except IOError as e_io:
                 logger.error(f"IOError reading settings file '{SETTINGS_FILE_PATH}': {e_io}. Using default settings.")
                 # Keep loaded_settings as defaults
            except Exception:
                logger.exception(f"Unexpected error loading settings from '{SETTINGS_FILE_PATH}'. Using default settings.")
                # Keep loaded_settings as defaults
        else:
            logger.info("Settings file not found. Using default settings.")
            # Maybe save defaults on first run? Optional.
            # try:
            #     with open(SETTINGS_FILE_PATH, 'w', encoding='utf-8') as f:
            #         json.dump(loaded_settings, f, indent=4, ensure_ascii=False)
            #     logger.info("Saved default settings to new file.")
            # except Exception: logger.exception("Could not save default settings.")

        # Ensure essential settings have *some* value after loading/merging
        loaded_settings.setdefault("download_dir", DEFAULT_SETTINGS["download_dir"])
        loaded_settings.setdefault("font_family", DEFAULT_SETTINGS["font_family"])
        loaded_settings.setdefault("font_size", DEFAULT_SETTINGS["font_size"])
        loaded_settings.setdefault("theme", DEFAULT_SETTINGS["theme"])

        return loaded_settings


    def apply_theme(self):
        """Apply the theme and font settings loaded in `self.settings` to the GUI."""
        if not self.root or not self.root.winfo_exists():
            logger.warning("Apply theme called but root window is not available.")
            return

        theme_name = self.settings.get("theme", DEFAULT_SETTINGS["theme"])
        font_family = self.settings.get("font_family", DEFAULT_SETTINGS["font_family"])
        font_size = self.settings.get("font_size", DEFAULT_SETTINGS["font_size"])
        font_tuple = (font_family, font_size)
        logger.info(f"Applying Theme: '{theme_name}', Font: {font_tuple}")

        # --- Apply Theme ---
        theme_applied = False
        try:
            # Priority 1: ThemedTk if available and active
            if TTKTHEMES_AVAILABLE and isinstance(self.root, ThemedTk):
                available_themes = self.root.get_themes()
                if theme_name in available_themes:
                    self.root.set_theme(theme_name)
                    logger.debug(f"Applied theme '{theme_name}' via ThemedTk.")
                    theme_applied = True
                else:
                    # Fallback for ThemedTk
                    fallback = "adapta" if "adapta" in available_themes else ("clam" if "clam" in available_themes else None)
                    if fallback:
                        self.root.set_theme(fallback)
                        self.settings["theme"] = fallback # Update setting to reflect actual theme
                        if hasattr(self, 'theme_var'): self.theme_var.set(fallback) # Update GUI combo
                        logger.warning(f"Theme '{theme_name}' not found in ThemedTk themes. Applied fallback '{fallback}'.")
                        theme_applied = True
                    else:
                        logger.error("Could not apply requested theme or any fallback theme via ThemedTk.")

            # Priority 2: Standard ttk.Style if ThemedTk not used or failed
            if not theme_applied and hasattr(self, 'style') and isinstance(self.style, ttk.Style):
                available_themes = self.style.theme_names()
                if theme_name in available_themes:
                    self.style.theme_use(theme_name)
                    logger.debug(f"Applied theme '{theme_name}' via ttk.Style.")
                    theme_applied = True
                else:
                    # Fallback for standard ttk
                    fallback = "clam" if "clam" in available_themes else ("vista" if "vista" in available_themes else ("aqua" if "aqua" in available_themes else "default"))
                    if fallback in available_themes:
                         self.style.theme_use(fallback)
                         self.settings["theme"] = fallback # Update setting
                         if hasattr(self, 'theme_var'): self.theme_var.set(fallback) # Update GUI
                         logger.warning(f"Theme '{theme_name}' not found in standard ttk themes. Applied fallback '{fallback}'.")
                         theme_applied = True
                    else:
                         logger.error("Could not apply requested theme or any fallback theme via ttk.Style.")

            if not theme_applied:
                logger.error(f"Failed to apply theme '{theme_name}' using any available method.")

        except tk.TclError as e_theme:
             logger.error(f"TclError applying theme '{theme_name}': {e_theme}")
        except Exception:
            logger.exception(f"Unexpected error applying theme '{theme_name}'")

        # --- Apply Font ---
        try:
            logger.debug(f"Applying global font settings: {font_tuple}")
            # Set default fonts used by Tk/ttk widgets
            # Using option_add is generally discouraged for ttk themes, but setting named fonts is better
            # font.nametofont("TkDefaultFont").configure(family=font_family, size=font_size)
            # font.nametofont("TkTextFont").configure(family=font_family, size=font_size) # For Text widgets
            # font.nametofont("TkFixedFont").configure(family=font_family, size=font_size) # For fixed-width (less common impact)
            # font.nametofont("TkMenuFont").configure(family=font_family, size=font_size)  # For menus

            # More reliable: Configure ttk styles globally
            self.style.configure(".", font=font_tuple) # Configure default style for all ttk widgets
            self.style.configure("TButton", font=font_tuple)
            self.style.configure("TLabel", font=font_tuple)
            self.style.configure("TEntry", font=font_tuple)
            self.style.configure("TCombobox", font=font_tuple)
            self.style.configure("TNotebook.Tab", font=font_tuple)
            self.style.configure("TLabelframe.Label", font=font_tuple)
            self.style.configure("Treeview", font=font_tuple)
            self.style.configure("Treeview.Heading", font=(font_family, font_size, 'bold')) # Make headings bold

            # Update specific Tk widgets (like Text) directly
            if hasattr(self, 'logs_text') and self.logs_text.winfo_exists():
                self.logs_text.configure(font=font_tuple)

            # Re-configure styles that depend on font (like URL hover)
            self.style.configure("URLHover.TLabel", font=(font_family, font_size, "underline"))
            self.style.configure("URL.TLabel", font=font_tuple) # Ensure base URL style also updated
            # Ensure status label uses updated font
            status_color = self.style.lookup("Status.TLabel", "foreground") # Get current color
            self.style.configure("Status.TLabel", font=font_tuple, foreground=status_color)

            logger.info(f"Applied font settings globally: {font_tuple}")
        except tk.TclError as e_font:
             logger.error(f"TclError applying font {font_tuple}: {e_font}")
        except Exception:
            logger.exception("Unexpected error applying font settings")


    # --- Utility and Lifecycle Methods ---

    def get_local_ip(self) -> str:
        """Tries multiple methods to get a non-loopback, likely LAN IP address."""
        logger.debug("Attempting to determine local IP address...")
        candidate_ips = []

        # Method 1: Socket connection to external target (doesn't actually send data)
        # This often finds the IP associated with the default route.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.1) # Don't wait long
                # Use a reliable external target (doesn't need to be reachable)
                s.connect(("8.8.8.8", 80)) # Google DNS
                ip = s.getsockname()[0]
                if ip and ip not in candidate_ips: candidate_ips.append(ip)
                logger.debug(f"IP from outgoing socket: {ip}")
        except Exception as e:
            logger.debug(f"Could not get IP via outgoing socket: {e}")

        # Method 2: Using hostname and getaddrinfo
        # This can return multiple IPs, including loopback.
        try:
            hostname = socket.gethostname()
            logger.debug(f"Hostname: {hostname}")
            # AF_INET limits to IPv4
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for item in addr_info:
                ip = item[4][0] # Address is in the 5th element, first part
                if ip and ip not in candidate_ips: candidate_ips.append(ip)
            logger.debug(f"IPs from getaddrinfo(hostname): {[item[4][0] for item in addr_info]}")
        except Exception as e:
            logger.debug(f"Could not get IP via getaddrinfo(hostname): {e}")

        # Method 3: getaddrinfo with AI_PASSIVE (might list IPs bound to interfaces)
        # Less reliable across platforms, but worth a try.
        try:
            addr_info_passive = socket.getaddrinfo(None, 0, socket.AF_INET, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
            for item in addr_info_passive:
                ip = item[4][0]
                if ip and ip not in candidate_ips: candidate_ips.append(ip)
            logger.debug(f"IPs from getaddrinfo(passive): {[item[4][0] for item in addr_info_passive]}")
        except Exception as e:
             logger.debug(f"Could not get IP via getaddrinfo(passive): {e}")


        # --- Filtering and Prioritization ---
        logger.debug(f"Candidate IPs found: {candidate_ips}")
        # 1. Remove loopback and 'any' addresses
        valid_ips = [ip for ip in candidate_ips if ip and ip != "127.0.0.1" and not ip.startswith("0.")]
        # 2. Prioritize common private LAN ranges
        preferred_ips = [ip for ip in valid_ips if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31]
        # 3. Prioritize other potential LAN IPs (e.g., 169.254. link-local, though less ideal)
        other_lan_ips = [ip for ip in valid_ips if ip not in preferred_ips]

        final_ip = "127.0.0.1" # Default fallback
        if preferred_ips:
            final_ip = preferred_ips[0] # Take the first preferred private IP
            logger.debug(f"Selected preferred private IP: {final_ip}")
        elif other_lan_ips:
            final_ip = other_lan_ips[0] # Take the first non-loopback, non-private IP
            logger.debug(f"Selected other valid IP: {final_ip}")
        else:
             # If only loopback or no IPs found, use loopback
             logger.warning("No suitable non-loopback IP address found. Using 127.0.0.1.")
             final_ip = "127.0.0.1"

        logger.info(f"Determined local IP address for use: {final_ip}")
        return final_ip


    def process_gui_queue(self):
        """Process items from the thread-safe GUI update queue."""
        try:
            # Process all currently available items in the queue without blocking
            while True: # Loop until queue is empty
                # Get item without waiting
                callback = gui_queue.get_nowait()
                try:
                     # Execute the callback function (which contains the GUI update logic)
                     callback()
                except Exception:
                     # Log errors happening inside the queued callback
                     logger.exception("Error executing callback from GUI queue:")
                finally:
                     # Mark task as done even if callback failed
                     gui_queue.task_done()
        except QueueEmpty:
            # Queue is empty, nothing more to process right now
            pass
        except Exception:
            # Catch errors related to the queue itself (less likely)
            logger.exception("Unexpected error processing GUI queue:")
        finally:
            # Reschedule this method to run again after a short delay
            # This creates a loop that continuously checks the queue
            if self.root and self.root.winfo_exists():
                self.root.after(100, self.process_gui_queue) # Check again in 100ms


    def on_close(self):
        """Handle the application window close event (WM_DELETE_WINDOW)."""
        logger.info("Application close requested...")

        confirm_msg = "Are you sure you want to exit the File Transfer App?"
        ask_confirm = False # Only ask if necessary

        # Check if server is running
        if self.is_server_running:
            confirm_msg += "\n\nThe server is currently running and will be stopped."
            ask_confirm = True

        # Check for pending receives
        if self.pending_uploads:
            num_pending = len(self.pending_uploads)
            confirm_msg += f"\n\nThere {'is' if num_pending == 1 else 'are'} {num_pending} pending upload(s) that will be rejected and removed."
            ask_confirm = True

        # Show confirmation dialog only if server running OR pending receives exist
        if ask_confirm:
            user_confirm = messagebox.askyesno("Confirm Exit", confirm_msg, icon='warning', parent=self.root)
            if not user_confirm:
                logger.info("User cancelled application exit.")
                return # Abort the closing process

        logger.info("Proceeding with application shutdown...")

        # --- Stop Server (if running) ---
        if self.is_server_running and self.server:
            self.log_threadsafe("Stopping server...", "info")
            # Initiate shutdown (runs in background thread)
            self.stop_server()
            # Wait briefly for the shutdown thread to complete
            shutdown_thread_ref = getattr(self, '_shutdown_thread_ref', None) # Assuming stop_server stores ref if needed, else use server_thread
            active_shutdown_thread = self.server_thread # More likely ref
            if active_shutdown_thread and active_shutdown_thread.is_alive():
                logger.debug("Waiting up to 1 second for server shutdown thread...")
                active_shutdown_thread.join(timeout=1.0)
                if active_shutdown_thread.is_alive():
                    logger.warning("Server shutdown thread did not complete within the timeout period.")
            else:
                 logger.debug("Server shutdown thread already finished or wasn't running.")
        elif self.is_server_running:
             logger.warning("Server was marked as running, but server object was None during shutdown.")

        # --- Clean up Temporary Upload Directory ---
        logger.info(f"Cleaning up temporary upload directory contents: {TEMP_DIR}")
        try:
            if os.path.isdir(TEMP_DIR):
                items_removed = 0
                items_failed = 0
                for item_name in os.listdir(TEMP_DIR):
                    item_path = os.path.join(TEMP_DIR, item_name)
                    try:
                        if os.path.isfile(item_path) or os.path.islink(item_path):
                            os.unlink(item_path)
                            items_removed += 1
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path) # Recursively remove subdirectories
                            items_removed += 1
                    except Exception as e_rem:
                        logger.error(f"Error removing temporary item '{item_path}': {e_rem}")
                        items_failed += 1
                log_suffix = f"Removed {items_removed} items."
                if items_failed > 0: log_suffix += f" Failed to remove {items_failed} items."
                logger.info(f"Temporary directory cleanup finished. {log_suffix}")
            else:
                logger.debug("Temporary directory does not exist, no cleanup needed.")
        except Exception as e_clean:
            logger.error(f"Error during temporary directory cleanup process: {e_clean}")

        # --- Destroy GUI Window ---
        logger.info("Destroying main Tkinter window...")
        if self.root and self.root.winfo_exists():
            try:
                self.root.destroy()
                logger.debug("Root window destroyed.")
            except Exception:
                logger.exception("Error occurred while destroying the root window.")

        # --- Final Log and Exit ---
        logger.info("Shutdown sequence complete. Exiting application.")

        # Close stderr log file if it was opened
        global _stderr_log_file
        if _stderr_log_file:
            logger.debug("Closing stderr log file.")
            try:
                _stderr_log_file.close()
            except Exception: pass # Ignore errors closing log file

        # Force exit - helps ensure process terminates cleanly, especially if
        # non-daemon threads are lingering (though we try to avoid them).
        os._exit(0)


# ----------------------------------------
# --- Main Execution ---
# ----------------------------------------
def main():
    """Main function to initialize Tkinter, create the app instance, and run the main loop."""
    root = None # Initialize root to None for finally block safety
    app = None # Initialize app to None
    exit_code = 0 # Default exit code

    try:
        logger.info("Starting application main function...")

        # --- Initialize Tkinter Root Window ---
        # Use ThemedTk if available for better theme support
        if TTKTHEMES_AVAILABLE:
            logger.debug("Attempting to initialize with ThemedTk.")
            try:
                # Start with a basic theme, app will apply user's theme later
                root = ThemedTk(theme="clam") # Or another safe default like "arc"
                logger.info("Initialized with ThemedTk.")
            except Exception as e_theme_init:
                 logger.error(f"Failed to initialize ThemedTk: {e_theme_init}. Falling back to standard Tk.", exc_info=True)
                 # Fallback to standard Tk if ThemedTk fails
                 root = tk.Tk()
                 logger.info("Initialized with standard tk.Tk.")
        else:
            # If ttkthemes not installed, use standard Tk
            root = tk.Tk()
            logger.info("Initialized with standard tk.Tk (ttkthemes not available).")

        # --- Set Application Icon ---
        # Do this after root window exists
        set_app_icon(root)

        # --- Create Application Instance ---
        # This loads settings, initializes GUI components, etc.
        logger.debug("Creating FileTransferApp instance...")
        app = FileTransferApp(root) # Pass the created root window

        # --- Start Tkinter Main Event Loop ---
        logger.info("Starting Tkinter main loop (root.mainloop())...")
        root.mainloop()
        # Code execution resumes here after the window is closed (or root.destroy() is called)
        logger.info("Tkinter main loop finished.")

    except tk.TclError as e_tcl:
        # Catch critical Tcl errors, often fatal for GUI apps
        logger.critical(f"Fatal TclError during application startup or runtime: {e_tcl}", exc_info=True)
        # Try to show a message box if possible
        try: messagebox.showerror("Fatal Error", f"A critical error occurred:\n{e_tcl}\n\nApplication must exit.\nCheck logs: {log_file_path}")
        except: pass # Ignore if messagebox fails too
        print(f"FATAL TCL ERROR: {e_tcl}\nCheck log file: {log_file_path}", file=sys.stderr)
        exit_code = 1
    except Exception as e_main:
        # Catch any other unexpected errors during startup or main loop
        logger.critical(f"Unhandled exception in main function: {e_main}", exc_info=True)
        try: messagebox.showerror("Fatal Error", f"An unexpected error occurred:\n{e_main}\n\nApplication must exit.\nCheck logs: {log_file_path}")
        except: pass
        print(f"FATAL UNEXPECTED ERROR: {e_main}\nCheck log file: {log_file_path}", file=sys.stderr)
        exit_code = 1
    finally:
        # --- Cleanup ---
        logger.debug("Entering main() finally block for cleanup.")

        # Ensure server is stopped if app instance exists and server was running
        if app and app.is_server_running and app.server:
            logger.warning("Attempting emergency server shutdown in main finally block.")
            try:
                app.server.shutdown()
                app.server.server_close()
                logger.info("Emergency server shutdown completed.")
            except Exception as e_final_shutdown:
                logger.error(f"Error during emergency server shutdown: {e_final_shutdown}")

        # Ensure temporary directory is cleaned (redundant if on_close worked, but safe)
        if os.path.isdir(TEMP_DIR):
             logger.debug(f"Performing final cleanup of temp directory: {TEMP_DIR}")
             try:
                  # Simple removal attempt in final cleanup
                  shutil.rmtree(TEMP_DIR, ignore_errors=True)
             except Exception as e_final_clean:
                  logger.error(f"Error during final temp dir cleanup: {e_final_clean}")


        # Explicitly destroy window if it still exists (needed if mainloop exited via error)
        if root and root.winfo_exists():
            logger.debug("Destroying root window in main finally block.")
            try:
                root.destroy()
            except Exception as e_final_destroy:
                 logger.error(f"Error destroying root window in finally block: {e_final_destroy}")

        # Close stderr log file if it was opened
        global _stderr_log_file
        if _stderr_log_file:
            logger.debug("Closing stderr log file in main finally block.")
            try: _stderr_log_file.close()
            except: pass

        logger.info(f"Application exiting with code {exit_code}.")
        sys.exit(exit_code) # Exit with the determined code


def set_app_icon(root_window: tk.Tk):
    """Attempts to set the application icon based on available formats and platform."""
    logger.debug("Attempting to set application icon...")
    icon_base_name = "icon" # Base name without extension
    icon_set_success = False

    # --- Platform-specific Icon Setting ---
    # 1. Windows (.ico is preferred)
    if sys.platform == "win32":
        ico_path = os.path.join(SCRIPT_DIR, f"{icon_base_name}.ico")
        if os.path.exists(ico_path):
            try:
                root_window.iconbitmap(default=ico_path)
                logger.info(f"Set application icon using .ico (Windows): {ico_path}")
                icon_set_success = True
            except Exception as e_ico:
                logger.error(f"Error setting .ico icon: {e_ico}")
        else: logger.debug(f".ico not found at {ico_path}")

    # 2. Other platforms or fallback: Try .png (requires Pillow) then .gif (Tk built-in)
    if not icon_set_success:
        # Determine formats to try based on Pillow availability
        formats_to_try = []
        if PILLOW_AVAILABLE:
             formats_to_try.append(".png")
        formats_to_try.append(".gif") # Tk supports GIF natively

        for ext in formats_to_try:
            icon_path = os.path.join(SCRIPT_DIR, f"{icon_base_name}{ext}")
            if os.path.exists(icon_path):
                try:
                    img = None
                    logger.debug(f"Attempting to load icon: {icon_path}")
                    if ext == ".png" and PILLOW_AVAILABLE:
                        # Use Pillow and ImageTk for PNG
                        pil_image = Image.open(icon_path)
                        img = ImageTk.PhotoImage(pil_image)
                    elif ext == ".gif":
                        # Use Tk's PhotoImage for GIF
                        img = tk.PhotoImage(file=icon_path)

                    if img:
                        # Use iconphoto() which works on most platforms
                        root_window.iconphoto(True, img) # True: use as default icon
                        # --- IMPORTANT: Keep a reference! ---
                        # Store the image object on the root window itself to prevent
                        # it from being garbage collected by Python, which would make the icon disappear.
                        root_window.app_icon_reference = img
                        # ------------------------------------
                        logger.info(f"Set application icon using {ext} via iconphoto: {icon_path}")
                        icon_set_success = True
                        break # Stop after successfully setting an icon
                    else:
                         logger.debug(f"Image object was None after attempting load for {icon_path}")

                except Exception:
                    logger.exception(f"Failed to load or set icon '{icon_path}'")
            else:
                 logger.debug(f"Icon file {ext} not found at {icon_path}")

    if not icon_set_success:
        logger.warning(f"Could not find or set application icon (tried '{icon_base_name}.ico/png/gif'). Using default icon.")


# --- Entry Point Check ---
if __name__ == "__main__":
    # --- Create Placeholder HTML ---
    # Check if the HTML file exists, create a basic one if not.
    if not os.path.exists(HTML_FILE_PATH):
        logger.warning(f"'{HTML_FILE_NAME}' not found in script directory. Creating a placeholder file.")
        # HTML content with basic structure and JavaScript for fetching/uploading
        # Ensure JavaScript uses standard string concatenation or correctly escaped template literals if needed.
        # Using backticks within the JS is fine as long as the Python string containing it is well-formed.
        html_placeholder = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Transfer</title>
    <style>
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Fira Sans", "Droid Sans", "Helvetica Neue", sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: auto; background-color: #f8f9fa; color: #212529; }
        h1, h2 { color: #0056b3; border-bottom: 1px solid #dee2e6; padding-bottom: 5px; margin-bottom: 20px; }
        #fileList { list-style: none; padding: 0; }
        #fileList li { background-color: #fff; border: 1px solid #dee2e6; margin-bottom: 10px; padding: 12px 18px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        #fileList .file-info { flex-grow: 1; margin-right: 15px; word-break: break-all; } /* Allow long names to wrap */
        #fileList .file-name { font-weight: 500; }
        #fileList .file-size { color: #6c757d; font-size: 0.9em; white-space: nowrap; padding-left: 10px; }
        #fileList .download-button { text-decoration: none; background-color: #007bff; color: white; padding: 6px 12px; border-radius: 4px; transition: background-color 0.2s ease-in-out; white-space: nowrap; font-size: 0.95em; border: none; cursor: pointer; }
        #fileList .download-button:hover { background-color: #0056b3; }
        #uploadSection { margin-top: 40px; background-color: #fff; border: 1px solid #dee2e6; padding: 25px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        label { display: block; margin-bottom: 8px; font-weight: bold; }
        input[type="file"] { display: block; margin-bottom: 15px; padding: 8px; border: 1px solid #ced4da; border-radius: 4px; width: calc(100% - 18px); /* Account for padding */ }
        #uploadButton { background-color: #28a745; color: white; padding: 10px 18px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; transition: background-color 0.2s ease-in-out; }
        #uploadButton:hover { background-color: #218838; }
        #uploadButton:disabled { background-color: #6c757d; cursor: not-allowed; }
        #status { margin-top: 15px; font-weight: 600; padding: 10px; border-radius: 4px; display: none; /* Initially hidden */ }
        .status-success { color: #155724; background-color: #d4edda; border: 1px solid #c3e6cb; display: block !important; }
        .status-error { color: #721c24; background-color: #f8d7da; border: 1px solid #f5c6cb; display: block !important; }
        .status-info { color: #004085; background-color: #cce5ff; border: 1px solid #b8daff; display: block !important; }
        .progress-bar { width: 100%; background-color: #e9ecef; border-radius: 4px; margin-top: 10px; overflow: hidden; display: none; /* Initially hidden */ }
        .progress-bar-fill { height: 12px; background-color: #007bff; border-radius: 4px; width: 0%; text-align: center; color: white; font-size: 0.8em; line-height: 12px; transition: width 0.1s linear; }
    </style>
</head>
<body>
    <h1>File Transfer</h1>

    <h2>Available Files for Download</h2>
    <ul id="fileList">
        <li>Loading shared files...</li>
    </ul>

    <div id="uploadSection">
        <h2>Upload File</h2>
        <form id="uploadForm" enctype="multipart/form-data">
            <label for="fileInput">Choose file to upload:</label>
            <input type="file" id="fileInput" name="file" required>
            <button type="submit" id="uploadButton">Upload File</button>
        </form>
        <div class="progress-bar" id="progressBar"><div class="progress-bar-fill" id="progressBarFill">0%</div></div>
        <div id="status"></div>
    </div>

    <script>
        const fileList = document.getElementById('fileList');
        const uploadForm = document.getElementById('uploadForm');
        const fileInput = document.getElementById('fileInput');
        const statusDiv = document.getElementById('status');
        const progressBar = document.getElementById('progressBar');
        const progressBarFill = document.getElementById('progressBarFill');
        const uploadButton = document.getElementById('uploadButton');

        // Function to safely escape HTML content
        function escapeHTML(str) {
            if (str === null || str === undefined) return '';
            return String(str).replace(/[&<>"']/g, function(match) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[match];
            });
        }

        // Function to fetch and display the list of available files
        function fetchFiles() {
            fetch('/available-files')
                .then(response => {
                    if (!response.ok) {
                        return Promise.reject(`HTTP error ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(files => {
                    fileList.innerHTML = ''; // Clear current list
                    if (!Array.isArray(files)) {
                         throw new Error("Received invalid file list format from server.");
                    }
                    if (files.length === 0) {
                        fileList.innerHTML = '<li>No files are currently shared for download.</li>';
                        return;
                    }
                    // Sort files alphabetically by name (case-insensitive)
                    files.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));

                    files.forEach(file => {
                        const li = document.createElement('li');
                        // Use backticks for template literal - this is JavaScript, not Python
                        li.innerHTML = \`
                            <div class="file-info">
                                <span class="file-name">\${escapeHTML(file.name)}</span>
                                <span class="file-size">(\${escapeHTML(file.size)})</span>
                            </div>
                            <a href="/download/\${file.id}" class="download-button" download="\${escapeHTML(file.name)}">Download</a>
                        \`; // Note: download attribute suggests filename to browser
                        fileList.appendChild(li);
                    });
                })
                .catch(error => {
                    console.error('Error fetching file list:', error);
                    fileList.innerHTML = \`<li>Error loading files: \${escapeHTML(String(error))}. Please refresh the page or check server status.</li>\`;
                });
        }

        // Event listener for the upload form submission
        uploadForm.addEventListener('submit', (event) => {
            event.preventDefault(); // Prevent default form submission

            if (!fileInput.files || fileInput.files.length === 0) {
                statusDiv.textContent = 'Please select a file before uploading.';
                statusDiv.className = 'status-error'; // Add error class
                statusDiv.style.display = 'block';
                return;
            }

            statusDiv.textContent = 'Starting upload...';
            statusDiv.className = 'status-info'; // Use info class
            statusDiv.style.display = 'block';
            progressBar.style.display = 'block'; // Show progress bar
            progressBarFill.style.width = '0%';
            progressBarFill.textContent = '0%';
            uploadButton.disabled = true; // Disable button during upload

            const formData = new FormData();
            formData.append('file', fileInput.files[0]); // Get the selected file

            const xhr = new XMLHttpRequest();

            // Progress event listener
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentComplete = Math.round((e.loaded / e.total) * 100);
                    progressBarFill.style.width = percentComplete + '%';
                    progressBarFill.textContent = percentComplete + '%';
                } else {
                     progressBarFill.textContent = ''; // Indicate indeterminate progress if size unknown
                }
            });

            // Load event listener (upload finished)
            xhr.addEventListener('load', () => {
                progressBar.style.display = 'none'; // Hide progress bar on completion or error
                uploadButton.disabled = false; // Re-enable button

                if (xhr.status >= 200 && xhr.status < 300) {
                    // Success: Server received the file (likely pending approval)
                    statusDiv.textContent = \`Upload complete! \${escapeHTML(xhr.responseText)}\`; // Show server message
                    statusDiv.className = 'status-success';
                    fileInput.value = ''; // Clear the file input field
                    // DO NOT refresh the file list automatically here, as file is pending approval.
                } else {
                    // Error: Upload failed on the server side
                    statusDiv.textContent = \`Upload failed. Server responded with status \${xhr.status}. \${escapeHTML(xhr.responseText) || '(No additional details)'}\`;
                    statusDiv.className = 'status-error';
                }
                 statusDiv.style.display = 'block';
            });

            // Error event listener (network errors, etc.)
            xhr.addEventListener('error', () => {
                progressBar.style.display = 'none';
                uploadButton.disabled = false;
                statusDiv.textContent = 'Upload failed due to a network error or server connection issue.';
                statusDiv.className = 'status-error';
                statusDiv.style.display = 'block';
                console.error("XHR Upload Error", xhr.status, xhr.statusText);
            });

            // Abort event listener
            xhr.addEventListener('abort', () => {
                progressBar.style.display = 'none';
                uploadButton.disabled = false;
                statusDiv.textContent = 'Upload aborted by the user.';
                statusDiv.className = 'status-error'; // Treat abort as an error state visually
                 statusDiv.style.display = 'block';
            });

            // Configure and send the request
            xhr.open('POST', '/upload'); // POST request to the /upload endpoint
            xhr.send(formData); // Send the form data
        });

        // Initial fetch of available files when the page loads
        fetchFiles();

        // Optional: Set up polling to refresh the file list periodically
        // Consider using WebSockets for a more efficient real-time update later.
        // setInterval(fetchFiles, 30000); // Example: Refresh list every 30 seconds

    </script>
</body>
</html>"""
        try:
            with open(HTML_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write(html_placeholder)
            logger.info(f"Created placeholder HTML file at: {HTML_FILE_PATH}")
        except OSError as e:
            logger.error(f"Failed to create placeholder HTML file '{HTML_FILE_PATH}': {e}")
            # Application might still run but web UI will fail. Consider exiting?
            # For now, just log the error.

    # --- Run the Main Application ---
    main()
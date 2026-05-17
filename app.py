import os
import re
import json
import time
import logging
import secrets
import threading
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, abort
import yt_dlp

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

if os.name == 'nt':
    FFMPEG_DIR = r'C:\Users\Shashank\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1.1-full_build\bin'
    if os.path.isdir(FFMPEG_DIR) and FFMPEG_DIR not in os.environ.get('PATH', ''):
        os.environ['PATH'] = FFMPEG_DIR + os.pathsep + os.environ.get('PATH', '')

# --- YouTube Cookie Authentication ---
COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cookies.txt')
cookie_content = os.environ.get('YT_COOKIES', '')
if cookie_content:
    with open(COOKIE_FILE, 'w') as f:
        f.write(cookie_content)
    logger.info('YouTube cookies loaded from YT_COOKIES environment variable')
else:
    if os.path.isfile(COOKIE_FILE):
        logger.info('Using existing cookies.txt file')
    else:
        COOKIE_FILE = None
        logger.warning('No YouTube cookies configured. Bot detection may block requests from datacenter IPs. '
                       'Set the YT_COOKIES secret in your Hugging Face Space settings.')

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

DOWNLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloads')
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

progress_data = {}
progress_lock = threading.Lock()

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30
rate_limit_store = {}
rate_limit_lock = threading.Lock()

DOWNLOAD_LIMIT = 3
active_downloads = {}
active_downloads_lock = threading.Lock()

YOUTUBE_URL_PATTERN = re.compile(
    r'^https?://(www\.)?(youtube\.com|youtu\.be)/',
    re.IGNORECASE
)

ALLOWED_EXTENSIONS = {'mp4', 'webm', 'mkv', 'avi', 'mov', 'm4a', 'mp3', 'wav', 'flac', 'ogg', 'opus'}

def rate_limit(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or 'unknown'
        now = time.time()
        with rate_limit_lock:
            if ip not in rate_limit_store:
                rate_limit_store[ip] = []
            rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
            if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX:
                logger.warning(f'Rate limit exceeded for {ip}')
                return jsonify({'error': 'Too many requests. Please slow down.'}), 429
            rate_limit_store[ip].append(now)
        return f(*args, **kwargs)
    return wrapper

def require_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.content_type is None or 'application/json' not in request.content_type:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        return f(*args, **kwargs)
    return wrapper

def validate_youtube_url(url):
    if not url or len(url) > 2048:
        return False
    return bool(YOUTUBE_URL_PATTERN.match(url))

def sanitize_filename(filename):
    return re.sub(r'[\\/*?:"<>|]', '', filename)

def is_safe_path(basedir, path):
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return abs_path.startswith(os.path.abspath(basedir))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-ancestors 'self' https://huggingface.co https://*.hf.space; "
        "object-src 'none'"
    )
    if 'X-Forwarded-Proto' in request.headers and request.headers['X-Forwarded-Proto'] == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def progress_hook(d):
    if d['status'] == 'downloading':
        video_id = d.get('info_dict', {}).get('id', 'unknown')
        total = d.get('total_bytes') or d.get('total_bytes_estimate', 0)
        downloaded = d.get('downloaded_bytes', 0)
        if total > 0:
            percent = round((downloaded / total) * 100, 1)
            speed = d.get('speed', 0)
            speed_str = f"{speed / 1024 / 1024:.1f} MB/s" if speed else "N/A"
            eta = d.get('eta', 0)
            eta_str = f"{eta}s" if eta else "N/A"
            with progress_lock:
                progress_data[video_id] = {
                    'percent': percent,
                    'speed': speed_str,
                    'eta': eta_str,
                    'status': 'downloading'
                }
    elif d['status'] == 'finished':
        video_id = d.get('info_dict', {}).get('id', 'unknown')
        with progress_lock:
            progress_data[video_id] = {'percent': 100, 'status': 'finished'}

@app.route('/robots.txt')
def robots_txt():
    base = request.url_root.rstrip('/')
    sitemap_url = f'{base}/sitemap.xml'
    return f"""User-agent: *
Allow: /
Sitemap: {sitemap_url}
""", 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base = request.url_root.rstrip('/')
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{base}/</loc>
    <lastmod>2026-05-17</lastmod>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
""", 200, {'Content-Type': 'application/xml'}

@app.route('/')
def index():
    base_url = request.url_root.rstrip('/')
    return render_template('index.html', base_url=base_url)

@app.route('/info', methods=['POST'])
@rate_limit
@require_json
def get_info():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not validate_youtube_url(url):
        return jsonify({'error': 'Invalid YouTube URL'}), 400

    try:
        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'noplaylist': True,
            'extract_flat': False,
            'socket_timeout': 60,
            'retries': 5,
            'source_address': '0.0.0.0',
            'extractor_args': {'youtube': {'player_client': ['mweb', 'ios']}},
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
        }
        if COOKIE_FILE:
            ydl_opts['cookiefile'] = COOKIE_FILE
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)

        formats = []
        seen = set()
        for f in info.get('formats', []):
            format_id = f.get('format_id', '')
            ext = f.get('ext', '')
            vcodec = f.get('vcodec', 'none')
            acodec = f.get('acodec', 'none')
            height = f.get('height', 0)
            filesize = f.get('filesize') or f.get('filesize_approx', 0)
            tbr = f.get('tbr', 0)

            has_video = vcodec != 'none'
            has_audio = acodec != 'none'

            if not has_video and not has_audio:
                continue

            if has_video:
                has_audio_flag = '1' if has_audio else '0'
                key = f"v_{ext}_{height}_{has_audio_flag}"
            else:
                bucket = round(tbr / 20) * 20 if tbr else 0
                key = f"a_{ext}_{bucket}"
            if key in seen:
                continue
            seen.add(key)

            size_str = ''
            if filesize:
                if filesize > 1e9:
                    size_str = f"{filesize / 1e9:.1f} GB"
                elif filesize > 1e6:
                    size_str = f"{filesize / 1e6:.1f} MB"
                else:
                    size_str = f"{filesize / 1e3:.0f} KB"

            if has_audio and not has_video:
                tbr_str = f"{round(tbr)} kbps" if tbr else ""
                label = f"Audio ({ext.upper()})"
                if tbr_str:
                    label += f" - {tbr_str}"
                if size_str:
                    label += f" [{size_str}]"
            else:
                label_parts = []
                if has_video:
                    label_parts.append(f"{height}p" if height else "Video")
                if has_audio:
                    label_parts.append("Audio")
                label = f"{' + '.join(label_parts)} - {ext.upper()}"
                if height:
                    label = f"{height}p - {ext.upper()}"
                if size_str:
                    label += f" [{size_str}]"

            formats.append({
                'format_id': format_id,
                'ext': ext,
                'height': height,
                'filesize': size_str,
                'tbr': round(tbr, 1) if tbr else 0,
                'label': label,
                'has_video': has_video,
                'has_audio': has_audio,
            })

        best_qualities = [f for f in formats if f['has_video'] and f['has_audio']]
        best_video_only = [f for f in formats if f['has_video'] and not f['has_audio']]
        audio_formats = [f for f in formats if not f['has_video'] and f['has_audio']]

        return jsonify({
            'title': info.get('title', 'Unknown'),
            'thumbnail': info.get('thumbnail', ''),
            'duration': info.get('duration', 0),
            'channel': info.get('channel', info.get('uploader', 'Unknown')),
            'formats': formats,
            'best_qualities': best_qualities,
            'best_video_only': best_video_only,
            'audio_formats': audio_formats
        })

    except yt_dlp.utils.DownloadError as e:
        logger.warning(f'DownloadError for {url}: {e}')
        return jsonify({'error': f'Failed to fetch video: {e}'}), 400
    except Exception as e:
        logger.error(f'Info error for {url}: {e}')
        return jsonify({'error': f'An error occurred: {e}'}), 500

@app.route('/download', methods=['POST'])
@rate_limit
@require_json
def download():
    url = request.json.get('url', '').strip()
    format_id = str(request.json.get('format_id', ''))
    download_type = request.json.get('type', 'video')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not validate_youtube_url(url):
        return jsonify({'error': 'Invalid YouTube URL'}), 400
    if download_type not in ('video', 'audio'):
        return jsonify({'error': 'Invalid download type'}), 400
    if not format_id or not re.match(r'^[\w.+]+$', format_id):
        return jsonify({'error': 'Invalid format ID'}), 400

    ip = request.remote_addr or 'unknown'
    with active_downloads_lock:
        active_count = sum(1 for v in active_downloads.values() if v == ip)
        if active_count >= DOWNLOAD_LIMIT:
            return jsonify({'error': f'Maximum {DOWNLOAD_LIMIT} concurrent downloads allowed. Wait for current downloads to finish.'}), 429

    try:
        base_opts = {
            'quiet': True,
            'no_warnings': True,
            'noplaylist': True,
            'socket_timeout': 60,
            'retries': 5,
            'source_address': '0.0.0.0',
            'extractor_args': {'youtube': {'player_client': ['mweb', 'ios']}},
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
        }
        if COOKIE_FILE:
            base_opts['cookiefile'] = COOKIE_FILE
        with yt_dlp.YoutubeDL(base_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            video_id = info.get('id', 'unknown')

        output_template = os.path.join(DOWNLOAD_FOLDER, '%(title)s.%(ext)s')

        selected_format = None
        for f in info.get('formats', []):
            if f.get('format_id') == format_id:
                selected_format = f
                break

        if format_id and selected_format:
            has_video = selected_format.get('vcodec', 'none') != 'none'
            has_audio = selected_format.get('acodec', 'none') != 'none'
            if has_video and not has_audio:
                video_ext = selected_format.get('ext', 'mp4')
                compatible_audio_exts = ['m4a', 'mp4'] if video_ext == 'mp4' else [video_ext]
                best_audio = None
                for af in info.get('formats', []):
                    if af.get('acodec', 'none') != 'none' and af.get('vcodec', 'none') == 'none':
                        if af.get('ext') in compatible_audio_exts:
                            if best_audio is None or (af.get('tbr') or 0) > (best_audio.get('tbr') or 0):
                                best_audio = af
                if best_audio is None:
                    for af in info.get('formats', []):
                        if af.get('acodec', 'none') != 'none' and af.get('vcodec', 'none') == 'none':
                            if best_audio is None or (af.get('tbr') or 0) > (best_audio.get('tbr') or 0):
                                best_audio = af
                if best_audio:
                    fmt = f'{format_id}+{best_audio["format_id"]}'
                else:
                    fmt = format_id
            else:
                fmt = format_id
        else:
            fmt = 'bestvideo+bestaudio/best'

        ydl_opts = {
            'outtmpl': output_template,
            'progress_hooks': [progress_hook],
            'quiet': True,
            'no_warnings': True,
            'noplaylist': True,
            'format': fmt,
            'merge_output_format': 'mp4',
            'postprocessor_args': ['-c', 'copy'],
            'socket_timeout': 60,
            'retries': 5,
            'fragment_retries': 5,
            'source_address': '0.0.0.0',
            'extractor_args': {'youtube': {'player_client': ['mweb', 'ios']}},
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
        }
        if COOKIE_FILE:
            ydl_opts['cookiefile'] = COOKIE_FILE

        if download_type == 'audio':
            ydl_opts['format'] = 'bestaudio/best'
            ydl_opts['postprocessors'] = [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }]
            ydl_opts['outtmpl'] = os.path.join(DOWNLOAD_FOLDER, '%(title)s.%(ext)s')

        def download_video():
            with active_downloads_lock:
                active_downloads[threading.get_ident()] = ip
            try:
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    ydl.download([url])
                files = [f for f in os.listdir(DOWNLOAD_FOLDER)
                         if os.path.isfile(os.path.join(DOWNLOAD_FOLDER, f))]
                filename = ''
                if files:
                    files_with_path = [os.path.join(DOWNLOAD_FOLDER, f) for f in files]
                    latest = max(files_with_path, key=os.path.getctime)
                    filename = os.path.basename(latest)
                with progress_lock:
                    progress_data[video_id] = {'percent': 100, 'status': 'completed', 'filename': filename}
            except Exception as e:
                logger.error(f'Download failed for {video_id}: {e}')
                with progress_lock:
                    progress_data[video_id] = {'percent': 0, 'status': 'error', 'error': 'Download failed. Please try again.'}
            finally:
                with active_downloads_lock:
                    tid = threading.get_ident()
                    if tid in active_downloads:
                        del active_downloads[tid]

        thread = threading.Thread(target=download_video, daemon=True)
        thread.start()

        with active_downloads_lock:
            active_downloads[thread.ident] = ip

        return jsonify({
            'success': True,
            'video_id': video_id,
            'message': 'Download started'
        })

    except Exception as e:
        logger.error(f'Download error: {e}')
        return jsonify({'error': 'An error occurred while starting the download.'}), 500

@app.route('/progress/<video_id>', methods=['GET'])
@rate_limit
def get_progress(video_id):
    if not re.match(r'^[\w\-]+$', video_id):
        return jsonify({'error': 'Invalid video ID'}), 400
    with progress_lock:
        data = progress_data.get(video_id, {'percent': 0, 'status': 'starting'})
    return jsonify(data)

@app.route('/downloads/<path:filename>')
def download_file(filename):
    if not is_safe_path(DOWNLOAD_FOLDER, filename):
        return abort(404)
    if not os.path.isfile(os.path.join(DOWNLOAD_FOLDER, filename)):
        return abort(404)
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    if ext and ext not in ALLOWED_EXTENSIONS:
        return abort(404)
    safe_name = os.path.basename(filename)
    return send_file(
        os.path.join(DOWNLOAD_FOLDER, filename),
        as_attachment=True,
        download_name=safe_name
    )

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'error': 'Request body too large.'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found.'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error.'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f'Starting YouTube Downloader on port {port}')
    app.run(host='0.0.0.0', port=port)

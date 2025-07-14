from flask import Flask, request, jsonify
import logging
import sqlite3
import re
import os
from datetime import datetime, timezone
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# This is the code for a simple Klink server. Future versions should support more professional databases and multi-threaded servers.

# Set up logging to show INFO messages in console
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

DATABASE = 'klink.db'

# --- EMAIL REGEX FOR VALIDATION ---
# A simple regex to validate email format.
EMAIL_REGEX = re.compile(r'[^@]+@[^@]+\.[^@]+')

# Use a reusable and thread-safe connection function
def get_db_connection():
    return sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # ### ENDRING HER: Lagt til 'owner' kolonne i 'archives' tabellen ###
        cursor.execute('''CREATE TABLE IF NOT EXISTS archives (
                            name TEXT PRIMARY KEY,
                            password TEXT NOT NULL,
                            owner TEXT NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
                            fullname TEXT,
                            name TEXT,
                            path TEXT,
                            body TEXT,
                            lastupdated TEXT,
                            updatedby TEXT,
                            timestamp TEXT,
                            archive TEXT,
                            PRIMARY KEY (fullname, archive),
                            FOREIGN KEY (archive) REFERENCES archives (name))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS links (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            linkfrom TEXT,
                            linkto TEXT,
                            linkclass TEXT)''')
        
        # This part for server_config and token remains unchanged
        cursor.execute('''CREATE TABLE IF NOT EXISTS server_config (
                            key TEXT PRIMARY KEY,
                            value TEXT)''')
        cursor.execute("INSERT OR IGNORE INTO server_config (key, value) VALUES ('server_token', '')")
        
        conn.commit()

        env_var_token = os.environ.get('KLINKTOKEN')
        if env_var_token:
            logging.info("Found KLINKTOKEN environment variable and setting servertoken.")
            set_server_token_on_startup(env_var_token)

# This part for token check remains unchanged
@app.before_request
def check_server_token():
    # 1. Tillat ALLTID OPTIONS-kall å passere for CORS
    if request.method == 'OPTIONS':
        return
    
    if request.endpoint in ['set_server_token', 'static']: # Exclude static endpoint for safety
        return

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM server_config WHERE key = 'server_token'")
        result = cursor.fetchone()
    server_token = result[0] if result else ''

    if server_token:
        request_token = request.headers.get('X-Server-Token')
        if not request_token or request_token != server_token:
            return jsonify({'error': 'Unauthorized: Missing or invalid X-Server-Token'}), 401

# This part for setting token remains unchanged
@app.route('/set_server_token', methods=['POST'])
def set_server_token():
    new_token = request.headers.get('X-Server-Token')
    if not new_token:
        return jsonify({'error': 'X-Server-Token header is required'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM server_config WHERE key = 'server_token'")
        current_token = cursor.fetchone()[0]

        if current_token:
            return jsonify({'error': 'Server token is already set and cannot be changed.'}), 409

        cursor.execute("UPDATE server_config SET value = ? WHERE key = 'server_token'", (new_token,))
        conn.commit()
    
    logging.info('Server token has been set.')
    return jsonify({'status': 'success', 'message': 'Server token has been set successfully.'})


def verify_archive(archive, password):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM archives WHERE name = ?", (archive,))
        result = cursor.fetchone()
        if result and check_password_hash(result[0], password):
            return True
    return False

# ### ENDRING HER: /create_archive krever nå 'Owner-Email' header ###
@app.route('/create_archive', methods=['POST'])
def create_archive():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')
    owner_email = request.headers.get('Owner-Email') # Ny header

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    
    # Validering av e-post
    if not owner_email or not EMAIL_REGEX.match(owner_email):
        return jsonify({'error': 'A valid Owner-Email header is required'}), 400

    logging.info(f'Creating archive {archive} for owner {owner_email}')

    hashed_password = generate_password_hash(password)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Oppdatert INSERT for å inkludere eier
            cursor.execute("INSERT INTO archives (name, password, owner) VALUES (?, ?, ?)", (archive, hashed_password, owner_email))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': f'Archive with name {archive} already exists'}), 409

    return jsonify({'status': 'success'})

# ### ENDRING HER: /list_archives returnerer nå navn og eier ###
@app.route('/list_archives', methods=['GET'])
def list_archives():
    """Returns a sorted list of all archives with their owners."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Oppdatert SELECT for å hente navn og eier
            cursor.execute("SELECT name, owner FROM archives ORDER BY name")
            archives = cursor.fetchall()
        
        # Lag en liste med objekter som inneholder navn og eier
        archive_list = [{'name': name, 'owner': owner} for name, owner in archives]
        return jsonify(archive_list)
    except Exception as e:
        logging.error(f"Error fetching archives: {e}")
        return jsonify({'error': 'Could not retrieve archives from the database'}), 500


@app.route('/insert', methods=['POST'])
def insert_document():
    data = request.json
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400

    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    if 'name' not in data or 'body' not in data:
        return jsonify({'error': 'Document name and body are required'}), 400

    name = data['name'].strip().lstrip('/')
    path = data.get('path', '').strip().lstrip('/')
    body = data['body']
    updatedby = 'defaultuser'
    timestamp = datetime.now(timezone.utc).isoformat()
    lastupdated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')

    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))

        cursor.execute('''INSERT INTO documents (fullname, name, path, body, lastupdated, updatedby, timestamp, archive)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(fullname, archive) DO UPDATE SET
                            name=excluded.name,
                            path=excluded.path,
                            body=excluded.body,
                            lastupdated=excluded.lastupdated,
                            updatedby=excluded.updatedby,
                            timestamp=excluded.timestamp''',
                       (fullname, name, path, body, lastupdated, updatedby, timestamp, archive))

        links = re.findall(r'\[\[(.*?)\]\]', body)
        for link in links:
            if not link.lower().endswith('.kli'):
                link += '.kli'
            cursor.execute("INSERT INTO links (linkfrom, linkto, linkclass) VALUES (?, ?, ?)",
                           (fullname, link, 'document'))

        conn.commit()

    return jsonify({'status': 'success'})

@app.route('/retrieve', methods=['GET'])
def retrieve_document():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')
    fullname = request.args.get('fullname')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400

    if not fullname:
        return jsonify({'error': 'Fullname is required'}), 400

    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    fullname = fullname.strip().lstrip('/')
    if not fullname.lower().endswith('.kli'):
        fullname += '.kli'

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        document = cursor.fetchone()

        if document:
            doc_dict = {
                'fullname': document[0],
                'name': document[1],
                'path': document[2],
                'body': document[3],
                'lastupdated': document[4],
                'updatedby': document[5],
                'timestamp': document[6],
                'archive': document[7]
            }

            cursor.execute("SELECT linkfrom FROM links WHERE linkto = ?", (fullname,))
            incoming_links = cursor.fetchall()
            incoming_links_list = [link[0] for link in incoming_links]
            doc_dict['incominglinks'] = ','.join(incoming_links_list)

            return jsonify(doc_dict)
        else:
            return jsonify({'error': 'Document not found'}), 404

@app.route('/documents', methods=['GET'])
def list_documents():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400

    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, path, lastupdated, updatedby, timestamp FROM documents WHERE archive = ?", (archive,))
        documents = cursor.fetchall()

    # Separate documents with empty path and non-empty path
    empty_path_docs = [doc for doc in documents if doc[1] == '']
    non_empty_path_docs = [doc for doc in documents if doc[1] != '']

    # Sort non-empty path documents by path and name alphabetically
    non_empty_path_docs.sort(key=lambda x: (x[1], x[0]))

    # Sort empty path documents by name alphabetically
    empty_path_docs.sort(key=lambda x: x[0])

    # Combine the sorted lists, empty path documents first
    sorted_documents = empty_path_docs + non_empty_path_docs

    doc_list = []
    for doc in sorted_documents:
        doc_list.append({
            'name': doc[0],
            'path': doc[1],
            'lastupdated': doc[2],
            'updatedby': doc[3],
            'timestamp': doc[4]
        })
    return jsonify(doc_list)

@app.route('/delete_document', methods=['DELETE'])
def delete_document():
    data = request.json
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400

    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    if 'name' not in data:
        return jsonify({'error': 'Document name is required'}), 400

    name = data['name'].strip().lstrip('/')
    path = data.get('path', '').strip().lstrip('/')

    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')

    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
        conn.commit()

    return jsonify({'status': 'success'})

def set_server_token_on_startup(token):
    """Overwrites the server token in the database."""
    logging.info(f"Overwriting server token with provided startup token.")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO server_config (key, value) VALUES ('server_token', ?)
                          ON CONFLICT(key) DO UPDATE SET value=excluded.value''', (token,))
        conn.commit()
    logging.info("Server token has been set. ✅")

# Initialiser databasen ved oppstarten
logging.info('Initializing database.')
init_db()

if __name__ == '__main__':
    logging.info('Starting web application.')
    port = int(os.environ.get('PORT', 54827))
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
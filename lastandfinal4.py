import joblib
import logging
import requests
import threading
import tkinter as tk
from flask import Flask, request, jsonify
from flask_cors import CORS
from tkinter import ttk, scrolledtext, PhotoImage, messagebox
import pandas as pd
import numpy as np
import tldextract
import math
from collections import Counter
from urllib.parse import urlparse
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from tkinter import PhotoImage

# Flask app URL
flask_app = Flask(__name__)
CORS(flask_app, resources={r'/*': {'origins': '*'}})

# Custom logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
)

# In-memory storage for URLs storage
urls = []

# Convert blacklist to a set for O(1) lookups
# Blacklist of known phishing URLs
BLACKLIST = set([
    "www.youtube.com"
    # Add more blacklisted URLs as needed
])

# Keep track of subdomains for partial matching
BLACKLIST_SUBDOMAINS = {}
for domain in BLACKLIST:
    parts = domain.split('.')
    for i in range(len(parts)):
        subdomain = '.'.join(parts[i:])
        if subdomain not in BLACKLIST_SUBDOMAINS:
            BLACKLIST_SUBDOMAINS[subdomain] = set()
        BLACKLIST_SUBDOMAINS[subdomain].add(domain)

# Define feature sets as in the model training code
svm_features = [
    'urllength',
    'tldlength',
    'specialcharratio',
    'digitratio',
    'entropy',
    'noofletters',
    'noofslashes',
    'ishttps',
    'noofdots',
]

rf_features = [
    'noofnos',
    'tld',
    'noofequals',
    'noofquestionmarks',
    'noofampersands',
    'noofat',
    'noofdashes',
]

@flask_app.route('/log_urls', methods=['POST', 'OPTIONS'])
def log_urls():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'success'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response

    data = request.get_json()
    global urls
    urls = data.get('urls', [])

    logging.info(f'Received URLs: {urls}')

    response = jsonify({'status': 'success', 'count': len(urls)})
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


@flask_app.route('/log_urls', methods=['GET'])
def get_urls():
    response = jsonify({'urls': urls})
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


def load_models():
    """Load all necessary models and preprocessors"""
    global svm_model, rf_model, ensemble_weights
    
    # Load the trained models
    try:
        svm_model = joblib.load('models/svm_model.pkl')
        rf_model = joblib.load('models/rf_model.pkl')
        ensemble_weights = joblib.load('models/ensemble_weights.pkl')
        print('Models loaded successfully')
        return True
    except Exception as e:
        print(f'Error loading models: {e}')
        return False


# URL Feature Extraction Functions
def get_url_length(url):
    return len(url)


def extract_tld(url):
    ext = tldextract.extract(url)
    return ext.suffix if ext.suffix else 'unknown'  # Handle blank TLDs


def add_tld_length(tld):
    return len(tld) if tld != 'unknown' else 0


def extract_noofletters(url):
    return sum(c.isalpha() for c in str(url))


def extract_noofnos(url):
    return sum(c.isdigit() for c in str(url))


def extract_noofequals(url):
    return url.count('=')


def extract_noofquestionmarks(url):
    return url.count('?')


def extract_noofampersands(url):
    return url.count('&')


def count_slashes(url):
    return url.count('/')


def count_at_symbols(url):
    return url.count('@')


def is_https(url):
    return 1 if url.startswith('https://') else 0


def count_dots(url):
    return url.count('.')


def count_dashes(url):
    return url.count('-')


def calculate_special_char_ratio(url):
    return sum(not c.isalnum() for c in url) / len(url) if len(url) > 0 else 0


def calculate_digit_ratio(url):
    return sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0


def calculate_entropy(url):
    # Count occurrences of each character
    char_counts = Counter(url)

    # Calculate total characters
    total_chars = len(url)

    # Calculate entropy
    entropy = 0
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)

    return entropy


def extract_url_features(url):
    """Extract all features from a URL"""
    features = {}

    # Basic URL properties
    features['urllength'] = len(url)

    # Extract TLD
    try:
        tld_extract = tldextract.extract(url)
        features['tld'] = tld_extract.suffix if tld_extract.suffix else 'unknown'
        features['tldlength'] = len(tld_extract.suffix) if tld_extract.suffix else 0
    except:
        features['tld'] = 'unknown'
        features['tldlength'] = 0

    # Count special characters and symbols
    features['specialcharratio'] = sum(
        c in '~`!@#$%^&*()_-+={}[]|\\:;"\'<>,.?/' for c in url
    ) / max(len(url), 1)
    features['digitratio'] = sum(c.isdigit() for c in url) / max(len(url), 1)
    features['noofletters'] = sum(c.isalpha() for c in url)

    # Count specific characters
    features['noofslashes'] = url.count('/')
    features['noofdots'] = url.count('.')
    features['noofequals'] = url.count('=')
    features['noofquestionmarks'] = url.count('?')
    features['noofampersands'] = url.count('&')
    features['noofat'] = url.count('@')
    features['noofdashes'] = url.count('-')
    features['noofnos'] = sum(c.isdigit() for c in url)

    # Entropy calculation (measure of randomness)
    features['entropy'] = calculate_entropy(url)

    # HTTPS check
    features['ishttps'] = 1 if url.startswith('https://') else 0

    return features


def check_url_in_blacklist(url):
    """Check if the URL contains any blacklisted domain using hash-based lookup"""
    parsed_url = urlparse(url).netloc
    if not parsed_url:  # If netloc is empty, try to parse the URL as-is
        parsed_url = url
    
    # Direct hash lookup - O(1) operation
    if parsed_url in BLACKLIST:
        return True
    
    # Check for partial matches with subdomains
    parts = parsed_url.split('.')
    for i in range(len(parts)):
        subdomain = '.'.join(parts[i:])
        if subdomain in BLACKLIST:
            return True
    
    return False


def predict_urls(urls):
    """Predict whether URLs are phishing or legitimate"""
    results = []

    for url in urls:
        try:
            # First check if URL is in blacklist
            if check_url_in_blacklist(url):
                # If in blacklist, mark as phishing without processing
                results.append({
                    'url': url,
                    'prediction': 1,  # Changed from 0 to 1 for phishing
                    'blacklisted': True,
                    'probability': 1.0,  # 100% probability of being phishing
                })
                continue
                
            # Check if URL is HTTP (not HTTPS)
            if url.startswith('http://'):
                results.append({
                    'url': url,
                    'prediction': 1,  # Changed from 0 to 1 for phishing
                    'probability': 1.0,  # 100% probability of being phishing
                    'blacklisted': False,
                })
                continue
                
            # Extract features
            features = extract_url_features(url)
            features_df = pd.DataFrame([features])

            # Prepare features for SVM model (needs only svm_features)
            svm_features_data = features_df[svm_features]

            # Prepare features for RF model 
            rf_features_data = features_df[rf_features]
            
            # Make predictions
            svm_prob = svm_model.predict_proba(svm_features_data)[0, 1]
            rf_prob = rf_model.predict_proba(rf_features_data)[0, 1]

            # Ensemble prediction with weighted voting
            weighted_prob = (
                ensemble_weights['SVM'] * svm_prob + ensemble_weights['RF'] * rf_prob
            )
            ensemble_pred = 1 if weighted_prob >= 0.5 else 0

            # 1 = phishing, 0 = legitimate (inverted logic to match display)
            results.append({
                'url': url,
                'prediction': ensemble_pred,
                'svm_prediction': 1 if svm_prob >= 0.5 else 0,
                'rf_prediction': 1 if rf_prob >= 0.5 else 0,
                'probability': weighted_prob,
                'blacklisted': False,
            })
        except Exception as e:
            logging.error(f"Error processing URL '{url}': {e}")
            results.append({
                'url': url,
                'prediction': None,
                'error': str(e),
                'blacklisted': False,
            })

    return results
# fetch URLs from the flask server
def fetch_urls():
    try:
        response = requests.get('http://127.0.0.1:5000/log_urls')
        if response.status_code == 200:
            data = response.json()
            urls = data.get('urls', [])
            if isinstance(urls, list) and all(isinstance(url, str) for url in urls):
                logging.info(f"Successfully fetched {len(urls)} URLs")
                return urls
            else:
                error_msg = 'Fetched data is not in expected format or contains non-string URLs.'
                logging.error(error_msg)
        else:
            logging.error(f'Error fetching URLs: {response.status_code}')
    except requests.exceptions.RequestException as e:
        logging.error(f'Request error: {e}')
    return []

def update_gui():
    # fetch URLs from the flask
    urls = fetch_urls()

    if urls:
        # Clear results area
        url_app.result_area.delete('1.0', tk.END)
        url_app.update_status(f"Processing {len(urls)} URLs...")

        # Make predictions
        predictions = predict_urls(urls)

        # Display predictions
        for result in predictions:
            url = result['url']
            prediction = result.get('prediction')
            is_blacklisted = result.get('blacklisted', False)
            
            if prediction is not None:
                # Handle blacklisted URLs - always mark as phishing with cross icon and bold
                if is_blacklisted:
                    try:
                        url_app.result_area.image_create(tk.END, image=url_app.cross_icon)
                    except:
                        url_app.result_area.insert(tk.END, "✗ ")  # Unicode X mark as fallback
                    url_app.result_area.insert(tk.END, f' {url}\n', 'blacklisted')
                
                # For non-blacklisted URLs, invert the prediction logic
                # prediction == 1 now means phishing, prediction == 0 means legitimate
                elif prediction == 1:  # Phishing URL (inverted logic)
                    try:
                        url_app.result_area.image_create(tk.END, image=url_app.cross_icon)
                    except:
                        url_app.result_area.insert(tk.END, "✗ ")  # Unicode X mark as fallback
                    url_app.result_area.insert(tk.END, f' {url}\n', 'phishing')
                else:  # Legitimate URL (inverted logic)
                    try:
                        url_app.result_area.image_create(tk.END, image=url_app.tick_icon)
                    except:
                        url_app.result_area.insert(tk.END, "✓ ")  # Unicode checkmark as fallback
                    url_app.result_area.insert(tk.END, f' {url}\n', 'legitimate')
            else:
                url_app.result_area.insert(tk.END, f'Error processing: {url}\n', 'error')

        url_app.update_status(f"Completed processing {len(urls)} URLs")
    else:
        url_app.result_area.insert(tk.END, 'No URLs received or an error occurred.\n', 'error')
        url_app.update_status("No URLs found")

    # Schedule the next update
    url_app.root.after(10000, update_gui)  # update every 10 seconds
    
# separate thread flask
def run_flask_app():
    flask_app.run(debug=False, port=5000, use_reloader=False)


class URLGuardianGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('URL Guardian')
        self.root.geometry('900x700')
        self.root.configure(bg='#282c34')

        self.setup_styles()
        self.create_widgets()

        # Load icons
        self.load_icons()
        
        # Add tag configurations
        self.result_area.tag_configure('legitimate', foreground='black')
        self.result_area.tag_configure('phishing', foreground='black')
        self.result_area.tag_configure('blacklisted', foreground='black', font=('Helvetica Neue', 12, 'bold'))
        self.result_area.tag_configure('error', foreground='black')

        # Load the models
        self.update_status('Loading models...')
        models_loaded = load_models()
        
        if not models_loaded:
            messagebox.showerror('Model Load Error', 'Could not load the machine learning models. Please check the models directory.')
            self.update_status('Error: Models not loaded')
        else:
            self.update_status('Models loaded, starting server...')
            
            # Start Flask server in a thread
            flask_thread = threading.Thread(target=run_flask_app)
            flask_thread.daemon = True  # Make thread daemon so it exits when main thread exits
            flask_thread.start()
            
            # Updating the GUI
            self.root.after(1000, update_gui)  # Start after 1s
            self.update_status('Ready - Waiting for URLs...')

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#282c34')
        style.configure(
            'TButton',
            background='#61dafb',
            foreground='#282c34',
            font=('Helvetica Neue', 12),
            padding=10,
        )
        style.map(
            'TButton',
            background=[('active', '#4fa8d5')],
            foreground=[('active', '#ffffff')],
        )
        style.configure(
            'TLabel',
            background='#282c34',
            foreground='#ffffff',
            font=('Helvetica Neue', 12),
        )

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding='20 20 20 20')
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(
            main_frame,
            text='URL Guardian',
            font=('Helvetica Neue', 24, 'bold'),
            foreground='#61dafb',
        )
        title_label.pack(pady=(0, 20))

        self.result_area = scrolledtext.ScrolledText(
            main_frame,
            width=80,
            height=20,
            font=('Helvetica Neue', 12),
            bg='#ffffff',  # white background
            fg='#000000',  # text color black
        )
        self.result_area.pack(pady=10, fill=tk.BOTH, expand=True)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10, fill=tk.X)

        refresh_button = ttk.Button(
            button_frame, text='Refresh Now', command=self.update_gui_with_status
        )
        refresh_button.pack(side=tk.LEFT, padx=(0, 10))

        clear_button = ttk.Button(
            button_frame, text='Clear Results', command=self.clear_results
        )
        clear_button.pack(side=tk.LEFT)

        # Add button to manage blacklist
        manage_blacklist_button = ttk.Button(
            button_frame, text='Manage Blacklist', command=self.open_blacklist_manager
        )
        manage_blacklist_button.pack(side=tk.LEFT, padx=(10, 0))

        self.status_label = ttk.Label(main_frame, text='Initializing...')
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

    def update_status(self, status_text):
        self.status_label.config(text=status_text)

    def update_gui_with_status(self):
        self.update_status('Refreshing now...')
        update_gui()  # Call the update function directly

    def clear_results(self):
        self.result_area.delete('1.0', tk.END)

    def open_blacklist_manager(self):
        # Create a new window for blacklist management
        blacklist_window = tk.Toplevel(self.root)
        blacklist_window.title("Blacklist Manager")
        blacklist_window.geometry("600x500")
        blacklist_window.configure(bg='#282c34')
        
        # Create frame for the blacklist window
        frame = ttk.Frame(blacklist_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create label
        ttk.Label(frame, text="URL Blacklist", font=('Helvetica Neue', 18, 'bold')).pack(pady=(0, 10))
        
        # Create text area to display and edit blacklist
        blacklist_text = scrolledtext.ScrolledText(
            frame, width=60, height=15, font=('Helvetica Neue', 12)
        )
        blacklist_text.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # Insert current blacklist
        for url in sorted(BLACKLIST):
            blacklist_text.insert(tk.END, url + "\n")
        
        # Create buttons for actions
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        def save_blacklist():
            # Get text from the text widget
            new_blacklist_text = blacklist_text.get('1.0', tk.END)
            
            # Parse into list and remove empty lines
            new_blacklist_urls = [line.strip() for line in new_blacklist_text.split('\n') if line.strip()]
            
            # Update the global blacklist (convert to set for O(1) lookups)
            global BLACKLIST, BLACKLIST_SUBDOMAINS
            BLACKLIST = set(new_blacklist_urls)
            
            # Rebuild the subdomain dictionary
            BLACKLIST_SUBDOMAINS = {}
            for domain in BLACKLIST:
                parts = domain.split('.')
                for i in range(len(parts)):
                    subdomain = '.'.join(parts[i:])
                    if subdomain not in BLACKLIST_SUBDOMAINS:
                        BLACKLIST_SUBDOMAINS[subdomain] = set()
                    BLACKLIST_SUBDOMAINS[subdomain].add(domain)
            
            # Show confirmation
            self.update_status(f"Blacklist updated with {len(BLACKLIST)} URLs")
            blacklist_window.destroy()
        
        # Save button
        save_button = ttk.Button(
            button_frame, text="Save Changes", command=save_blacklist
        )
        save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Cancel button
        cancel_button = ttk.Button(
            button_frame, text="Cancel", command=blacklist_window.destroy
        )
        cancel_button.pack(side=tk.LEFT)
        
        # Instructions
        instructions = ttk.Label(
            frame,
            text="Add one URL per line. URLs in this list will be automatically marked as phishing.",
            wraplength=550
        )
        instructions.pack(pady=10)

    def load_icons(self):
        try:
            # Load images from files
            self.tick_icon = PhotoImage(file='icons/tick.png')  # Provide the correct file path here
            self.cross_icon = PhotoImage(file='icons/cross.png')  # Provide the correct file path here
            print('Icons loaded successfully')
        except Exception as e:
            # Handle any errors while loading images
            print(f'Could not load icons: {e}')
            # Fallback to using text if image loading fails
            self.tick_icon = None
            self.cross_icon = None


if __name__ == '__main__':
    root = tk.Tk()
    url_app = URLGuardianGUI(root)
    root.mainloop()
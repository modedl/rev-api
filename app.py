# Import the Flask class from the flask library
from flask import Flask, jsonify, request, Response # Import Response
# Import the requests library to make HTTP requests to external APIs
import requests
# Import necessary modules for decryption
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad # Required for unpadding decrypted data
from collections import OrderedDict # To maintain order of keys
import os # Import the os module to access environment variables

# Create an instance of the Flask application
# The __name__ argument helps Flask locate resources like templates and static files
app = Flask(__name__)

# Define the application key for decryption
# This key is crucial for decrypting the Laravel-encrypted strings
# Retrieve the APP_KEY_STR from environment variables
APP_KEY_STR = os.environ.get("APP_KEY_STR")

# It's good practice to check if the environment variable is set
if not APP_KEY_STR:
    # In a production environment, you might want to raise an error or log a critical message
    # For local development, you could set a default or provide a warning
    print("WARNING: APP_KEY_STR environment variable is not set. Decryption may fail.")
    # You might want to halt the app or use a placeholder for local testing if needed
    # APP_KEY_STR = "YOUR_FALLBACK_KEY_FOR_LOCAL_DEV" # Uncomment for local fallback


def decrypt_laravel_string_unsafe(encrypted_data_str, app_key_str):
    """
    Decrypts a Base64-encoded Laravel encrypted string without
    performing the MAC verification.

    Args:
        encrypted_data_str: The Base64-encoded encrypted string.
        app_key_str: The application key as a string.

    Returns:
        The decrypted plaintext string, or an error message.
    """
    # Ensure app_key_str is not None or empty before proceeding
    if not app_key_str:
        return "Decryption key (APP_KEY_STR) is missing."

    # --- 1. Decode the initial JSON payload ---
    try:
        # Add padding if necessary for the outer Base64 string
        missing_padding = len(encrypted_data_str) % 4
        if missing_padding:
            encrypted_data_str += '=' * (4 - missing_padding)

        # Base64-decode and load the JSON payload
        decoded_payload = base64.b64decode(encrypted_data_str)
        json_data = json.loads(decoded_payload)

        # Extract the IV and the encrypted value
        iv_bytes = base64.b64decode(json_data['iv'])
        encrypted_value_bytes = base64.b64decode(json_data['value'])

    except (json.JSONDecodeError, base64.binascii.Error, KeyError) as e:
        return f"An error occurred during initial decoding: {e}"

    # --- 2. Decrypt the data using AES-256-CBC ---
    # NOTE: The MAC verification step has been removed.
    try:
        # The key must be a 32-byte binary string for AES-256.
        app_key_bytes = app_key_str.encode('utf-8')

        # Create an AES cipher object in CBC mode
        cipher = AES.new(app_key_bytes, AES.MODE_CBC, iv_bytes)

        # Decrypt the value
        decrypted_bytes = cipher.decrypt(encrypted_value_bytes)

        # Unpad the decrypted bytes using PKCS7 padding
        unpadded_bytes = unpad(decrypted_bytes, AES.block_size)

        # Decode from bytes to string
        plaintext = unpadded_bytes.decode('utf-8')

        # --- Post-decryption cleaning for Laravel string format ---
        # The result is often a JSON string with quotes, so we remove them.
        if plaintext.startswith('"') and plaintext.endswith('"'):
            plaintext = plaintext[1:-1]

        # Remove Laravel's "s:NNN:" prefix and trailing ";" if present
        # Example: s:112:"https://example.com/movie.mp4";
        if plaintext.startswith('s:') and plaintext.endswith(';'):
            # Find the first colon after "s:"
            first_colon_index = plaintext.find(':', 2) # Start search after 's:'
            if first_colon_index != -1:
                # Find the first double quote after the length (e.g., after s:112:")
                first_quote_index = plaintext.find('"', first_colon_index)
                if first_quote_index != -1:
                    # The actual URL starts after this quote and ends before the last quote
                    # and the trailing semicolon.
                    # We need to find the last quote before the trailing semicolon.
                    last_quote_index = plaintext.rfind('"', 0, len(plaintext) - 1) # Search before the last char (;)
                    if last_quote_index != -1 and last_quote_index > first_quote_index:
                        plaintext = plaintext[first_quote_index + 1:last_quote_index]

        return plaintext

    except Exception as e:
        # If the key is wrong, you will likely get a padding error here instead
        # of a MAC error.
        return f"An error occurred during decryption: {e}"


# Define the root endpoint ('/')
# This function will be executed when a GET request is made to the root URL
@app.route('/')
def home():
    """
    Handles requests to the root URL.
    Returns a simple welcome message.
    """
    return "<h1>Welcome to a Simple Flask API!</h1><p>Use /greet/&lt;name&gt;, /data, /movies/&lt;id&gt;, or /search</p>"

# Define an endpoint that takes a path parameter
# <name> is a variable part of the URL, which will be passed as an argument to the function
@app.route('/greet/<name>')
def greet(name):
    """
    Greets the user with a personalized message.
    Args:
        name (str): The name provided in the URL path.
    Returns:
        str: A greeting message.
    """
    return f"Hello, {name}! Nice to meet you."

# Define an endpoint that returns JSON data
# jsonify helps convert Python dictionaries into JSON responses
@app.route('/data')
def get_data():
    """
    Returns a simple JSON object.
    """
    data = {
        "message": "This is some sample data from the API.",
        "version": "1.0",
        "items": ["item1", "item2", "item3"]
    }
    return jsonify(data)

# Define a new endpoint to fetch movie details by ID
@app.route('/movies/<int:movie_id>') # Use <int:movie_id> to ensure the ID is an integer
def get_movie_details(movie_id):
    """
    Fetches movie details from an external API based on the provided movie ID,
    and decrypts specific URL fields.
    Args:
        movie_id (int): The ID of the movie to fetch.
    Returns:
        json: The JSON response from the external movie API with decrypted URLs,
              or an error message.
    """
    # Check if APP_KEY_STR is available before attempting decryption
    if not APP_KEY_STR:
        return jsonify({"error": "Server configuration error: Decryption key is missing."}), 500

    # Construct the URL for the external movie API
    external_api_url = f"https://api.msubmovie.com/api/v1/mobile/get/single/movie/{movie_id}"

    try:
        # Make a GET request to the external API
        response = requests.get(external_api_url)
        # Raise an HTTPError for bad responses (4xx or 5xx)
        response.raise_for_status()

        # Get the JSON response from the external API
        movie_data = response.json()

        # List of keys that contain encrypted URLs
        encrypted_url_keys = [
            "vstream", "vdownload2", "vbackup", "freemium", "download", "stream", "astream"
        ]

        # Decrypt each encrypted URL in the movie_data
        for key in encrypted_url_keys:
            if key in movie_data and isinstance(movie_data[key], str):
                decrypted_url = decrypt_laravel_string_unsafe(movie_data[key], APP_KEY_STR)
                # Update the movie_data with the decrypted URL
                movie_data[key] = decrypted_url
            else:
                # If the key is missing or not a string, set it to None or an empty string
                movie_data[key] = None # Or you could set it to ""

        # Define a preferred order for the keys
        PREFERRED_MOVIE_KEY_ORDER = [
            "id", "movietitle", "movieyear", "moviegenres", "language", "imdb",
            "quality", "review", "image",
            "vstream", "stream", "astream", "freemium", "download", "vdownload2", "vbackup",
            "premium", "downloadcount", "viewcount", "filesize"
        ]

        # Create an OrderedDict to store the movie data in the preferred order
        ordered_movie_data = OrderedDict()

        # Add keys in the preferred order
        for key in PREFERRED_MOVIE_KEY_ORDER:
            if key in movie_data:
                ordered_movie_data[key] = movie_data[key]

        # Add any remaining keys that were not in the preferred order
        for key in movie_data:
            if key not in ordered_movie_data:
                ordered_movie_data[key] = movie_data[key]

        # Convert OrderedDict to a regular dictionary (if needed for older Python versions,
        # though standard dicts preserve insertion order from Python 3.7+)
        final_response_data = dict(ordered_movie_data)

        # Manually serialize to JSON to ensure sort_keys=False is applied
        json_output = json.dumps(final_response_data, indent=4, sort_keys=False)

        # Return as a Flask Response object with the correct mimetype
        return Response(json_output, mimetype='application/json')

    except requests.exceptions.HTTPError as http_err:
        # Handle HTTP errors (e.g., 404 Not Found, 500 Internal Server Error)
        return jsonify({"error": f"HTTP error occurred: {http_err}", "status_code": response.status_code}), response.status_code
    except requests.exceptions.ConnectionError as conn_err:
        # Handle connection errors (e.g., network issues)
        return jsonify({"error": f"Connection error occurred: {conn_err}"}), 503 # Service Unavailable
    except requests.exceptions.Timeout as timeout_err:
        # Handle timeout errors
        return jsonify({"error": f"Timeout error occurred: {timeout_err}"}), 408 # Request Timeout
    except requests.exceptions.RequestException as req_err:
        # Handle any other general request errors
        return jsonify({"error": f"An unexpected error occurred: {req_err}"}), 500 # Internal Server Error
    except Exception as e:
        # Catch any other unforeseen errors
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

# Define a new endpoint for searching movies
@app.route('/search')
def search_movies():
    """
    Searches for movies using a query and page number from an external API.
    Args:
        query (str): The search query for movies.
        page (int): The page number for results.
    Returns:
        json: The JSON response from the external movie search API, or an error message.
    """
    # Get query and page parameters from the request arguments
    search_query = request.args.get('query', default='', type=str)
    page_number = request.args.get('page', default=1, type=int)

    # Construct the URL for the external search API
    external_search_api_url = f"https://api.msubmovie.com/api/get/search/movies?query={search_query}&page={page_number}"

    try:
        # Make a GET request to the external search API
        response = requests.get(external_search_api_url)
        # Raise an HTTPError for bad responses (4xx or 5xx)
        response.raise_for_status()

        # Return the JSON response directly from the external API
        # The search response structure is already well-defined by the external API
        return jsonify(response.json())

    except requests.exceptions.HTTPError as http_err:
        return jsonify({"error": f"HTTP error occurred: {http_err}", "status_code": response.status_code}), response.status_code
    except requests.exceptions.ConnectionError as conn_err:
        return jsonify({"error": f"Connection error occurred: {conn_err}"}), 503
    except requests.exceptions.Timeout as timeout_err:
        return jsonify({"error": f"Timeout error occurred: {timeout_err}"}), 408
    except requests.exceptions.RequestException as req_err:
        return jsonify({"error": f"An unexpected error occurred: {req_err}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

# This block ensures the Flask development server runs only when the script is executed directly
# It will not run if the script is imported as a module into another script
if __name__ == '__main__':
    # Run the Flask application in debug mode
    # Debug mode provides a debugger and auto-reloader, useful for development
    app.run(debug=True)

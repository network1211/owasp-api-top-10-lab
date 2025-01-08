from flask import Flask, jsonify
import json

app = Flask(__name__)

# Load routes from configuration file
with open('routes_config.json', 'r') as f:
    routes = json.load(f)["routes"]

# Store dynamic routes' responses
dynamic_responses = {}

# Dynamically create routes from the configuration
for route in routes:
    path = route["path"]
    method = route["method"]
    response_data = route.get("response", {})  # Load the predefined response for the route

    # Store the response data for later access
    dynamic_responses[path] = response_data

    # Dynamically add routes
    if method == "GET":
        # Use a closure to capture the specific path
        def create_get_route(response):
            def dynamic_route():
                return jsonify(response)
            return dynamic_route

        app.route(path, methods=["GET"])(create_get_route(response_data))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

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

    if method == "GET":
        # Handle routes with path parameters
        if "<int:" in path:
            # Create a dynamic route with path parameters
            def create_get_route_with_param(response):
                def dynamic_route_with_param(user_id):
                    # Check if the user_id exists in the response data
                    user = response.get(str(user_id))
                    if user:
                        return jsonify(user)
                    else:
                        return jsonify({"error": "User not found"}), 404
                return dynamic_route_with_param

            # Register the dynamic route with path parameters
            app.route(path, methods=["GET"])(create_get_route_with_param(response_data))
        else:
            # Handle static routes
            def create_get_route(response):
                def dynamic_route():
                    return jsonify(response)
                return dynamic_route

            # Register the dynamic static route
            app.route(path, methods=["GET"])(create_get_route(response_data))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

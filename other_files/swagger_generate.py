import json
from pathlib import Path

# Define the updated OpenAPI spec base
openapi_spec = {
    "openapi": "3.0.0",
    "info": {
        "title": "OWASP API Vulnerabilities Combined App (Security Scheme Added)",
        "version": "1.0.5"
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            },
            "apiKeyAuth": {
                "type": "apiKey",
                "in": "query",
                "name": "apikey"
            }
        }
    },
    "security": [
      { "bearerAuth": [] },
      { "apiKeyAuth": [] }
    ],
    "paths": {}
}

# Common response codes
default_responses = {
    "201": {"description": "Created"},
    "400": {"description": "Bad Request"},
    "401": {"description": "Unauthorized"},
    "403": {"description": "Forbidden"},
    "404": {"description": "Not Found"},
    "429": {"description": "Too Many Requests"},
    "503": {"description": "Service Unavailable"}
}

# 200 OK with CORS headers
cors_200_response = {
    "description": "OK",
    "headers": {
        "Access-Control-Allow-Origin": {
            "description": "CORS policy",
            "schema": {
                "type": "string",
                "enum": ["https://www.test.com"]
            }
        }
    }
}
standard_200_response = {
    "200": {"description": "OK"}
}

def merge_responses(response_200):
    responses = {"200": response_200}
    responses.update(default_responses)
    return responses

# API endpoints definition
endpoints = {
    "/api/v1/users/{user_id}": {
        "get": {
            "summary": "Get user info by ID (BOLA)",
            "parameters": [
                {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}}
            ],
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/auth/data": {
        "get": {
            "summary": "Access using API key and registration token",
            "parameters": [
                {"name": "apikey", "in": "query", "required": True, "schema": {"type": "string"}},
                {"name": "regToken", "in": "query", "required": True, "schema": {"type": "string"}}
            ],
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/jwt/data": {
        "get": {
            "summary": "Access using JWT (bypasses signature validation)",
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/pii": {
        "get": {
            "summary": "Get PII data (BOPLA)",
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/users": {
        "post": {
            "summary": "Create user (mass assignment vulnerability)",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"},
                                "email": {"type": "string"},
                                "role": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/initiate_forgot_password": {
        "post": {
            "summary": "Initiate forgot password (Unrestricted Resource Consumption)",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "step": {"type": "integer"},
                                "user_number": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/data": {
        "get": {
            "summary": "Access data with JWT (BFLA)",
            "responses": merge_responses(standard_200_response["200"])
        },
        "post": {
            "summary": "Write data with JWT (BFLA)",
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/generate_token/{username}": {
        "get": {
            "summary": "Generate JWT token for a user",
            "parameters": [
                {"name": "username", "in": "path", "required": True, "schema": {"type": "string"}}
            ],
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/tickets/buy": {
        "post": {
            "summary": "Buy tickets (business flow abuse)",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "ticket_type": {"type": "string"},
                                "quantity": {"type": "integer"}
                            }
                        }
                    }
                }
            },
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/tickets/reset": {
        "post": {
            "summary": "Reset ticket counter",
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/profile/picture": {
        "post": {
            "summary": "Update profile picture (SSRF test)",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "image_url": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "responses": merge_responses(standard_200_response["200"])
        }
    },
    "/api/v1/config/sample": {
        "get": {
            "summary": "Get config (Security Misconfiguration: CORS *)",
            "description": "Simulates a weak CORS policy returning Access-Control-Allow-Origin.",
            "responses": merge_responses(cors_200_response)
        }
    },
    "/api/v1/userinfo": {
        "get": {
            "summary": "Get user info (Unsafe Consumption)",
            "parameters": [
                {
                    "name": "X-UCA",
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"}
                }
            ],
            "responses": merge_responses(standard_200_response["200"])
        }
    }
}

openapi_spec["paths"] = endpoints

# Save updated spec
Path("static").mkdir(parents=True, exist_ok=True)
swagger_path = Path("static/swagger.json")
swagger_path.write_text(json.dumps(openapi_spec, indent=2))

swagger_path.absolute()
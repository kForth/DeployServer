import json

from flask import Flask, jsonify, make_response

app = Flask(__name__)
config = json.load(open('config.json'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5050)

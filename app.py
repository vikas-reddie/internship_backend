import bcrypt
from flask import Flask, request, jsonify
import jwt
from pymongo import MongoClient
from flask_cors import CORS
import random
import string
import datetime

app = Flask(__name__)
CORS(app)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['dhreeg_agro']
users = db['users']
orders = db['orders']

# Secret key for JWT token
app.config['SECRET_KEY'] = 'vVGJVvnUK0nuyHnpEcTAQ8a0BoM4cUKMVkQuwi2WePoRfQxCoqSTTJtEDr0-oyqLictsAUjr3N9Re_PgyC5PqA'

def generate_order_id():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

@app.route('/addusers', methods=['POST'])
def addusers():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phno = data.get('phno')
    role = data.get('role')

    if not name or not email or not password or not phno or not role:
        return jsonify({'message': 'Enter all the fields'}), 400

    if users.find_one({'email': email}):
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({'name': name, 'email': email, 'password': hashed_password, 'phno': phno, 'role': role})
    return jsonify({'message': 'User added successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user_data = users.find_one({'email': email})

    if user_data:
        if bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
            token = jwt.encode({'email': email}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token}), 200
        else:
            return jsonify({'message': 'Invalid email or password'}), 401
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/getuser', methods=['GET'])
def getuser():
    token = request.headers.get('Authorization')
    token = token.split(' ')[1]
    if not token:
        return jsonify({'message': 'Token is missing'}), 400
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_data = users.find_one({'email': data['email']})
        if user_data:
            return jsonify({'name': user_data['name'], 'email': user_data['email'], 'phno': user_data['phno'], 'role': user_data['role']}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/update-profile', methods=['POST'])
def update_profile():
    token = request.headers.get('Authorization')
    token = token.split(' ')[1]
    if not token:
        return jsonify({'message': 'Token is missing'}), 400
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = data['email']
        update_data = request.json
        
        if 'password' in update_data:
            update_data.pop('password')
       
        users.update_one({'email': email}, {'$set': update_data})
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/addorder', methods=['POST'])
def addorder():
    data = request.json
    distributorName = data.get('distributorName')
    phoneNumber = data.get('phoneNumber')
    address = data.get('address')
    quantity500ml = data.get('quantity500ml')
    quantity200ml = data.get('quantity200ml')
    quantity1ltr = data.get('quantity1ltr')
    quantity2ltr = data.get('quantity2ltr')
    quantity5ltr = data.get('quantity5ltr')
    quantity20ltr = data.get('quantity20ltr')
    order_id = generate_order_id()
    order_data = {
        'order_id': order_id,
        'distributorName': distributorName,
        'phoneNumber': phoneNumber,
        'address': address,
        'quantity500ml': quantity500ml,
        'quantity200ml': quantity200ml,
        'quantity1ltr': quantity1ltr,
        'quantity2ltr': quantity2ltr,
        'quantity5ltr': quantity5ltr,
        'quantity20ltr': quantity20ltr,
        'created_at': datetime.datetime.utcnow().strftime('%d-%m-%Y')
    }
    orders.insert_one(order_data)

    return jsonify({'message': 'Order added successfully', 'order_id': order_id}), 200
@app .route('/getorders', methods=['GET'])
def getorders():
    orders_data = list(orders.find({}, {'_id': 0}))
    return jsonify(orders_data), 200
@app.route('/getorder/<order_id>', methods=['GET'])
def get_order(order_id):
    order_data = orders.find_one({'order_id': order_id}, {'_id': 0})
    if order_data:
        return jsonify(order_data), 200
    else:
        return jsonify({'message': 'Order not found'}), 404

    

if __name__ == '__main__':
    app.run(debug=True, port=8050)

# Backend of a simple login wesbite
- api of the simple login website with authentication and encryption and local database using json


Since this is just a test website for it to work locally please add a .env file in the project with the contents:
```
# Server Configuration
PORT=3000
NODE_ENV=development

# Security
BCRYPT_SALT_ROUNDS=12
JWT_SECRET=a8f7d92e4b6c1a3f9e2d8b7c5a4f6e9d2b8c7a5f4e3d9c8b6a7f5e4d3c2b1a9f8e7d6c5b4a3f2e1d9c8b7a6f5e4d3c2b1a

# File Storage
DATA_FILE_PATH=users.json
```

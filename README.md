### Coding Challenge: Build a Data Privacy Vault

#### Overview
Your task is to build a Data Privacy Vault, a secure way to store and manage sensitive information. This vault will ensure that data is protected and access is controlled, allowing businesses to safely handle sensitive data such as medical records, payment details, and personal information.

The Data Privacy Vault will provide a HTTP-based API to store sensitive data and return a token. This token can later be used to retrieve the data by an authorized user or service. For more information on why tokenization is beneficial, refer to Wikipedia's article on [Tokenization](https://en.wikipedia.org/wiki/Tokenization).

#### Step Zero: Setup
1. Set up your development environment.
2. Choose your preferred programming language and IDE/editor.

#### Step 1: Create Tokenization Service
Build a simple tokenization service with two endpoints: `/tokenize` and `/detokenize`.

**Endpoint: /tokenize**
- **Method**: POST
- **Request Payload**:
  ```json
  {
    "id": "req-123",
    "data": {
      "field1": "value1",
      "field2": "value2",
      "fieldn": "valuen"
    }
  }
  ```	
- **Success Response**: HTTP Code 201
- **Response Payload**:
  ```json
  {
    "id": "req-123",
    "data": {
      "field1": "t8yk4f5",
      "field2": "gj45nkd",
      "fieldn": "bkj6iob"
    }
  }
  ```

**Endpoint: /detokenize**
- **Method**: POST
- **Request Payload**:
  ```json
  {
    "id": "req-33445",
    "data": {
      "field1": "t8yk4f5",
      "field2": "gj45nkd",
      "field3": "invalid token"
    }
  }
  ```
- **Response Payload**:
  ```json
  {
    "id": "req-33445",
    "data": {
      "field1": {
        "found": true,
        "value": "value1"
      },
      "field2": {
        "found": true,
        "value": "value2"
      },
      "field3": {
        "found": false,
        "value": ""
      }
    }
  }
  ```

**Notes**:
- Store data in memory for now.
- Handle appropriate error responses for both endpoints.
- Implement logic to handle cases where tokens are not found.

#### Step 2: Persistent Storage and Encryption
Extend the service to store data in a persistent storage solution with encryption.

1. Choose a secure encryption algorithm for privacy-related data.
2. Implement format-preserving encryption if necessary (e.g., preserving phone number formats).

#### Step 3: Authentication and Authorization
Implement authenticated access to the vault.

1. Implement service-to-service authentication.
2. Ensure that only authorized users/services can create tokens.
3. Verify that only authorized users/services can detokenize data.

By the end of this challenge, you will have built a secure Data Privacy Vault with tokenization, encryption, persistent storage, and authenticated access. Good luck!
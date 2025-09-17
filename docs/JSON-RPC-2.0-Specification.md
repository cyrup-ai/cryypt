# JSON-RPC 2.0 Specification

## Overview
JSON-RPC is a stateless, lightweight remote procedure call (RPC) protocol. Encoded in JSON, it is transport-agnostic in that the concepts can be used within the same process, over sockets, over HTTP, or in many various message passing environments.

## Key Characteristics
- Stateless, lightweight remote procedure call protocol
- Transport-agnostic
- Uses JSON as data format
- Designed for simplicity

## Request Object

A remote procedure call is made by sending a request to a remote service. The request is a single object serialized using JSON.

### Required Fields
- **"jsonrpc"**: A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
- **"method"**: A String containing the name of the method to be invoked.

### Optional Fields  
- **"params"**: A Structured value that holds the parameter values to be used during the invocation of the method. This member MAY be omitted.
- **"id"**: An identifier established by the Client. If it is not included it is assumed to be a notification.

### Parameter Passing
Parameters can be passed:
- **By position** (array): `"params": [42, 23]`
- **By name** (object): `"params": {"subtrahend": 23, "minuend": 42}`

### Notification
A Notification is a Request object without an "id" member. A Request object that is a Notification signifies the Client's lack of interest in the corresponding Response object, and as such no Response object needs to be returned to the Client.

## Response Object

When a request is made, the service must reply with a response unless the request was a notification.

### Required Fields
- **"jsonrpc"**: A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
- **"id"**: This will be the same as the value of the id member in the Request Object. If there was an error in detecting the id in the Request object (e.g. Parse error/Invalid Request), it will be Null.

### Success Response
- **"result"**: This member is REQUIRED on success. This member MUST NOT exist if there was an error invoking the method.

### Error Response  
- **"error"**: This member is REQUIRED on error. This member MUST NOT exist if there was no error triggered during invocation.

## Error Object

When a request fails, the Response Object contains the error member with a value that is an Object with the following members:

### Required Fields
- **"code"**: A Number that indicates the error type that occurred.
- **"message"**: A String providing a short description of the error.

### Optional Fields
- **"data"**: A Primitive or Structured value that contains additional information about the error.

## Predefined Error Codes

The error codes from and including -32768 to -32000 are reserved for predefined errors.

- **-32700**: Parse error - Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.
- **-32600**: Invalid Request - The JSON sent is not a valid Request object.
- **-32601**: Method not found - The method does not exist / is not available.
- **-32602**: Invalid params - Invalid method parameter(s).
- **-32603**: Internal error - Internal JSON-RPC error.

Server error codes from -32000 to -32099 are reserved for implementation-defined server-errors.

## Batch Processing

To send several Request objects at the same time, the Client MAY send an Array filled with Request objects.

- The Server should respond with an Array containing the corresponding Response objects, after all of the batch Request objects have been processed.
- A Response object SHOULD exist for each Request object, except that there SHOULD NOT be any Response objects for notifications.
- The Server MAY process a batch request concurrently, processing them in any order.
- The Response objects being returned from a batch request MAY be returned in any order within the Array.
- If the batch request itself fails to be recognized as a valid JSON or as an Array with at least one value, the response from the Server MUST be a single Response object.

## Examples

### Simple Request/Response
**Request:**
```json
{
  "jsonrpc": "2.0", 
  "method": "subtract", 
  "params": [42, 23], 
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0", 
  "result": 19, 
  "id": 1
}
```

### Notification (no response expected)
**Request:**
```json
{
  "jsonrpc": "2.0", 
  "method": "update", 
  "params": [1,2,3,4,5]
}
```

### Error Response
**Request:**
```json
{
  "jsonrpc": "2.0", 
  "method": "foobar", 
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0", 
  "error": {
    "code": -32601, 
    "message": "Method not found"
  }, 
  "id": 1
}
```

### Batch Request
**Request:**
```json
[
  {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
  {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]},
  {"jsonrpc": "2.0", "method": "subtract", "params": [42,23], "id": "2"},
  {"jsonrpc": "2.0", "method": "foo.get", "params": {"name": "myself"}, "id": "5"}
]
```

**Response:**
```json
[
  {"jsonrpc": "2.0", "result": 7, "id": "1"},
  {"jsonrpc": "2.0", "result": 19, "id": "2"}, 
  {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "5"}
]
```

## Key Implementation Requirements

1. **Request ID Management**: Each request must have a unique identifier for proper request/response correlation
2. **Version Field**: All requests and responses must include `"jsonrpc": "2.0"`
3. **Method Names**: Case-sensitive, can use dot notation for namespacing
4. **Parameter Handling**: Support both positional (array) and named (object) parameters
5. **Error Handling**: Use predefined error codes and proper error object structure
6. **Batch Processing**: Handle arrays of requests and return corresponding response arrays
7. **Notifications**: Requests without "id" field require no response
8. **Concurrent Processing**: Batch requests may be processed concurrently
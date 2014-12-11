#Tokens for NodeJS

##Purpose

The purpose of this module is to provide a simple lightweight framework for managing session tokens. 
This module does NOT provide authentication functionality but rather authorizes requests to a REST service 
after authentication has already taken place.  By using a session token and combining that with a nonce value tracked
per session this module will help prevent session hijacking and cross site request forgery attacks.

##Security Standards

This module implements best practices as specified in the [OWASP](http://www.owasp.org) [suggested best practices for securing REST services](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet).

##Usage

###createSession

Create a session token with *createSession*.

#####Method Signature

	createSession(complete, error)

#####Example

	var auth = require('tokens')();

	auth.createSession(function (response) {
		console.log('sessionToken: %s', response.sessionToken);
		console.log('sessionToken: %s', response.nonce);
		console.log('sessionToken: %s', response.expirationDateTime);
	},
	function(error) {
		console.log('error message: %s', error.message);
	});

####response: complete

The response will contain the newly created session token, the session's nonce value and the session expiration date and time.

	{
	    "sessionToken": "b0c96728-4c44-4c0a-9fca-5563fb1ebe44",
	    "nonce": 1,
	    "expiration": "2014-11-15T20:02:43.450Z"
	}

###validateSession

Subsequent requests can be validated by calling *validateSession*.

#####Method Signature

	validateSession(sessionToken, nonce, complete, error)

#####Example

	var auth = require('tokens')();

	auth.validateSession(sessionTokenFromRequest, nonceFromRequest,
	function(response) {
		console.log('sessionToken: %s', response.sessionToken);
		console.log('sessionToken: %s', response.nonce);
		console.log('sessionToken: %s', response.expirationDateTime);
	},
	function(error) {
		console.log('error message: %s', error.message);
		console.log('session token: %s', error.sessionToken);
		console.log('nonce: %d', error.nonce);
	});

####responses: complete, error

#####complete callback
The response from a complete callback contains the following information:

	{
		success: true,
		failureReason: '',
		newSessionInformation: {
								 sessionToken: "6faf36df-8877-4177-945b-700c4684e7c3",
								 nonce: 2,
								 expiration: "2014-11-16T16:41:41.062Z"
							   }
	}

If there is a failure the *success* property will be false, the *failureReason* will contain the error message, and the *newSessionInformation* will be undefined.
A non-successful response is not the same as an error.  Failures that result in a non-successful result are caused because the session token or the nonce is incorrect.

- A system error such as the inability to read or write to the persisted storage mechanism would result in an error.
- If there is a system error the complete callback is never called.

#####error callback
The error callback will be called if there is a system level error in processing the request. Known error conditions would be:

- could not read or write to the persisted storage
- invalid or corrupt session data retrieved

###destroySession

A session can be immediately destroyed (and removed from persisted storage) by calling *destroySession*.

#####Method Signature

	destroySession(sessionToken, complete, error)

#####Example

	var auth = require('tokens')();

	auth.destroySession(sessionTokenFromRequest,
	function() {
		console.log('session %s destroyed.', sessionTokenFromRequest);
	},
	function(error) {
		console.log('error message: %s', error.message);
		console.log('session token: %s', error.sessionToken);
	});

####responses: complete, error

#####complete callback
The complete callback is called with no method arguments as there is no data to return to the caller.

*Please note that if there is an error condition (e.g. the session could not be deleted from the persistence store) the complete callback is not called.

#####error callback
The error callback will be called if there is a system level error in processing the request. Known error conditions would be:

- could not read or write to the persisted storage

##Running the unit tests
The unit tests use the jasmine-node format.

- To execute them you need to install jasmine: `npm install jasmine-node`
- Change into the root project folder `node-session-tokens`
- Execute the unit tests: `jasmine-node spec`

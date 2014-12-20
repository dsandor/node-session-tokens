/*
 Copyright 2014 David Sandor

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


 OWASP Recommended Security Features
    - Synchronizer Token Pattern: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet

 */
var uuid    = require('node-uuid');
var fs      = require('fs');
var os      = require('os');
var winston = require('winston');

(function() {
    "use strict";

    module.exports = function (options) {
        var methods = {};

        var Options = {
            /* This is the base path to use in order to store the session details.  This path must exist. */
            sessionStorageBasePath: os.tmpdir() + 'sessionstorage/',

            /* When the ticket is first created it will be valid from the current time in UTC + sessionTicketValidForMinutes. */
            sessionTicketValidForMinutes: 1,

            /* Means that each request with the sessionTicket will extend the validity period.  */
            sessionTicketSlidingValidity: true,

            /*
             The number of minutes to extend the validity time to when the session ticket is seen on the server.
             The sessionTicketSlidingValidity must be set to true in order for this setting to have an effect.
             For example:  If the ticket validity period is 5 minutes and a sessionTicket validation is
             performed (and the ticket was valid) the session expiration date/time is set to
             current time UTC + sessionTicketSlidingIncrementMinutes.
             */
            sessionTicketSlidingIncrementMinutes: 1,

            /*
             When set to true a nonce is used in conjunction with the sessionTicket.  This helps prevent
             session hijacking by supplying an incrementing number with the ticket.  The client must provide
             the nonce value back with the ticket.
             */
            useNonceValueWithTicket: true,

            /*
             Indicates the acceptable deviation in the nonce value.  This is important for multi-threaded applications
             as the client code could be responding to a nonce with more than one response.  This value will support the
             exact nonce value and up to 2 units of deviation from that value on either side.

             For example:  A user logs in and gets a session ticket plus a nonce.  Later the client makes a request for
             two pieces of data (two asynchronous requests) simultaneously. The expected nonce is updated
             with the first request yet the second request is already in-flight therefore the nonce provided
             in that request will deviate from the newly expected nonce value by at least a value of 1.
             */
            nonceValueAcceptableDeviation: 2,

            /*
             The session persistence mechanism is responsible for storing, retrieving, and deleting session information.
             The default store uses the local file system and puts the session information in a directory called
             sessionstorage located beneath the directory defined in the sessionStorageBasePath property.
             */
            sessionStore: undefined
        };

        // Option overrides.
        if (typeof options != 'undefined')
        {
            for (var attrname in options) {
                if (typeof Options[attrname] != 'undefined') {
                    Options[attrname] = options[attrname];
                }
            }
        }

        // default session store to local store.
        if (typeof Options.sessionStore === 'undefined') {
            localFileStorageSync.sessionStorageBasePath = Options.sessionStorageBasePath;
            Options.sessionStore = localFileStorageSync;
        }

        /*
         Creates a new session.
         The completion callback is called with the sessionToken, nonce, and expiration date/time.
         */
        methods.createSession = function(callback, error){

            if (typeof callback === 'undefined') return;

            try {
                var expirationDateTime = new Date().getTime();
                expirationDateTime = new Date(expirationDateTime + Options.sessionTicketValidForMinutes * 60000);

                var session =
                {
                    sessionToken: uuid.v4(),
                    nonce: 1,
                    expiration: expirationDateTime
                };

                Options.sessionStore.Save(session,
                function() {
                    callback(session);
                    return;
                },
                function(err) {
                    winston.log('error', 'There was an error saving session: %s', err.message);
                });

            } catch (err) {
                if (typeof error != 'undefined') {
                    error({message: err.message});
                    return;
                }
            }
        };

        // TODO: Fix validateSession so that it deals with the nonce and the session expiration date.
        methods.validateSession = function(sessionToken, nonce, complete, error){
            if (typeof complete === 'undefined') return {};

            var sessionFilePath = Options.sessionStorageBasePath + sessionToken;

            var result = {
                success: false,
                failureReason: "",
                newSessionInformation: undefined
            };

            try {
                var sessionFile = fs.readFileSync(sessionFilePath, {encoding: 'utf8'});
                var session = JSON.parse(sessionFile);

                // Validate nonce if necessary.
                if (Options.useNonceValueWithTicket)
                {
                    if (nonce < (session.nonce - Options.nonceValueAcceptableDeviation/2)
                        && nonce > (session.nonce + Options.nonceValueAcceptableDeviation/2))
                    {
                        result.failureReason = 'Nonce deviation exceeded threshold.';
                        result.success = false;

                        complete(result);
                        return;
                    }
                }

                if (new Date().getTime() > session.expiration)
                {
                    result.failureReason = 'Session is expired.';
                    result.success = false;

                    complete(result);
                    return;
                }

                // not expired, nonce validated ok, lets increment the nonce.
                session.nonce ++;

                if (Options.sessionTicketSlidingValidity) {

                    console.log('session expiration: %s', session.expiration);

                    var currentExpiration = new Date(session.expiration);
                    currentExpiration = new Date(currentExpiration.getTime() + Options.sessionTicketSlidingIncrementMinutes*60000);

                    session.expiration = currentExpiration;
                }

                result.success = true;
                result.newSessionInformation = session;

                // persist session information
                fs.writeFileSync(sessionFilePath, JSON.stringify(session), { encoding: 'utf8'});

                complete(result);
                return;
            } catch(err) {
                var errorMessage = 'There was a failure validating session: ' + err.message;

                result.succcess = false;
                result.message = errorMessage;

                if (typeof error != 'undefined') {
                    error({message: errorMessage, sessionToken: sessionToken, nonce: nonce});
                    return;
                }
            }
        };

        methods.destroySession = function(sessionToken, complete, error){
            var sessionFilePath = Options.sessionStorageBasePath + sessionToken;

            try {
                if (fs.existsSync(sessionFilePath))
                    fs.unlinkSync(sessionFilePath);
            } catch(err) {
                if (typeof error != 'undefined') {
                    error({message: err.message, sessionToken: sessionToken});
                    return;
                }
            }

            if (typeof complete === 'undefined')
                return {};
            else
                complete();
        };

        methods.createSynchronizerToken = function(sessionToken, callback){

            // TODO: Implement creating a synchronizer token in the session storage object.
        };

        methods.validateSynchronizerToken = function(sessionToken, synchronizerToken, callback){

            // TODO: Implement validating a synchronizer token in the session storage object.
        };

        return methods;
    };

    /*
     Synchronous persistence store.
     */
    var localFileStorageSync = new function() {

        this.sessionStorageBasePath = '';

        this.Save = function(session, complete, error) {
            // TODO: Handle errors and missing values in session or options objects.

            try {
                var sessionFilePath = this.sessionStorageBasePath + session.sessionToken;

                if (!fs.existsSync(this.sessionStorageBasePath)) {
                    winston.log('info', 'Session storage location: %s does not exist, creating.', this.sessionStorageBasePath);
                    fs.mkdirSync(this.sessionStorageBasePath);
                }

                winston.log('info', 'creating session file: %s', sessionFilePath);

                fs.writeFileSync(sessionFilePath, JSON.stringify(session), {encoding: 'utf8'});

                if (typeof complete != 'undefined') {
                    complete();
                }
            } catch(err) {
                if (typeof error != 'undefined') {
                    error(err);
                }
            }
        }

        //this.Load
    }
}());



// TODO: actually implement all of this stuff.  createSession, validateSession, endSession.
// maybe even allow adding arbitrary session metadata to the session storage.
// Things to consider: uuid, filed.
